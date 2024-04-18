/*
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#include "common/specs/ieee802154.h"
#include "common/hif.h"
#include "common/ieee802154_frame.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mpx.h"
#include "common/named_values.h"
#include "common/rcp_api.h"
#include "common/ws_ie.h"
#include "common/ws_regdb.h"
#include "common/ws_types.h"
#include "wsrd/app/wsrd.h" // FIXME: move rcp to ws_ctx

#include "ws.h"

struct ws_ind {
    const struct rcp_rx_ind *hif;
    struct ieee802154_hdr hdr;
    struct iobuf_read ie_hdr;
    struct iobuf_read ie_wp;
    struct iobuf_read ie_mpx;
};

static const struct name_value ws_frames[] = {
    { "adv",       WS_FT_PA },
    { "adv-sol",   WS_FT_PAS },
    { "cfg",       WS_FT_PC },
    { "cfg-sol",   WS_FT_PCS },
    { "data",      WS_FT_DATA },
    { "ack",       WS_FT_ACK },
    { "eapol",     WS_FT_EAPOL },
    { "l-adv",     WS_FT_LPA },
    { "l-adv-sol", WS_FT_LPAS },
    { "l-cfg",     WS_FT_LPC },
    { "l-cfg-sol", WS_FT_LPCS },
    { "l-tsync",   WS_FT_LTS },
    { NULL },
};

static const char *tr_ws_frame(uint8_t type)
{
    return val_to_str(type, ws_frames, "unknown");
}

static bool ws_ie_validate_chan_plan(struct ws_ctx *ws, const struct ws_generic_channel_info *schedule)
{
    const struct ws_channel_plan_zero *plan0 = &schedule->plan.zero;
    const struct ws_channel_plan_one *plan1 = &schedule->plan.one;
    const struct ws_channel_plan_two *plan2 = &schedule->plan.two;
    const struct chan_params *parms = NULL;
    int plan_nr = schedule->channel_plan;

    if (plan_nr == 1)
        return plan1->ch0 * 1000      == ws->fhss.chan_params->chan0_freq &&
               plan1->channel_spacing == ws_regdb_chan_spacing_id(ws->fhss.chan_params->chan_spacing);
    if (plan_nr == 0)
        parms = ws_regdb_chan_params(plan0->regulatory_domain,
                                     0, plan0->operating_class);
    if (plan_nr == 2)
        parms = ws_regdb_chan_params(plan2->regulatory_domain,
                                     plan2->channel_plan_id, 0);
    if (!parms)
        return false;
    return parms->chan0_freq   == ws->fhss.chan_params->chan0_freq &&
           parms->chan_spacing == ws->fhss.chan_params->chan_spacing;
}

static bool ws_ie_validate_schedule(struct ws_ctx *ws, const struct ws_generic_channel_info *schedule)
{
    if (!ws_ie_validate_chan_plan(ws, schedule)) {
        TRACE(TR_DROP, "drop %-9s: invalid channel plan", "15.4");
        return false;
    }

    switch (schedule->channel_function) {
    case WS_CHAN_FUNC_FIXED:
        if (schedule->function.zero.fixed_channel >= 8 * WS_CHAN_MASK_LEN) {
            TRACE(TR_DROP, "drop %-9s: fixed channel >= %u", "15.4", 8 * WS_CHAN_MASK_LEN);
            return false;
        }
        break;
    case WS_CHAN_FUNC_TR51CF:
    case WS_CHAN_FUNC_DH1CF:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported channel function", "15.4");
        return false;
    }

    switch (schedule->excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_NONE:
    case WS_EXC_CHAN_CTRL_RANGE:
    case WS_EXC_CHAN_CTRL_BITMASK:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported excluded channel control", "15.4");
        return false;
    }
    return true;
}

static bool ws_ie_validate_us(struct ws_ctx *ws, const struct iobuf_read *ie_wp, struct ws_us_ie *ie_us)
{
    if (!ws_wp_nested_us_read(ie_wp->data, ie_wp->data_size, ie_us)) {
        TRACE(TR_DROP, "drop %-9s: missing US-IE", "15.4");
        return false;
    }
    if (ie_us->chan_plan.channel_function != WS_CHAN_FUNC_FIXED && !ie_us->dwell_interval) {
        TRACE(TR_DROP, "drop %-9s: invalid dwell interval", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(ws, &ie_us->chan_plan);
}

static bool ws_ie_validate_bs(struct ws_ctx *ws, const struct iobuf_read *ie_wp, struct ws_bs_ie *ie_bs)
{
    if (!ws_wp_nested_bs_read(ie_wp->data, ie_wp->data_size, ie_bs)) {
        TRACE(TR_DROP, "drop %-9s: missing BS-IE", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(ws, &ie_bs->chan_plan);
}

static bool ws_ie_validate_netname(struct ws_ctx *ws, const struct iobuf_read *ie_wp)
{
    struct ws_netname_ie ie_netname;

    if (!ws_wp_nested_netname_read(ie_wp->data, ie_wp->data_size, &ie_netname)) {
        TRACE(TR_DROP, "drop %-9s: missing NETNAME-IE", "15.4");
        return false;
    }
    if (strcmp(ws->netname, ie_netname.netname)) {
        TRACE(TR_DROP, "drop %-9s: NETNAME-IE mismatch", "15.4");
        return false;
    }
    return true;
}

static bool ws_ie_validate_pan(struct ws_ctx *ws, const struct iobuf_read *ie_wp, struct ws_pan_ie *ie_pan)
{
    if (!ws_wp_nested_pan_read(ie_wp->data, ie_wp->data_size, ie_pan)) {
        TRACE(TR_DROP, "drop %-9s: missing PAN-IE", "15.4");
        return false;
    }
    if (!ie_pan->routing_method) {
        TRACE(TR_DROP, "drop %-9s: unsupported routing method", "15.4");
        return false;
    }
    if (!ie_pan->use_parent_bs_ie)
        TRACE(TR_IGNORE, "ignore %-9s: unsupported local broadcast", "15.4");
    return true;
}

void ws_recv_pa(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct ws_neigh *neigh;
    struct ws_utt_ie ie_utt;
    struct ws_pan_ie ie_pan;
    struct ws_us_ie ie_us;

    if (ind->hdr.pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: missing PAN ID", "15.4");
        return;
    }
    if (ws->pan_id != 0xffff && ws->pan_id != ind->hdr.pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    if (!ws_ie_validate_netname(ws, &ind->ie_wp))
        return;
    if (!ws_ie_validate_pan(ws, &ind->ie_wp, &ie_pan))
        return;
    if (!ws_ie_validate_us(ws, &ind->ie_wp, &ie_us))
        return;

    neigh = ws_neigh_get(&ws->neigh_table, ind->hdr.src);
    if (!neigh)
        // TODO: TX power (APC)
        // TODO: active key indices
        neigh = ws_neigh_add(&ws->neigh_table, ind->hdr.src, WS_NR_ROLE_ROUTER, 16, 0x02);
    else
        ws_neigh_refresh(&ws->neigh_table, neigh, neigh->lifetime_s);
    ws_neigh_ut_update(&neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_us_update(&ws->fhss, &neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    // TODO: POM-IE
    // TODO: Select between several PANs
    ws->pan_id = ind->hdr.pan_id;
}

static void ws_chan_params_from_ie(const struct ws_generic_channel_info *ie, struct chan_params *params)
{
    memset(params, 0, sizeof(*params));
    params->reg_domain = REG_DOMAIN_UNDEF;
    switch (ie->channel_plan) {
    case 0:
        *params = *ws_regdb_chan_params(ie->plan.zero.regulatory_domain, 0, ie->plan.zero.operating_class);
        break;
    case 1:
        params->chan0_freq   = ie->plan.one.ch0 * 1000;
        params->chan_spacing = ws_regdb_chan_spacing_from_id(ie->plan.one.channel_spacing);
        params->chan_count   = ie->plan.one.number_of_channel;
        break;
    case 2:
        *params = *ws_regdb_chan_params(ie->plan.two.regulatory_domain, ie->plan.two.channel_plan_id, 0);
        break;
    }
}

static void ws_recv_pc(struct ws_ctx *ws, struct ws_ind *ind)
{
    uint8_t bc_chan_mask[WS_CHAN_MASK_LEN];
    struct chan_params chan_params;
    struct ws_neigh *neigh;
    struct ws_utt_ie ie_utt;
    struct ws_bt_ie ie_bt;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;

    if (ws->pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (ind->hdr.pan_id != ws->pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsecured frame", "15.4");
        return;
    }

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    if (!ws_wh_bt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_bt)) {
        TRACE(TR_DROP, "drop %s: missing BT-IE", "15.4");
        return;
    }
    if (!ws_ie_validate_us(ws, &ind->ie_wp, &ie_us))
        return;
    if (!ws_ie_validate_bs(ws, &ind->ie_wp, &ie_bs))
        return;

    // TODO: PANVER-IE, GTKHASH-IE, LFNVER-IE, LGTKHASH-IE, LBC-IE, FFN/PAN-Wide IEs

    neigh = ws_neigh_get(&ws->neigh_table, ind->hdr.src);
    if (!neigh)
        neigh = ws_neigh_add(&ws->neigh_table, ind->hdr.src, WS_NR_ROLE_ROUTER, 16, 0x01);
    else
        ws_neigh_refresh(&ws->neigh_table, neigh, neigh->lifetime_s);
    ws_neigh_ut_update(&neigh->fhss_data,           ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_ut_update(&neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_us_update(&ws->fhss, &neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
    ws_neigh_us_update(&ws->fhss, &neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    // TODO: only update on BS-IE change, or parent change
    ws_chan_params_from_ie(&ie_bs.chan_plan, &chan_params);
    ws_chan_mask_calc_reg(bc_chan_mask, &chan_params, HIF_REG_NONE);
    rcp_set_fhss_ffn_bc(&g_wsrd.rcp,
                        ie_bs.broadcast_interval,
                        ie_bs.broadcast_schedule_identifier,
                        ie_bs.dwell_interval,
                        bc_chan_mask);
}

void ws_recv_data(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct ws_neigh *neigh;
    struct ws_utt_ie ie_utt;
    struct ws_us_ie ie_us;
    struct mpx_ie ie_mpx;

    if (ws->pan_id == 0xffff) {
        TRACE(TR_DROP, "drop %s: PAN ID not yet configured", "15.4");
        return;
    }
    if (!memcmp(ind->hdr.dst, ieee802154_addr_bc, 8) && ind->hdr.pan_id != ws->pan_id) {
        TRACE(TR_DROP, "drop %s: PAN ID mismatch", "15.4");
        return;
    }
    if (!ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsecured frame", "15.4");
        return;
    }

    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_6LOWPAN ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }

    neigh = ws_neigh_get(&ws->neigh_table, ind->hdr.src);
    if (!neigh)
        neigh = ws_neigh_add(&ws->neigh_table, ind->hdr.src, WS_NR_ROLE_ROUTER, 16, 0x01);
    else
        ws_neigh_refresh(&ws->neigh_table, neigh, neigh->lifetime_s);

    ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt);
    ws_neigh_ut_update(&neigh->fhss_data,           ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);
    ws_neigh_ut_update(&neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src);

    if (ws_ie_validate_us(ws, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&ws->fhss, &neigh->fhss_data,           &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&ws->fhss, &neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    }
}

void ws_print_ind(const struct ws_ind *ind, uint8_t type)
{
    unsigned int tr_domain;

    if (type == WS_FT_DATA || type == WS_FT_ACK || type == WS_FT_EAPOL)
        tr_domain = TR_15_4_DATA;
    else
        tr_domain = TR_15_4_MNGT;

    if (ind->hdr.pan_id >= 0 && ind->hdr.pan_id != 0xffff)
        TRACE(tr_domain, "rx-15.4 %-9s src:%s panid:%x (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src),
              ind->hdr.pan_id, ind->hif->rx_power_dbm);
    else
        TRACE(tr_domain, "rx-15.4 %-9s src:%s (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src),
              ind->hif->rx_power_dbm);
}

void ws_recv_ind(struct ws_ctx *ws, const struct rcp_rx_ind *hif_ind)
{
    struct ws_ind ind = { .hif = hif_ind };
    struct iobuf_read ie_payload;
    struct ws_utt_ie ie_utt;
    int ret;

    ret = ieee802154_frame_parse(hif_ind->frame, hif_ind->frame_len,
                                 &ind.hdr, &ind.ie_hdr, &ie_payload);
    if (ret < 0)
        return;

    if (!ws_wh_utt_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_utt)) {
        TRACE(TR_DROP, "drop %-9s: missing UTT-IE", "15.4");
        return;
    }

    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_WP, &ind.ie_wp);
    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_MPX, &ind.ie_mpx);

    ws_print_ind(&ind, ie_utt.message_type);

    switch (ie_utt.message_type) {
    case WS_FT_PA:
        ws_recv_pa(ws, &ind);
        break;
    case WS_FT_PC:
        ws_recv_pc(ws, &ind);
        break;
    case WS_FT_DATA:
        ws_recv_data(ws, &ind);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type", "15.4");
        return;
    }
}
