/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#define _GNU_SOURCE
#include <errno.h>

#include "common/specs/ieee802154.h"
#include "common/specs/ieee802159.h"
#include "common/specs/ws.h"
#include "common/sys_queue_extra.h"
#include "common/ieee802154_ie.h"
#include "common/string_extra.h"
#include "common/memutils.h"
#include "common/sl_ws.h"
#include "common/mpx.h"

#include "ws_interface.h"

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
    { "dc-sol",    SL_FT_DCS },
    { "dc-adv",    SL_FT_DCA },
    { NULL },
};

static const char *tr_ws_frame(uint8_t type)
{
    return val_to_str(type, ws_frames, "unknown");
}

static void ws_print_ind(const struct ws_ind *ind, uint8_t type)
{
    unsigned int tr_domain;

    if (type == WS_FT_DATA || type == WS_FT_ACK || type == WS_FT_EAPOL)
        tr_domain = TR_15_4_DATA;
    else
        tr_domain = TR_15_4_MNGT;

    if (ind->hdr.pan_id != UINT16_MAX)
        TRACE(tr_domain, "rx-15.4 %-9s src:%s panid:%x (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src.u8),
              ind->hdr.pan_id, ind->hif->rx_power_dbm);
    else
        TRACE(tr_domain, "rx-15.4 %-9s src:%s (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src.u8),
              ind->hif->rx_power_dbm);
}

static void ws_write_ies(struct ws_ctx *ws, struct iobuf_write *iobuf, uint8_t frame_type,
                         struct wh_ie_list *wh_ies, struct wp_ie_list *wp_ies, uint16_t multiplex_id)
{
    bool has_ie_wp = false;
    struct ws_ie *ie;
    int offset;

    BUG_ON(wh_ies->utt && wh_ies->sl_utt);

    if (wh_ies->utt)
        ws_wh_utt_write(iobuf, frame_type);
    if (wh_ies->bt)
        ws_wh_bt_write(iobuf);
    if (wh_ies->sl_utt)
        ws_wh_sl_utt_write(iobuf, frame_type);
    if (wh_ies->ea)
        ws_wh_ea_write(iobuf, wh_ies->ea);
    SLIST_FOREACH(ie, &ws->ie_list, link) {
        if (!(ie->frame_type_mask & BIT(frame_type)))
            continue;
        if (ie->ie_type == WS_IE_TYPE_HEADER)
            iobuf_push_data(iobuf, ie->buf.data, ie->buf.len);
        else
            has_ie_wp = true;
    }
    // TODO: remaning WH-IEs
    if (!memzcmp(wp_ies, sizeof(struct wp_ie_list)) && !multiplex_id && !has_ie_wp)
        return;

    ieee802154_ie_push_header(iobuf, IEEE802154_IE_ID_HT1);

    offset = ieee802154_ie_push_payload(iobuf, IEEE802154_IE_ID_WP);
    if (wp_ies->us)
        ws_wp_nested_us_write(iobuf, &ws->fhss);
    if (wp_ies->bs)
        ws_wp_nested_bs_write(iobuf, &ws->fhss);
    if (wp_ies->pan)
        ws_wp_nested_pan_write(iobuf, wp_ies->pan->pan_size, wp_ies->pan->routing_cost, wp_ies->pan->use_parent_bs_ie,
                               wp_ies->pan->routing_method, wp_ies->pan->lfn_window_style, wp_ies->pan->fan_tps_version);
    if (wp_ies->panver)
        ws_wp_nested_panver_write(iobuf, (uint16_t)ws->pan_version);
    if (wp_ies->gtkhash)
        ws_wp_nested_gtkhash_write(iobuf, ws->gtkhash);
    if (wp_ies->netname)
        ws_wp_nested_netname_write(iobuf, ws->netname);
    if (wp_ies->jm)
        ws_wp_nested_jm_write(iobuf, &ws->jm);
    SLIST_FOREACH(ie, &ws->ie_list, link)
        if (ie->frame_type_mask & BIT(frame_type) &&
            ie->ie_type != WS_IE_TYPE_HEADER)
            iobuf_push_data(iobuf, ie->buf.data, ie->buf.len);
    // TODO: remaning WP-IEs
    ieee802154_ie_fill_len_payload(iobuf, offset);
}

void ws_if_recv_ind(struct rcp *rcp, const struct rcp_rx_ind *hif_ind)
{
    struct ws_ctx *ws = container_of(rcp, struct ws_ctx, rcp);
    struct ws_ind ind = { .hif = hif_ind };
    struct iobuf_read ie_payload;
    struct ws_utt_ie ie_utt;
    struct ws_fc_ie ie_fc;
    int ret;

    ret = ieee802154_frame_parse(hif_ind->frame, hif_ind->frame_len,
                                 &ind.hdr, &ind.ie_hdr, &ie_payload);
    if (ret < 0)
        return;
    if (ind.hdr.key_index && ind.hdr.sec_level != IEEE802154_SEC_LEVEL_ENC_MIC64) {
        TRACE(TR_DROP, "drop %-9s: unsupported security level", "15.4");
        return;
    }
    if (!ws_wh_sl_utt_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_utt) &&
        !ws_wh_utt_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_utt)) {
        TRACE(TR_DROP, "drop %-9s: missing UTT-IE", "15.4");
        return;
    }
    // HACK: In FAN 1.0 the source address is elided in EDFE response frames
    if (ws_wh_fc_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_fc)) {
        if (!eui64_is_bc(&ind.hdr.src))
            ws->edfe_src = ind.hdr.src;
        else
            ind.hdr.src = ws->edfe_src;
    }

    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_WP, &ind.ie_wp);
    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_MPX, &ind.ie_mpx);

    ind.neigh = ws_neigh_get(&ws->neigh_table, &ind.hdr.src);
    if (!ind.neigh)
        // TODO: TX power (APC), active key indices
        ind.neigh = ws_neigh_add(&ws->neigh_table, &ind.hdr.src, WS_NR_ROLE_ROUTER, 16, 0x02);
    else
        ws_neigh_refresh(&ws->neigh_table, ind.neigh, ind.neigh->lifetime_s);
    ws_neigh_ut_update(&ind.neigh->fhss_data_unsecured, ie_utt.ufsi,
                       ind.hif->timestamp_us, &ind.hdr.src);
    ind.neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(ind.neigh->rsl_in_dbm_unsecured,
                                                         hif_ind->rx_power_dbm, WS_EWMA_SF);
    if (ind.hdr.key_index) {
        ws_neigh_ut_update(&ind.neigh->fhss_data, ie_utt.ufsi,
                           ind.hif->timestamp_us, &ind.hdr.src);
        ind.neigh->rsl_in_dbm = ws_neigh_ewma_next(ind.neigh->rsl_in_dbm,
                                                   hif_ind->rx_power_dbm, WS_EWMA_SF);
    }

    ws_print_ind(&ind, ie_utt.message_type);
    if (ws->on_recv_ind)
        ws->on_recv_ind(ws, &ind);
}

static struct ws_frame_ctx *ws_if_frame_ctx_new(struct ws_ctx *ws, uint8_t type)
{
    struct ws_frame_ctx *cur, *new;

    if (type == SL_FT_DCS &&
        SLIST_FIND(cur, &ws->frame_ctx_list, link, cur->type == type)) {
        WARN("%s tx overlap, consider increasing disc_period_s", tr_ws_frame(type));
        TRACE(TR_TX_ABORT, "tx-abort %-9s: tx already in progress", tr_ws_frame(type));
        return NULL;
    }
    if ((type == WS_FT_PAS || type == WS_FT_PA || type == WS_FT_PCS || type == WS_FT_PC) &&
        SLIST_FIND(cur, &ws->frame_ctx_list, link, cur->type == type)) {
        WARN("%s tx overlap, consider increasing trickle Imin", tr_ws_frame(type));
        TRACE(TR_TX_ABORT, "tx-abort %-9s: tx already in progress", tr_ws_frame(type));
        return NULL;
    }
    if (SLIST_SIZE(&ws->frame_ctx_list, link) > UINT8_MAX) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: no handle available", tr_ws_frame(type));
        return NULL;
    }

    new = zalloc(sizeof(*new));
    new->handle = ws->handle_next++;
    new->type = type;
    // If next handle is already in use (unlikely), use the next available one.
    while (SLIST_FIND(cur, &ws->frame_ctx_list, link,
                      cur->handle == new->handle))
        new->handle = ws->handle_next++;
    SLIST_INSERT_HEAD(&ws->frame_ctx_list, new, link);
    return new;
}

static struct ws_frame_ctx *ws_if_frame_ctx_pop(struct ws_ctx *ws, uint8_t handle)
{
    struct ws_frame_ctx *cur;

    cur = SLIST_FIND(cur, &ws->frame_ctx_list, link, cur->handle == handle);
    if (cur)
        SLIST_REMOVE(&ws->frame_ctx_list, cur, ws_frame_ctx, link);
    return cur;
}

void ws_if_recv_cnf(struct rcp *rcp, const struct rcp_tx_cnf *cnf)
{
    struct ws_ctx *ws = container_of(rcp, struct ws_ctx, rcp);
    struct iobuf_read ie_header, ie_payload;
    struct ws_frame_ctx *frame_ctx;
    struct ws_neigh *neigh = NULL;
    struct ieee802154_hdr hdr;
    struct ws_utt_ie ie_utt;
    struct ws_bt_ie ie_bt;
    int ret, rsl;

    if (cnf->status != HIF_STATUS_SUCCESS)
        TRACE(TR_TX_ABORT, "tx-abort 15.4: status %s", hif_status_str(cnf->status));

    frame_ctx = ws_if_frame_ctx_pop(ws, cnf->handle);
    if (!frame_ctx) {
        ERROR("unknown frame handle: %u", cnf->handle);
        return;
    }

    // DCS are async unicast packets to the chosen target
    if (frame_ctx->type != SL_FT_DCS && !eui64_is_bc(&frame_ctx->dst)) {
        neigh = ws_neigh_get(&ws->neigh_table, &frame_ctx->dst);
        if (!neigh) {
            WARN("%s: neighbor expired", __func__);
            // TODO: TX power (APC), active key indices
            neigh = ws_neigh_add(&ws->neigh_table, &frame_ctx->dst, WS_NR_ROLE_ROUTER, 16, BIT(1));
        }
    }

    if (neigh && cnf->frame_len) {
        ret = ieee802154_frame_parse(cnf->frame, cnf->frame_len, &hdr, &ie_header, &ie_payload);
        if (ret < 0) {
            WARN("%s: malformed frame", __func__);
            return;
        }
        // TODO: check frame counter
        ws_neigh_refresh(&ws->neigh_table, neigh, neigh->lifetime_s);
        neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(neigh->rsl_in_dbm_unsecured,
                                                         cnf->rx_power_dbm, WS_EWMA_SF);
        if (hdr.key_index)
            neigh->rsl_in_dbm = ws_neigh_ewma_next(neigh->rsl_in_dbm, cnf->rx_power_dbm, WS_EWMA_SF);
        if (ws_wh_rsl_read(ie_header.data, ie_header.data_size, &rsl))
            neigh->rsl_out_dbm = ws_neigh_ewma_next(neigh->rsl_out_dbm, rsl, WS_EWMA_SF);
        if (ws_wh_utt_read(ie_header.data, ie_header.data_size, &ie_utt)) {
            ws_neigh_ut_update(&neigh->fhss_data_unsecured, ie_utt.ufsi, cnf->timestamp_us, &neigh->eui64);
            if (hdr.key_index)
                ws_neigh_ut_update(&neigh->fhss_data, ie_utt.ufsi, cnf->timestamp_us, &neigh->eui64);
        }
        if (ws_wh_bt_read(ie_header.data, ie_header.data_size, &ie_bt)) {
            ws_neigh_bt_update(&neigh->fhss_data_unsecured, ie_bt.broadcast_slot_number,
                               ie_bt.broadcast_interval_offset, cnf->timestamp_us);
            if (hdr.key_index)
                ws_neigh_bt_update(&neigh->fhss_data, ie_bt.broadcast_slot_number,
                                   ie_bt.broadcast_interval_offset, cnf->timestamp_us);
        }
    }
    if (neigh)
        ws_neigh_etx_update(&ws->neigh_table, neigh,
                            cnf->tx_retries + 1,
                            cnf->status == HIF_STATUS_SUCCESS);
    if (ws->on_recv_cnf)
        ws->on_recv_cnf(ws, frame_ctx, cnf);
    free(frame_ctx);
}

int ws_if_send_data(struct ws_ctx *ws, const void *pkt, size_t pkt_len, const struct eui64 *dst)
{
    struct ws_neigh *neigh = ws_neigh_get(&ws->neigh_table, dst);
    struct ieee802154_hdr hdr = {
        .frame_type = IEEE802154_FRAME_TYPE_DATA,
        .ack_req    = neigh,
        .dst        = *dst,
        .src        = ws->rcp.eui64,
        .pan_id     = neigh ? UINT16_MAX : ws->pan_id,
        .seqno      = ws->seqno++, // TODO: think more about how seqno should be handled
        .sec_level  = IEEE802154_SEC_LEVEL_ENC_MIC64,
        .key_index  = ws->gak_index,
    };
    struct mpx_ie ie_mpx = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .multiplex_id  = MPX_ID_6LOWPAN,
    };
    struct wh_ie_list wh_ies = {
        .utt = true,
        // TODO: BT-IE, LBT-IE
    };
    struct wp_ie_list wp_ies = { }; // TODO: JM-IE
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    int offset;

    if (!ws->gak_index) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: security not ready", "15.4");
        return -EAGAIN;
    }
    if (!eui64_is_bc(dst) && !neigh) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: unknown neighbor %s", "15.4", tr_eui64(dst->u8));
        return -ETIMEDOUT;
    }
    if (neigh && !ws_neigh_has_us(&neigh->fhss_data_unsecured)) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: unknown unicast schedule for %s", "15.4", tr_eui64(dst->u8));
        return -EINVAL;
    }

    frame_ctx = ws_if_frame_ctx_new(ws, WS_FT_DATA);
    if (!frame_ctx)
        return -ENOMEM;
    frame_ctx->dst = hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    if (neigh) // TODO: only include US-IE if 1st unicast frame to neighbor
        wp_ies.us = true;
    ws_write_ies(ws, &iobuf, WS_FT_DATA, &wh_ies, &wp_ies, ie_mpx.multiplex_id);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_MPX);
    mpx_ie_write(&iobuf, &ie_mpx);
    iobuf_push_data(&iobuf, pkt, pkt_len);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    ieee802154_reserve_mic(&iobuf, &hdr);

    TRACE(TR_15_4_DATA, "tx-15.4 %-9s dst:%s", tr_ws_frame(WS_FT_DATA), tr_eui64(hdr.dst.u8));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    neigh ? HIF_FHSS_TYPE_FFN_UC : HIF_FHSS_TYPE_FFN_BC,
                    neigh ? &neigh->fhss_data_unsecured : NULL,
                    neigh ? neigh->frame_counter_min : NULL,
                    NULL, 0);  // TODO: mode switch
    iobuf_free(&iobuf);
    return frame_ctx->handle;
}

void ws_if_send_eapol(struct ws_ctx *ws, uint8_t kmp_id,
                   const void *pkt, size_t pkt_len,
                   const struct eui64 *dst,
                   const struct eui64 *ea)
{
    struct ieee802154_hdr hdr = {
        .frame_type = IEEE802154_FRAME_TYPE_DATA,
        .ack_req    = true,
        .dst        = *dst,
        .src        = ws->rcp.eui64,
        .seqno      = ws->seqno++, // TODO: think more about how seqno should be handled
        .pan_id     = UINT16_MAX,
    };
    struct mpx_ie ie_mpx = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .multiplex_id  = MPX_ID_KMP,
    };
    struct wh_ie_list wh_ies = {
        .utt = true,
        .ea  = ea,
        // TODO: BT-IE, LBT-IE
    };
    struct wp_ie_list wp_ies = {
        .us = true, // TODO: only include US-IE if 1st unicast frame to neighbor
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    struct ws_neigh *neigh;
    int offset;

    neigh = ws_neigh_get(&ws->neigh_table, dst);
    if (!neigh) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: unknown neighbor %s", "15.4", tr_eui64(dst->u8));
        return;
    }

    frame_ctx = ws_if_frame_ctx_new(ws, WS_FT_EAPOL);
    if (!frame_ctx)
        return;
    frame_ctx->dst = hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_write_ies(ws, &iobuf, WS_FT_EAPOL, &wh_ies, &wp_ies, MPX_ID_KMP);

    offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_MPX);
    mpx_ie_write(&iobuf, &ie_mpx);
    iobuf_push_u8(&iobuf, kmp_id);
    iobuf_push_data(&iobuf, pkt, pkt_len);
    ieee802154_ie_fill_len_payload(&iobuf, offset);

    TRACE(TR_15_4_DATA, "tx-15.4 %-9s dst:%s", tr_ws_frame(WS_FT_EAPOL), tr_eui64(dst->u8));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_FFN_UC,
                    &neigh->fhss_data_unsecured,
                    neigh->frame_counter_min,
                    NULL, 0); // TODO: mode switch
    iobuf_free(&iobuf);
}

void ws_if_send_pas(struct ws_ctx *ws)
{
    struct ieee802154_hdr hdr = {
        .frame_type   = IEEE802154_FRAME_TYPE_DATA,
        .seqno        = -1,
        .pan_id       = UINT16_MAX,
        .dst          = EUI64_BC,
        .src          = ws->rcp.eui64,
    };
    struct wh_ie_list wh_ies = {
        .utt = true,
    };
    struct wp_ie_list wp_ies = {
        .us      = true,
        .netname = true,
        // TODO: POM-IE
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };

    frame_ctx = ws_if_frame_ctx_new(ws, WS_FT_PAS);
    if (!frame_ctx)
        return;
    frame_ctx->dst = hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_write_ies(ws, &iobuf, WS_FT_PAS, &wh_ies, &wp_ies, 0);

    TRACE(TR_15_4_MNGT, "tx-15.4 %-9s", tr_ws_frame(WS_FT_PAS));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_ASYNC,
                    NULL, 0,
                    NULL, 0);
    iobuf_free(&iobuf);
}

void ws_if_send_pa(struct ws_ctx *ws, uint16_t pan_size, uint16_t routing_cost)
{
    struct ieee802154_hdr hdr = {
        .frame_type = IEEE802154_FRAME_TYPE_DATA,
        .seqno      = -1,
        .pan_id     = ws->pan_id,
        .dst        = EUI64_BC,
        .src        = ws->rcp.eui64,
    };
    struct wh_ie_list wh_ies = {
        .utt = true,
    };
    struct wp_ie_list wp_ies = {
        .us  = true,
        .pan = &(struct ws_pan_ie) {
            .pan_size         = pan_size,
            .routing_cost     = routing_cost,
            .use_parent_bs_ie = 1,
            .routing_method   = 1,
            .lfn_window_style = 0,
            // Reserved
            .fan_tps_version  = WS_FAN_VERSION_1_1,
        },
        .netname = true,
        .jm      = memzcmp(ws->jm.metrics, sizeof(ws->jm.metrics)),
        // TODO: POM-IE
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    uint8_t frame_type = WS_FT_PA;

    frame_ctx = ws_if_frame_ctx_new(ws, frame_type);
    if (!frame_ctx)
        return;
    frame_ctx->dst = hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_write_ies(ws, &iobuf, frame_type, &wh_ies, &wp_ies, 0);

    TRACE(TR_15_4_MNGT, "tx-15.4 %-9s", tr_ws_frame(frame_type));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_ASYNC,
                    NULL, 0,
                    NULL, 0);
    iobuf_free(&iobuf);
}

void ws_if_send_pcs(struct ws_ctx *ws)
{
    struct ieee802154_hdr hdr = {
        .frame_type   = IEEE802154_FRAME_TYPE_DATA,
        .seqno        = -1,
        .pan_id       = ws->pan_id,
        .dst          = EUI64_BC,
        .src          = ws->rcp.eui64,
        .sec_level    = IEEE802154_SEC_LEVEL_ENC_MIC64,
        .key_index    = ws->gak_index,
    };
    struct wh_ie_list wh_ies = {
        .utt = true,
    };
    struct wp_ie_list wp_ies = {
        .us      = true,
        .netname = true,
        // TODO: POM-IE
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };

    frame_ctx = ws_if_frame_ctx_new(ws, WS_FT_PCS);
    if (!frame_ctx)
        return;
    frame_ctx->dst = hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_write_ies(ws, &iobuf, WS_FT_PCS, &wh_ies, &wp_ies, 0);

    TRACE(TR_15_4_MNGT, "tx-15.4 %-9s panid:0x%x", tr_ws_frame(WS_FT_PCS), ws->pan_id);
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_ASYNC,
                    NULL, 0,
                    NULL, 0);
    iobuf_free(&iobuf);
}

void ws_if_send_pc(struct ws_ctx *ws)
{
    struct ieee802154_hdr hdr = {
        .frame_type = IEEE802154_FRAME_TYPE_DATA,
        .seqno      = -1,
        .pan_id     = ws->pan_id,
        .dst        = EUI64_BC,
        .src        = ws->rcp.eui64,
        .key_index  = ws->gak_index,
    };
    struct wh_ie_list wh_ies = {
        .utt = true,
        .bt  = true,
    };
    struct wp_ie_list wp_ies = {
        .us      = true,
        .bs      = true,
        .panver  = true,
        .gtkhash = true,
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    uint8_t frame_type = WS_FT_PC;

    if (!ws->gak_index) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: security not ready", "15.4");
        return;
    }

    frame_ctx = ws_if_frame_ctx_new(ws, frame_type);
    if (!frame_ctx)
        return;
    frame_ctx->dst = hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_write_ies(ws, &iobuf, frame_type, &wh_ies, &wp_ies, 0);
    iobuf_push_data_reserved(&iobuf, 8); // MIC-64

    TRACE(TR_15_4_MNGT, "tx-15.4 %-9s", tr_ws_frame(frame_type));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    HIF_FHSS_TYPE_ASYNC,
                    NULL, 0,
                    NULL, 0);
    iobuf_free(&iobuf);
}

void ws_if_send(struct ws_ctx *ws, struct ws_send_req *req)
{
    struct ws_neigh *neigh = ws_neigh_get(&ws->neigh_table, req->dst);
    struct ieee802154_hdr hdr = {
        .frame_type   = IEEE802154_FRAME_TYPE_DATA,
        .seqno        = req->pkt || req->fhss_type == HIF_FHSS_TYPE_FFN_BC ? ws->seqno++ : -1,
        .pan_id       = req->fhss_type != HIF_FHSS_TYPE_FFN_UC ? ws->pan_id : UINT16_MAX,
        .ack_req      = req->fhss_type == HIF_FHSS_TYPE_FFN_UC,
        .sec_level    = IEEE802154_SEC_LEVEL_ENC_MIC64,
        .key_index    = req->gak_index,
        .src          = ws->rcp.eui64,
        .dst          = *req->dst,
    };
    struct mpx_ie ie_mpx = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .multiplex_id  = req->multiplex_id,
    };
    struct ws_frame_ctx *frame_ctx;
    struct iobuf_write iobuf = { };
    int offset;

    frame_ctx = ws_if_frame_ctx_new(ws, req->frame_type);
    if (!frame_ctx)
        return;
    frame_ctx->dst =  hdr.dst;

    ieee802154_frame_write_hdr(&iobuf, &hdr);

    ws_write_ies(ws, &iobuf, req->frame_type, &req->wh_ies, &req->wp_ies, req->multiplex_id);

    if (req->multiplex_id) {
        offset = ieee802154_ie_push_payload(&iobuf, IEEE802154_IE_ID_MPX);
        mpx_ie_write(&iobuf, &ie_mpx);
        iobuf_push_data(&iobuf, req->pkt, req->pkt_len);
        ieee802154_ie_fill_len_payload(&iobuf, offset);
    }

    ieee802154_reserve_mic(&iobuf, &hdr);

    TRACE(TR_15_4_DATA, "tx-15.4 %-9s dst:%s", tr_ws_frame(req->frame_type), tr_eui64(hdr.dst.u8));
    rcp_req_data_tx(&ws->rcp,
                    iobuf.data, iobuf.len,
                    frame_ctx->handle,
                    req->fhss_type,
                    neigh ? &neigh->fhss_data_unsecured : NULL,
                    neigh ? neigh->frame_counter_min : NULL,
                    NULL, 0);
    iobuf_free(&iobuf);
}
