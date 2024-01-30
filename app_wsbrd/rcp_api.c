/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/frame_helpers.h"
#include "app_wsbrd/rcp_api_legacy.h"
#include "stack/source/nwk_interface/protocol.h"
#include "stack/source/nwk_interface/protocol_abstract.h"
#include "common/bits.h"
#include "common/endian.h"
#include "common/hif.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/spinel.h"
#include "common/string_extra.h"
#include "common/version.h"
#include "common/ws_regdb.h"
#include "rcp_api.h"

uint8_t rcp_rx_buf[4096];

static void rcp_tx(struct rcp *rcp, struct iobuf_write *buf)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);

    BUG_ON(!buf->len);
    TRACE(TR_HIF, "hif tx: %s %s", hif_cmd_str(buf->data[0]),
          tr_bytes(buf->data + 1, buf->len - 1,
                   NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
    rcp->device_tx(ctxt->os_ctxt, buf->data, buf->len);
}

static void rcp_ind_nop(struct rcp *rcp, struct iobuf_read *buf)
{
    BUG_ON(buf->err);
}

void rcp_req_reset(struct rcp *rcp, bool bootload)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RESET);
    hif_push_bool(&buf, bootload);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void rcp_ind_reset(struct rcp *rcp, struct iobuf_read *buf)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    const char *version_label;

    FATAL_ON(rcp->init_state & RCP_HAS_RESET, 3, "unsupported RCP reset");

    rcp->version_api = hif_pop_u32(buf);
    rcp->version_fw  = hif_pop_u32(buf);
    version_label    = hif_pop_str(buf);
    hif_pop_fixed_u8_array(buf, rcp->eui64, 8);
    BUG_ON(buf->err);

    BUG_ON(version_older_than(rcp->version_api, 2, 0, 0));
    rcp->version_label = strdup(version_label);
    BUG_ON(!rcp->version_label);
    rcp->init_state |= RCP_HAS_RESET;
    rcp->init_state |= RCP_HAS_HWADDR;

    if (rcp->on_reset)
        rcp->on_reset(ctxt);
}

static void rcp_ind_fatal(struct rcp *rcp, struct iobuf_read *buf)
{
    const char *msg;
    uint16_t err;

    err = hif_pop_u16(buf);
    msg = hif_pop_str(buf);
    BUG_ON(buf->err);

    if (msg)
        FATAL(3, "rcp error %s: %s", hif_fatal_str(err), msg);
    else
        FATAL(3, "rcp error %s", hif_fatal_str(err));
}

static void __rcp_set_host_api(struct rcp *rcp, uint32_t host_api_version)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_HOST_API);
    hif_push_u32(&buf, host_api_version);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_host_api(struct rcp *rcp, uint32_t host_api_version)
{
    if (!version_older_than(rcp->version_api, 2, 0, 0))
        __rcp_set_host_api(rcp, host_api_version);
}

#define HIF_MASK_FHSS_TYPE      0x0007
#define HIF_MASK_FHSS_DEFAULT   0x0010
#define HIF_MASK_MODE_SWITCH    0x0020
#define HIF_MASK_FRAME_COUNTERS 0x1fc0

static void __rcp_req_data_tx(struct rcp *rcp,
                              const uint8_t *frame, int frame_len,
                              uint8_t handle, uint8_t fhss_type,
                              const struct ws_neigh *neigh,
                              const struct hif_rate_info rate_list[4])
{
    struct iobuf_write buf = { };
    int bitfield_offset;
    uint16_t bitfield;

    hif_push_u8(&buf, HIF_CMD_REQ_DATA_TX);
    hif_push_u8(&buf, handle);
    hif_push_data(&buf, frame, frame_len);

    bitfield = 0;
    bitfield_offset = buf.len;
    hif_push_u16(&buf, 0);

    bitfield |= FIELD_PREP(HIF_MASK_FHSS_TYPE, fhss_type);
    switch (fhss_type) {
    case HIF_FHSS_TYPE_FFN_UC:
        BUG_ON(!neigh);
        BUG_ON(!neigh->fhss_data.ffn.uc_dwell_interval_ms);
        hif_push_u64(&buf, neigh->fhss_data.ffn.utt_rx_tstamp_us);
        hif_push_u24(&buf, neigh->fhss_data.ffn.ufsi);
        hif_push_u8(&buf, neigh->fhss_data.ffn.uc_dwell_interval_ms);
        break;
    case HIF_FHSS_TYPE_FFN_BC:
        bitfield |= HIF_MASK_FHSS_DEFAULT;
        break;
    case HIF_FHSS_TYPE_LFN_UC:
        BUG_ON(!neigh);
        BUG_ON(!neigh->fhss_data.lfn.uc_listen_interval_ms);
        hif_push_u64(&buf, neigh->fhss_data.lfn.lutt_rx_tstamp_us);
        hif_push_u16(&buf, neigh->fhss_data.lfn.uc_slot_number);
        hif_push_u24(&buf, neigh->fhss_data.lfn.uc_interval_offset_ms);
        hif_push_u24(&buf, neigh->fhss_data.lfn.uc_listen_interval_ms);
        break;
    case HIF_FHSS_TYPE_LFN_BC:
        bitfield |= HIF_MASK_FHSS_DEFAULT;
        break;
    case HIF_FHSS_TYPE_ASYNC:
        bitfield |= HIF_MASK_FHSS_DEFAULT;
        break;
    case HIF_FHSS_TYPE_LFN_PA:
        BUG_ON(!neigh);
        BUG_ON(!neigh->fhss_data.lfn.lpa_slot_duration_ms);
        hif_push_u64(&buf, neigh->fhss_data.lfn.lnd_rx_tstamp_us);
        hif_push_u32(&buf, neigh->fhss_data.lfn.lpa_response_delay_ms);
        hif_push_u8(&buf,  neigh->fhss_data.lfn.lpa_slot_duration_ms);
        hif_push_u8(&buf,  neigh->fhss_data.lfn.lpa_slot_count);
        hif_push_u16(&buf, neigh->fhss_data.lfn.lpa_slot_first);
        break;
    default:
        BUG();
    }
    if (fhss_type == HIF_FHSS_TYPE_FFN_UC || fhss_type == HIF_FHSS_TYPE_LFN_UC || fhss_type == HIF_FHSS_TYPE_LFN_PA) {
        hif_push_u8(&buf, neigh->fhss_data.uc_chan_func);
        switch (neigh->fhss_data.uc_chan_func) {
        case WS_CHAN_FUNC_FIXED:
            hif_push_u16(&buf, neigh->fhss_data.uc_chan_fixed);
            break;
        case WS_CHAN_FUNC_DH1CF: {
            uint8_t chan_mask_len = roundup(neigh->fhss_data.uc_chan_count, 8) / 8;

            hif_push_u8(&buf, chan_mask_len);
            hif_push_fixed_u8_array(&buf, neigh->fhss_data.uc_channel_list.channel_mask, chan_mask_len);
            break;
        }
        default:
            BUG();
        }
    }
    if (neigh) {
        for (uint8_t i = 0; i < ARRAY_SIZE(neigh->frame_counter_min); i++) {
            if (neigh->frame_counter_min[i] != UINT32_MAX) {
                bitfield |= FIELD_PREP(HIF_MASK_FRAME_COUNTERS, 1u << i);
                hif_push_u32(&buf, neigh->frame_counter_min[i]);
            }
        }
    }
    if (rate_list) {
        bitfield |= HIF_MASK_MODE_SWITCH;
        for (int i = 0; i < 4; i++) {
            hif_push_u8(&buf, rate_list[i].phy_mode_id);
            hif_push_u8(&buf, rate_list[i].tx_attempts);
            hif_push_i8(&buf, rate_list[i].tx_power_dbm);
        }
    }
    write_le16(buf.data + bitfield_offset, bitfield);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_req_data_tx(struct rcp *rcp,
                     const uint8_t *frame, int frame_len,
                     uint8_t handle, uint8_t fhss_type,
                     const struct ws_neigh *neigh,
                     const struct hif_rate_info rate_list[4])
{
    if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_tx_req(frame, frame_len, neigh, handle, fhss_type,
                          false, MAC_DATA_MEDIUM_PRIORITY,
                          rate_list ? rate_list[0].phy_mode_id : 0);
    else
        __rcp_req_data_tx(rcp, frame, frame_len, handle, fhss_type, neigh, rate_list);
}

static void __rcp_req_data_tx_abort(struct rcp *rcp, uint8_t handle)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_DATA_TX_ABORT);
    hif_push_u8(&buf, handle);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_req_data_tx_abort(struct rcp *rcp, uint8_t handle)
{
    if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_tx_drop(handle);
    else
        __rcp_req_data_tx_abort(rcp, handle);
}

static uint8_t rcp_data_status_hif2mlme(enum hif_data_status status)
{
    switch (status) {
    case HIF_STATUS_SUCCESS:  return MLME_SUCCESS;
    case HIF_STATUS_NOMEM:    return MLME_TRANSACTION_OVERFLOW;
    case HIF_STATUS_CCA:      return MLME_BUSY_CHAN;
    case HIF_STATUS_NOACK:    return MLME_TX_NO_ACK;
    case HIF_STATUS_TIMEDOUT: return MLME_TRANSACTION_EXPIRED;
    default:
        WARN("unknown status 0x%02x", status);
        return MLME_INVALID_PARAMETER; // arbitrary
    }
}

static void rcp_cnf_data_tx(struct rcp *rcp, struct iobuf_read *buf)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    struct mcps_data_rx_ie_list ie = { };
    struct mcps_data_cnf cnf = { };
    const uint8_t *frame;
    size_t frame_len;
    int ret;

    cnf.msduHandle    = hif_pop_u8(buf);
    cnf.status        = rcp_data_status_hif2mlme(hif_pop_u8(buf));
    frame_len         = hif_pop_data_ptr(buf, &frame);
    cnf.timestamp     = hif_pop_u64(buf);
    hif_pop_u8(buf);  // TODO: LQI
    hif_pop_u8(buf);  // TODO: RSSI
    cnf.frame_counter = hif_pop_u32(buf);
    hif_pop_u16(buf); // TODO: channel
    cnf.cca_retries   = hif_pop_u8(buf);
    cnf.tx_retries    = hif_pop_u8(buf);
    hif_pop_u8(buf);  // TODO: mode switch stats
    BUG_ON(buf->err);

    if (frame_len) {
        ret = wsbr_data_cnf_parse(frame, frame_len, &cnf, &ie);
        WARN_ON(ret < 0, "invalid ack frame");
    }
    ctxt->rcp.on_tx_cnf(ctxt->net_if.id, &cnf, &ie);
}

static void rcp_ind_data_rx(struct rcp *rcp, struct iobuf_read *buf)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    struct mcps_data_rx_ie_list ind_ie;
    struct mcps_data_ind ind;
    const uint8_t *frame;
    size_t frame_len;
    int ret;

    frame_len           = hif_pop_data_ptr(buf, &frame);
    ind.timestamp       = hif_pop_u64(buf);
    ind.mpduLinkQuality = hif_pop_u8(buf); // LQI
    ind.signal_dbm      = hif_pop_i8(buf); // RSSI
    hif_pop_u8(buf);  // TODO: RX PhyModeId
    hif_pop_u16(buf); // TODO: RX channel
    BUG_ON(buf->err);

    ret = wsbr_data_ind_parse(frame, frame_len, &ind, &ind_ie, ctxt->net_if.ws_info.pan_information.pan_id);
    if (ret < 0)
        return;
    ctxt->rcp.on_rx_ind(ctxt->net_if.id, &ind, &ind_ie);
}

static void __rcp_req_radio_enable(struct rcp *rcp)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RADIO_ENABLE);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void __rcp_set_filter_pan_id(struct rcp *rcp, uint16_t pan_id);
void rcp_req_radio_enable(struct rcp *rcp, uint16_t pan_id)
{
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_start(pan_id, true);
    } else {
        __rcp_set_filter_pan_id(rcp, pan_id);
        __rcp_req_radio_enable(rcp);
    }
}

static void __rcp_req_radio_list(struct rcp *rcp)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RADIO_LIST);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_req_radio_list(struct rcp *rcp)
{
    if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_get_rf_config_list();
    else
        __rcp_req_radio_list(rcp);
}

#define HIF_MASK_RADIO_LIST_GROUP 0x0001
#define HIF_MASK_RADIO_LIST_MCS   0x01fe

static void rcp_cnf_radio_list(struct rcp *rcp, struct iobuf_read *buf)
{
    const struct phy_params *phy_params;
    bool group_bit, group_bit_prev, list_end;
    int phy_mode_group = 0;
    uint8_t entry_size;
    uint16_t flags;
    int offset;
    int i = 0;

    BUG_ON(rcp->init_state & RCP_HAS_RF_CONFIG_LIST);
    entry_size = hif_pop_u8(buf);
    BUG_ON(entry_size < 2 + 1 + 4 + 4 + 2);
    list_end   = hif_pop_bool(buf);
    if (rcp->rail_config_list)
        while (rcp->rail_config_list[i].chan0_freq)
            i++;
    group_bit_prev = true;
    while (iobuf_remaining_size(buf)) {
        rcp->rail_config_list = reallocarray(rcp->rail_config_list, i + 2, sizeof(struct rcp_rail_config));
        offset = buf->cnt;
        flags = hif_pop_u16(buf);
        rcp->rail_config_list[i].index = i;
        rcp->rail_config_list[i].rail_phy_mode_id = hif_pop_u8(buf);
        rcp->rail_config_list[i].chan0_freq       = hif_pop_u32(buf);
        rcp->rail_config_list[i].chan_spacing     = hif_pop_u32(buf);
        rcp->rail_config_list[i].chan_count       = hif_pop_u16(buf);
        if (buf->cnt - offset < entry_size)
            hif_pop_fixed_u8_array(buf, NULL, entry_size - (buf->cnt - offset));
        phy_params = ws_regdb_phy_params(rcp->rail_config_list[i].rail_phy_mode_id, 0);
        if (phy_params && phy_params->modulation == MODULATION_OFDM &&
            FIELD_GET(HIF_MASK_RADIO_LIST_MCS, flags) != 0x00ff)
            BUG("unsupported OFDM PHY with MCS support not 0-7");
        group_bit = FIELD_GET(HIF_MASK_RADIO_LIST_GROUP, flags);
        BUG_ON(i == 0 && group_bit);
        if (group_bit && !group_bit_prev)
            rcp->rail_config_list[i - 1].phy_mode_group = ++phy_mode_group;
        rcp->rail_config_list[i].phy_mode_group = group_bit ? phy_mode_group : 0;
        group_bit_prev = group_bit;
        i++;
    }
    memset(&rcp->rail_config_list[i], 0, sizeof(struct rcp_rail_config));
    BUG_ON(buf->err || iobuf_remaining_size(buf));
    if (list_end)
        rcp->init_state |= RCP_HAS_RF_CONFIG_LIST;
}

static void __rcp_set_radio(struct rcp *rcp, uint8_t radioconf_index, uint8_t ofdm_mcs, bool enable_ms)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO);
    hif_push_u8(&buf, radioconf_index);
    hif_push_u8(&buf, ofdm_mcs);
    hif_push_bool(&buf, enable_ms);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);

    rcp->init_state |= RCP_HAS_RF_CONFIG;
}

void rcp_set_radio(struct rcp *rcp, const struct phy_rf_channel_configuration *rf_config)
{
    if (version_older_than(rcp->version_api, 0, 25, 1))
        rcp_legacy_set_rf_config_legacy(rf_config);
    else if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_set_rf_config(rf_config);
    else
        __rcp_set_radio(rcp,
                        rf_config->rcp_config_index,
                        rf_config->ofdm_mcs,
                        rf_config->use_phy_op_modes);
}

static void __rcp_set_radio_regulation(struct rcp *rcp, enum hif_reg reg)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO_REGULATION);
    hif_push_u8(&buf, reg);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

enum {
    // These values are part of the legacy RCP API.
    REG_REGIONAL_NONE = 0,
    REG_REGIONAL_ARIB = 1,
    REG_REGIONAL_UNDEF,
};

void rcp_set_radio_regulation(struct rcp *rcp, enum hif_reg reg)
{
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        if (reg == HIF_REG_ARIB)
            rcp_legacy_set_regional_regulation(REG_REGIONAL_ARIB);
        else if (reg == HIF_REG_NONE)
            rcp_legacy_set_regional_regulation(REG_REGIONAL_NONE);
        else
            rcp_legacy_set_regional_regulation(REG_REGIONAL_UNDEF);
        rcp_legacy_set_edfe_mode(reg != HIF_REG_ARIB);
    } else {
        __rcp_set_radio_regulation(rcp, reg);
    }
}

static void __rcp_set_radio_tx_power(struct rcp *rcp, int8_t power_dbm)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO_TX_POWER);
    hif_push_i8(&buf, power_dbm);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_radio_tx_power(struct rcp *rcp, int8_t power_dbm)
{
    if (version_older_than(rcp->version_api, 2, 0, 0))
        rcp_legacy_set_tx_power(power_dbm);
    else
        __rcp_set_radio_tx_power(rcp, power_dbm);
}

static void __rcp_set_fhss_uc(struct rcp *rcp, const struct fhss_ws_configuration *cfg)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_FHSS_UC);
    hif_push_u8(&buf, cfg->fhss_uc_dwell_interval);
    hif_push_u8(&buf, cfg->ws_uc_channel_function);
    switch (cfg->ws_uc_channel_function) {
    case WS_CHAN_FUNC_FIXED:
        hif_push_u16(&buf, cfg->unicast_fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
        hif_push_u8(&buf, sizeof(cfg->unicast_channel_mask));
        hif_push_fixed_u8_array(&buf, cfg->unicast_channel_mask, sizeof(cfg->unicast_channel_mask));
        break;
    default:
        BUG("unsupported channel function");
        break;
    }
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void __rcp_set_fhss_ffn_bc(struct rcp *rcp, const struct fhss_ws_configuration *cfg)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf,  HIF_CMD_SET_FHSS_FFN_BC);
    hif_push_u24(&buf, cfg->fhss_broadcast_interval);
    hif_push_u16(&buf, cfg->bsi);
    hif_push_u8(&buf,  cfg->fhss_bc_dwell_interval);
    hif_push_u8(&buf,  cfg->ws_bc_channel_function);
    switch (cfg->ws_bc_channel_function) {
    case WS_CHAN_FUNC_FIXED:
        hif_push_u16(&buf, cfg->broadcast_fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
        hif_push_u8(&buf, sizeof(cfg->broadcast_channel_mask));
        hif_push_fixed_u8_array(&buf, cfg->broadcast_channel_mask, sizeof(cfg->broadcast_channel_mask));
        break;
    default:
        BUG("unsupported channel function");
        break;
    }
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void __rcp_set_fhss_lfn_bc(struct rcp *rcp, const struct fhss_ws_configuration *cfg)
{
    struct iobuf_write buf = { };

    // FIXME: Some parameters are shared with FFN broadcast
    hif_push_u8(&buf,  HIF_CMD_SET_FHSS_LFN_BC);
    hif_push_u24(&buf, cfg->lfn_bc_interval);
    hif_push_u16(&buf, cfg->bsi);
    hif_push_u8(&buf,  cfg->ws_bc_channel_function);
    switch (cfg->ws_bc_channel_function) {
    case WS_CHAN_FUNC_FIXED:
        hif_push_u16(&buf, cfg->broadcast_fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
        hif_push_u8(&buf, sizeof(cfg->broadcast_channel_mask));
        hif_push_fixed_u8_array(&buf, cfg->broadcast_channel_mask, sizeof(cfg->broadcast_channel_mask));
        break;
    default:
        BUG("unsupported channel function");
        break;
    }
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void __rcp_set_fhss_async(struct rcp *rcp, const struct fhss_ws_configuration *cfg)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf,  HIF_CMD_SET_FHSS_ASYNC);
    hif_push_u32(&buf, cfg->async_tx_duration_ms);
    hif_push_u8(&buf, sizeof(cfg->domain_channel_mask));
    hif_push_fixed_u8_array(&buf, cfg->domain_channel_mask, sizeof(cfg->domain_channel_mask));
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss(struct rcp *rcp, const struct fhss_ws_configuration *cfg)
{
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_set_fhss_timings(cfg);
        if (!version_older_than(rcp->version_api, 0, 17, 0))
            rcp_legacy_set_max_async_duration(cfg->async_tx_duration_ms);
    } else {
        __rcp_set_fhss_uc(rcp, cfg);
        __rcp_set_fhss_ffn_bc(rcp, cfg);
        __rcp_set_fhss_lfn_bc(rcp, cfg);
        __rcp_set_fhss_async(rcp, cfg);
    }
}

static void __rcp_set_sec_key(struct rcp *rcp,
                              uint8_t key_index,
                              const uint8_t key[16],
                              uint32_t frame_counter)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_SEC_KEY);
    hif_push_u8(&buf, key_index);
    hif_push_fixed_u8_array(&buf, key ? : (uint8_t[16]){ }, 16);
    hif_push_u32(&buf, frame_counter);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_sec_key(struct rcp *rcp,
                     uint8_t key_index,
                     const uint8_t key[16],
                     uint32_t frame_counter)
{
    const uint8_t lookup_data[9] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, key_index
    };

    BUG_ON(key_index < 1 || key_index > 7);
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_set_key(key_index - 1, lookup_data, key);
        if (key && !memzcmp(key, 16))
            rcp_legacy_set_frame_counter(key_index - 1, frame_counter);
    } else {
        __rcp_set_sec_key(rcp, key_index, key, frame_counter);
    }
}

static void __rcp_set_filter_pan_id(struct rcp *rcp, uint16_t pan_id)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_FILTER_PANID);
    hif_push_u16(&buf, pan_id);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void __rcp_set_filter_src64(struct rcp *rcp, const uint8_t eui64[][8], uint8_t count, bool allow)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_FILTER_SRC64);
    hif_push_bool(&buf, allow);
    hif_push_u8(&buf, count);
    while (count--)
        hif_push_fixed_u8_array(&buf, *eui64++, 8);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_filter_src64(struct rcp *rcp, const uint8_t eui64[][8], uint8_t count, bool allow)
{
    if (version_older_than(rcp->version_api, 0, 3, 0))
        FATAL(1, "allowed_mac64/denied_mac64 requires RCP API >= 0.3.0");
    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_enable_mac_filter(!allow);
        rcp_legacy_clear_mac_filters();
        while (count--)
            rcp_legacy_add_mac_filter_entry(*eui64++, allow);
    } else {
        __rcp_set_filter_src64(rcp, eui64, count, allow);
    }
}

static const struct {
    uint8_t cmd;
    void (*fn)(struct rcp *rcp, struct iobuf_read *buf);
} rcp_cmd_table[] = {
    { HIF_CMD_IND_NOP,        rcp_ind_nop        },
    { HIF_CMD_IND_RESET,      rcp_ind_reset      },
    { HIF_CMD_IND_FATAL,      rcp_ind_fatal      },
    { HIF_CMD_CNF_DATA_TX,    rcp_cnf_data_tx    },
    { HIF_CMD_IND_DATA_RX,    rcp_ind_data_rx    },
    { HIF_CMD_CNF_RADIO_LIST, rcp_cnf_radio_list },
};

void rcp_rx(struct rcp *rcp)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);
    struct iobuf_read buf = { .data = rcp_rx_buf };
    uint32_t cmd;

    if (version_older_than(rcp->version_api, 2, 0, 0)) {
        rcp_legacy_rx(ctxt);
        return;
    }

    buf.data_size = rcp->device_rx(ctxt->os_ctxt, rcp_rx_buf, sizeof(rcp_rx_buf));
    if (!buf.data_size)
        return;
    cmd = hif_pop_u8(&buf);
    if (cmd == 0xff)
        spinel_trace(buf.data, buf.data_size, "hif rx: ");
    else
        TRACE(TR_HIF, "hif rx: %s %s", hif_cmd_str(cmd),
              tr_bytes(iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                       NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
    for (int i = 0; i < ARRAY_SIZE(rcp_cmd_table); i++)
        if (rcp_cmd_table[i].cmd == cmd)
            return rcp_cmd_table[i].fn(rcp, &buf);
    TRACE(TR_DROP, "drop %-9s: unsupported command 0x%02x", "hif", cmd);
}
