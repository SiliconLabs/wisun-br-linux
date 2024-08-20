/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <poll.h>

#include "common/bus_uart.h"
#include "common/bus_cpc.h"
#include "common/bits.h"
#include "common/capture.h"
#include "common/endian.h"
#include "common/hif.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/string_extra.h"
#include "common/version.h"
#include "common/ws_neigh.h"
#include "common/ws_regdb.h"
#include "common/specs/ws.h"

#include "rcp_api.h"

uint8_t rcp_rx_buf[4096];

// See IEEE 802.15.4-2020 - 6.16.2.8 Received Signal Strength Indicator (RSSI)
// [...] the minimum and maximum values are 0 (–174 dBm) and 254 (80 dBm)
#define RX_POWER_DBM_MAX 80

static void rcp_tx(struct rcp *rcp, struct iobuf_write *buf)
{
    BUG_ON(!buf->len);
    TRACE(TR_HIF, "hif tx: %s %s", hif_cmd_str(buf->data[0]),
          tr_bytes(buf->data + 1, buf->len - 1,
                   NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
    rcp->bus.tx(&rcp->bus, buf->data, buf->len);
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
    const char *version_label;

    FATAL_ON(rcp->has_reset, 3, "unsupported RCP reset");

    rcp->version_api = hif_pop_u32(buf);
    rcp->version_fw  = hif_pop_u32(buf);
    version_label    = hif_pop_str(buf);
    hif_pop_fixed_u8_array(buf, rcp->eui64.u8, 8);
    BUG_ON(buf->err);

    BUG_ON(version_older_than(rcp->version_api, 2, 0, 0));
    rcp->version_label = strdup(version_label);
    BUG_ON(!rcp->version_label);
    rcp->has_reset = true;

    if (rcp->on_reset)
        rcp->on_reset(rcp);
}

static void rcp_ind_fatal(struct rcp *rcp, struct iobuf_read *buf)
{
    const char *msg;
    uint16_t err;

    err = hif_pop_u16(buf);
    msg = hif_pop_str(buf);
    BUG_ON(buf->err);

    // CRC errors can happen during init if a previous frame transmission was
    // interrupted.
    if (err == HIF_ECRC && !rcp->has_reset)
        return;

    if (msg)
        FATAL(3, "rcp error %s: %s", hif_fatal_str(err), msg);
    else
        FATAL(3, "rcp error %s", hif_fatal_str(err));
}

void rcp_set_host_api(struct rcp *rcp, uint32_t host_api_version)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_HOST_API);
    hif_push_u32(&buf, host_api_version);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

#define HIF_MASK_FHSS_TYPE      0x0007
#define HIF_MASK_FHSS_DEFAULT   0x0010
#define HIF_MASK_MODE_SWITCH    0x0020
#define HIF_MASK_FRAME_COUNTERS 0x1fc0
#define HIF_MASK_MODE_SWITCH_TYPE 0x2000

void rcp_req_data_tx(struct rcp *rcp,
                     const uint8_t *frame, int frame_len,
                     uint8_t handle, uint8_t fhss_type,
                     const struct ws_neigh_fhss *fhss_data,
                     const uint32_t frame_counters_min[7],
                     const struct rcp_rate_info rate_list[4], uint8_t ms_mode)
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
        BUG_ON(!fhss_data);
        BUG_ON(!fhss_data->ffn.uc_dwell_interval_ms);
        hif_push_u64(&buf, fhss_data->ffn.utt_rx_tstamp_us);
        hif_push_u24(&buf, fhss_data->ffn.ufsi);
        hif_push_u8(&buf, fhss_data->ffn.uc_dwell_interval_ms);
        break;
    case HIF_FHSS_TYPE_FFN_BC:
        bitfield |= HIF_MASK_FHSS_DEFAULT;
        break;
    case HIF_FHSS_TYPE_LFN_UC:
        BUG_ON(!fhss_data);
        BUG_ON(!fhss_data->lfn.uc_listen_interval_ms);
        hif_push_u64(&buf, fhss_data->lfn.lutt_rx_tstamp_us);
        hif_push_u16(&buf, fhss_data->lfn.uc_slot_number);
        hif_push_u24(&buf, fhss_data->lfn.uc_interval_offset_ms);
        hif_push_u24(&buf, fhss_data->lfn.uc_listen_interval_ms);
        break;
    case HIF_FHSS_TYPE_LFN_BC:
        bitfield |= HIF_MASK_FHSS_DEFAULT;
        break;
    case HIF_FHSS_TYPE_ASYNC:
        bitfield |= HIF_MASK_FHSS_DEFAULT;
        break;
    case HIF_FHSS_TYPE_LFN_PA:
        BUG_ON(!fhss_data);
        BUG_ON(!fhss_data->lfn.lpa_slot_duration_ms);
        hif_push_u64(&buf, fhss_data->lfn.lnd_rx_tstamp_us);
        hif_push_u32(&buf, fhss_data->lfn.lpa_response_delay_ms);
        hif_push_u8(&buf,  fhss_data->lfn.lpa_slot_duration_ms);
        hif_push_u8(&buf,  fhss_data->lfn.lpa_slot_count);
        hif_push_u16(&buf, fhss_data->lfn.lpa_slot_first);
        break;
    default:
        BUG();
    }
    if (fhss_type == HIF_FHSS_TYPE_FFN_UC || fhss_type == HIF_FHSS_TYPE_LFN_UC || fhss_type == HIF_FHSS_TYPE_LFN_PA) {
        hif_push_u8(&buf, fhss_data->uc_chan_func);
        switch (fhss_data->uc_chan_func) {
        case WS_CHAN_FUNC_FIXED: {
            int chan_fixed = ws_chan_mask_get_fixed(fhss_data->uc_channel_list);

            BUG_ON(chan_fixed < 0);
            hif_push_u16(&buf, chan_fixed);
            break;
        }
        case WS_CHAN_FUNC_DH1CF: {
            uint8_t chan_mask_len = ws_chan_mask_width(fhss_data->uc_channel_list);

            hif_push_u8(&buf, chan_mask_len);
            hif_push_fixed_u8_array(&buf, fhss_data->uc_channel_list, chan_mask_len);
            break;
        }
        default:
            BUG();
        }
    }
    if (frame_counters_min) {
        for (uint8_t i = 0; i < 7; i++) {
            if (frame_counters_min[i] != UINT32_MAX) {
                bitfield |= FIELD_PREP(HIF_MASK_FRAME_COUNTERS, BIT(i));
                hif_push_u32(&buf, frame_counters_min[i]);
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

    bitfield |= FIELD_PREP(HIF_MASK_MODE_SWITCH_TYPE, ms_mode);

    write_le16(buf.data + bitfield_offset, bitfield);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_req_data_tx_abort(struct rcp *rcp, uint8_t handle)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_DATA_TX_ABORT);
    hif_push_u8(&buf, handle);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

static void rcp_cnf_data_tx(struct rcp *rcp, struct iobuf_read *buf)
{
    struct rcp_tx_cnf cnf = { };

    cnf.handle        = hif_pop_u8(buf);
    cnf.status        = hif_pop_u8(buf);
    cnf.frame_len     = hif_pop_data_ptr(buf, &cnf.frame);
    cnf.timestamp_us  = hif_pop_u64(buf);
    cnf.lqi           = hif_pop_u8(buf);
    cnf.rx_power_dbm  = hif_pop_u8(buf);
    cnf.frame_counter = hif_pop_u32(buf);
    cnf.chan_num      = hif_pop_u16(buf);
    cnf.cca_retries   = hif_pop_u8(buf);
    cnf.tx_retries    = hif_pop_u8(buf);
    hif_pop_u8(buf);  // TODO: mode switch stats
    BUG_ON(buf->err);
    rcp->on_tx_cnf(rcp, &cnf);
}

static void rcp_ind_data_rx(struct rcp *rcp, struct iobuf_read *buf)
{
    struct rcp_rx_ind ind = { };

    ind.frame_len    = hif_pop_data_ptr(buf, &ind.frame);
    ind.timestamp_us = hif_pop_u64(buf);
    ind.lqi          = hif_pop_u8(buf);
    ind.rx_power_dbm = hif_pop_i8(buf);
    ind.phy_mode_id  = hif_pop_u8(buf);
    ind.chan_num     = hif_pop_u16(buf);
    BUG_ON(buf->err);
    BUG_ON(ind.rx_power_dbm > RX_POWER_DBM_MAX);
    rcp->on_rx_ind(rcp, &ind);
}

void rcp_req_radio_enable(struct rcp *rcp)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RADIO_ENABLE);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_req_radio_list(struct rcp *rcp)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_REQ_RADIO_LIST);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
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

    BUG_ON(rcp->has_rf_list);
    entry_size = hif_pop_u8(buf);
    if (version_older_than(rcp->version_api, 2, 4, 0))
        BUG_ON(entry_size < 2 + 1 + 4 + 4 + 2);
    else
        BUG_ON(entry_size < 2 + 1 + 4 + 4 + 2 + 2);
    list_end   = hif_pop_bool(buf);
    if (rcp->rail_config_list)
        while (rcp->rail_config_list[i].chan0_freq)
            i++;
    else
        rcp->rail_config_list = xalloc(sizeof(struct rcp_rail_config));
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
        if (!version_older_than(rcp->version_api, 2, 4, 0))
            rcp->rail_config_list[i].sensitivity_dbm  = hif_pop_i16(buf);
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
        rcp->has_rf_list = true;
}

void rcp_set_radio(struct rcp *rcp, uint8_t radioconf_index, uint8_t ofdm_mcs, bool enable_ms)
{
    struct iobuf_write buf = { };

    if (version_older_than(rcp->version_api, 2, 0, 1))
        enable_ms = !enable_ms; // API < 2.0.1 has this inverted

    hif_push_u8(&buf, HIF_CMD_SET_RADIO);
    hif_push_u8(&buf, radioconf_index);
    hif_push_u8(&buf, ofdm_mcs);
    hif_push_bool(&buf, enable_ms);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_radio_regulation(struct rcp *rcp, enum hif_reg reg)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO_REGULATION);
    hif_push_u8(&buf, reg);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_radio_tx_power(struct rcp *rcp, int8_t power_dbm)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_RADIO_TX_POWER);
    hif_push_i8(&buf, power_dbm);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_uc(struct rcp *rcp,
                     uint8_t dwell_interval_ms,
                     const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    int fixed_channel = ws_chan_mask_get_fixed(chan_mask);
    uint8_t chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_FHSS_UC);
    hif_push_u8(&buf, dwell_interval_ms);
    hif_push_u8(&buf, chan_func);
    switch (chan_func) {
    case WS_CHAN_FUNC_FIXED:
        if (version_older_than(rcp->version_api, 2, 1, 1))
            FATAL(3, "fixed channel requires RCP API > 2.1.1");
        BUG_ON(fixed_channel < 0);
        hif_push_u16(&buf, fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
        hif_push_u8(&buf, WS_CHAN_MASK_LEN);
        hif_push_fixed_u8_array(&buf, chan_mask, WS_CHAN_MASK_LEN);
        break;
    default:
        BUG("unsupported channel function");
        break;
    }
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_ffn_bc(struct rcp *rcp,
                         uint24_t interval_ms,
                         uint16_t bsi,
                         uint8_t  dwell_interval_ms,
                         const uint8_t chan_mask[WS_CHAN_MASK_LEN],
                         uint64_t rx_timestamp_us,
                         uint16_t slot,
                         uint32_t interval_offset_ms,
                         const uint8_t eui64[8],
                         const uint32_t frame_counter_min[4])
{
    int fixed_channel = ws_chan_mask_get_fixed(chan_mask);
    uint8_t chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    struct iobuf_write buf = { };

    hif_push_u8(&buf,  HIF_CMD_SET_FHSS_FFN_BC);
    hif_push_u24(&buf, interval_ms);
    hif_push_u16(&buf, bsi);
    hif_push_u8(&buf,  dwell_interval_ms);
    hif_push_u8(&buf,  chan_func);
    switch (chan_func) {
    case WS_CHAN_FUNC_FIXED:
        if (version_older_than(rcp->version_api, 2, 1, 1))
            FATAL(3, "fixed channel requires RCP API > 2.1.1");
        BUG_ON(fixed_channel < 0);
        hif_push_u16(&buf, fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
        hif_push_u8(&buf, WS_CHAN_MASK_LEN);
        hif_push_fixed_u8_array(&buf, chan_mask, WS_CHAN_MASK_LEN);
        break;
    default:
        BUG("unsupported channel function");
        break;
    }

    if (rx_timestamp_us) {
        BUG_ON(version_older_than(rcp->version_api, 2, 3, 0));
        hif_push_u64(&buf, rx_timestamp_us);
        hif_push_u16(&buf, slot);
        hif_push_u32(&buf, interval_offset_ms);
        if (eui64) {
            hif_push_fixed_u8_array(&buf, eui64, 8);
            hif_push_fixed_u32_array(&buf, frame_counter_min, 4); // Only 4 GTK counters
        }
    }

    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_lfn_bc(struct rcp *rcp,
                         uint24_t interval_ms,
                         uint16_t bsi,
                         const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    int fixed_channel = ws_chan_mask_get_fixed(chan_mask);
    uint8_t chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    struct iobuf_write buf = { };

    hif_push_u8(&buf,  HIF_CMD_SET_FHSS_LFN_BC);
    hif_push_u24(&buf, interval_ms);
    hif_push_u16(&buf, bsi);
    hif_push_u8(&buf,  chan_func);
    switch (chan_func) {
    case WS_CHAN_FUNC_FIXED:
        if (version_older_than(rcp->version_api, 2, 1, 1))
            FATAL(3, "fixed channel requires RCP API > 2.1.1");
        BUG_ON(fixed_channel < 0);
        hif_push_u16(&buf, fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
        hif_push_u8(&buf, WS_CHAN_MASK_LEN);
        hif_push_fixed_u8_array(&buf, chan_mask, WS_CHAN_MASK_LEN);
        break;
    default:
        BUG("unsupported channel function");
        break;
    }
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_async(struct rcp *rcp,
                        uint32_t tx_duration_ms,
                        const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf,  HIF_CMD_SET_FHSS_ASYNC);
    hif_push_u32(&buf, tx_duration_ms);
    hif_push_u8(&buf, 32);
    hif_push_fixed_u8_array(&buf, chan_mask, WS_CHAN_MASK_LEN);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_sec_key(struct rcp *rcp,
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

void rcp_set_filter_pan_id(struct rcp *rcp, uint16_t pan_id)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_SET_FILTER_PANID);
    hif_push_u16(&buf, pan_id);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

void rcp_set_filter_src64(struct rcp *rcp, const uint8_t eui64[][8], uint8_t count, bool allow)
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

void rcp_set_filter_dst64(struct rcp *rcp, const uint8_t eui64[8])
{
    struct iobuf_write buf = { };

    memcpy(&rcp->eui64, eui64, 8);

    hif_push_u8(&buf, HIF_CMD_SET_FILTER_DST64);
    hif_push_fixed_u8_array(&buf, eui64, 8);
    rcp_tx(rcp, &buf);
    iobuf_free(&buf);
}

struct rcp_cmd rcp_cmd_table[] = {
    { HIF_CMD_IND_NOP,           rcp_ind_nop        },
    { HIF_CMD_IND_RESET,         rcp_ind_reset      },
    { HIF_CMD_IND_FATAL,         rcp_ind_fatal      },
    { HIF_CMD_CNF_DATA_TX,       rcp_cnf_data_tx    },
    { HIF_CMD_IND_DATA_RX,       rcp_ind_data_rx    },
    { HIF_CMD_CNF_RADIO_LIST,    rcp_cnf_radio_list },
    { HIF_CMD_IND_REPLAY_TIMER,  rcp_ind_nop        },
    { HIF_CMD_IND_REPLAY_SOCKET, rcp_ind_nop        },
    { 0 }
};

static bool rcp_init_state_is_valid(struct rcp *rcp, uint8_t cmd)
{
    if (!rcp->has_reset)
        return cmd == HIF_CMD_IND_RESET;
    if (!rcp->has_rf_list)
        return cmd == HIF_CMD_CNF_RADIO_LIST;
    return true;
}

void rcp_rx(struct rcp *rcp)
{
    struct iobuf_read buf = { .data = rcp_rx_buf };
    uint32_t cmd;

    buf.data_size = rcp->bus.rx(&rcp->bus, rcp_rx_buf, sizeof(rcp_rx_buf));
    if (!buf.data_size)
        return;
    capture_record_hif(buf.data, buf.data_size);
    cmd = hif_pop_u8(&buf);
    TRACE(TR_HIF, "hif rx: %s %s", hif_cmd_str(cmd),
          tr_bytes(iobuf_ptr(&buf), iobuf_remaining_size(&buf),
                   NULL, 128, DELIM_SPACE | ELLIPSIS_STAR));
    if (!rcp_init_state_is_valid(rcp, cmd)) {
        TRACE(TR_DROP, "drop %-9s: unexpected command during reset sequence", "hif");
        return;
    }
    for (int i = 0; rcp_cmd_table[i].fn; i++)
        if (rcp_cmd_table[i].cmd == cmd)
            return rcp_cmd_table[i].fn(rcp, &buf);
    TRACE(TR_DROP, "drop %-9s: unsupported command 0x%02x", "hif", cmd);
}

void rcp_init(struct rcp *rcp, const struct rcp_cfg *config)
{
    struct pollfd pfd = { };
    int ret;

    if (config->uart_dev[0]) {
        rcp->bus.fd = uart_open(config->uart_dev, config->uart_baudrate, config->uart_rtscts);
        rcp->version_api = VERSION(2, 0, 0); // default assumed version
        rcp->bus.tx = uart_tx;
        rcp->bus.rx = uart_rx;
    } else if (config->cpc_instance[0]) {
        rcp->bus.tx = cpc_tx;
        rcp->bus.rx = cpc_rx;
        rcp->bus.fd = cpc_open(&rcp->bus, config->cpc_instance, g_enabled_traces & TR_CPC);
        rcp->version_api = cpc_secondary_app_version(&rcp->bus);
        if (version_older_than(rcp->version_api, 2, 0, 0))
            FATAL(3, "RCP API < 2.0.0 (too old)");
    } else {
        BUG();
    }

    rcp_req_reset(rcp, false);

    pfd.fd = rcp->bus.fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 5000);
    FATAL_ON(ret < 0, 2, "%s poll: %m", __func__);
    WARN_ON(!ret, "RCP is not responding");

    rcp->bus.uart.init_phase = true;
    while (!rcp->has_reset) {
        if (!rcp->bus.uart.data_ready) {
            ret = poll(&pfd, 1, 5000);
            FATAL_ON(ret < 0, 2, "%s poll: %m", __func__);
            WARN_ON(!ret, "RCP is not responding (no IND_RESET)");
        }
        rcp_rx(rcp);
    }
    rcp->bus.uart.init_phase = false;

    rcp_set_host_api(rcp, version_daemon_api);

    rcp_req_radio_list(rcp);
    while (!rcp->has_rf_list)
        rcp_rx(rcp);
}
