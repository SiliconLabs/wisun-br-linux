/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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

/* MAC API implementation */
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "common/log.h"
#include "common/os_types.h"
#include "common/named_values.h"
#include "common/parsers.h"
#include "common/pcapng.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "common/utils.h"
#include "common/ws_regdb.h"

#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_config.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/channel_list.h"
#include "stack/mac/mlme.h"
#include "stack/ws_management_api.h"
#include "stack/ws_bbr_api.h"

#include "version.h"
#include "wsbr.h"
#include "wsbr_mac.h"
#include "wsbr_fhss_net.h"
#include "wsbr_pcapng.h"
#include "timers.h"
#include "tun.h"
#include "dbus.h"
#include "commandline_values.h"

static void adjust_rcp_time_diff(struct wsbr_ctxt *ctxt, uint32_t rcp_time)
{
    struct timespec tp;
    int rcp_time_diff;

    // FIXME: explain hy and when this case happens
    if (!rcp_time)
        return;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    rcp_time_diff = (tp.tv_sec * 1000000 + tp.tv_nsec / 1000) - rcp_time;
    if (!ctxt->rcp_time_diff)
        ctxt->rcp_time_diff = rcp_time_diff;
    rcp_time_diff = rcp_time_diff * 0.10 + ctxt->rcp_time_diff * 0.9; // smooth adjustement
    ctxt->rcp_time_diff = rcp_time_diff;
}

static void print_rf_config(struct wsbr_ctxt *ctxt, char *out,
                            const struct phy_params *phy_params, const struct chan_params *chan_params,
                            uint32_t chan0_freq, uint32_t chan_spacing, uint16_t chan_count, uint8_t phy_mode_id)
{
    int i;

    *out = '\0';
    if (chan_params)
        sprintf(out + strlen(out), " %-2s", val_to_str(chan_params->reg_domain, valid_ws_domains, "??"));
    else
        sprintf(out + strlen(out), " ??");

    if (chan_params && chan_params->op_class)
        sprintf(out + strlen(out), "   %d", chan_params->op_class);
    else if (chan_params)
        sprintf(out + strlen(out), "   -");
    else
        sprintf(out + strlen(out), "   ?");

    if (chan_params && chan_params->chan_plan_id)
        sprintf(out + strlen(out), "  %3d", chan_params->chan_plan_id);
    else if (chan_params)
        sprintf(out + strlen(out), "   --");
    else
        sprintf(out + strlen(out), "   ??");

    sprintf(out + strlen(out), "   %2d", phy_mode_id);

    if (phy_params && phy_params->op_mode)
        sprintf(out + strlen(out), "   %-2x", phy_params->op_mode);
    else if (phy_params)
        sprintf(out + strlen(out), "   --");
    else
        sprintf(out + strlen(out), "   ??");

    if (phy_params && phy_params->modulation == MODULATION_OFDM) {
        sprintf(out + strlen(out), "   OFDM");
        sprintf(out + strlen(out), "   %1d", phy_params->ofdm_mcs);
        sprintf(out + strlen(out), "    %1d", phy_params->ofdm_option);
        sprintf(out + strlen(out), "   --");
    } else if (phy_params && phy_params->modulation == MODULATION_2FSK) {
        sprintf(out + strlen(out), "    FSK");
        sprintf(out + strlen(out), "  --");
        sprintf(out + strlen(out), "   --");
        sprintf(out + strlen(out), "  %3s", val_to_str(phy_params->fsk_modulation_index, valid_fsk_modulation_indexes, "??"));
    } else {
        sprintf(out + strlen(out), "     ??");
        sprintf(out + strlen(out), "  ??");
        sprintf(out + strlen(out), "   ??");
        sprintf(out + strlen(out), "   ??");
    }

    if (phy_params)
        sprintf(out + strlen(out), " %4dkbps", phy_params->datarate / 1000);
    else
        sprintf(out + strlen(out), "   ??    ");

    sprintf(out + strlen(out), " %4.1fMHz", (double)chan0_freq / 1000000);
    sprintf(out + strlen(out), " %4dkHz", chan_spacing / 1000);
    sprintf(out + strlen(out), "  %3d", chan_count);

    if (chan_params && chan_params->chan_allowed)
        sprintf(out + strlen(out), "  %s", chan_params->chan_allowed);
    else if (chan_params)
        sprintf(out + strlen(out), "  --");
    else
        sprintf(out + strlen(out), "  ??");

    if (chan_params) {
        for (i = 0; chan_params->valid_phy_modes[i]; i++)
            if (chan_params->valid_phy_modes[i] == phy_mode_id)
                break;
        if (!chan_params->valid_phy_modes[i])
            sprintf(out + strlen(out), " (non standard)");
    }
}


static void store_rf_config_list(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf)
{
    const struct chan_params *chan_params = ws_regdb_chan_params(ctxt->config.ws_domain, ctxt->config.ws_chan_plan_id, ctxt->config.ws_class);
    const struct phy_params *phy_params = ws_regdb_phy_params(ctxt->config.ws_phy_mode_id, ctxt->config.ws_mode);
    uint32_t chan0_freq;
    uint32_t chan_spacing;
    uint8_t rail_phy_mode_id;
    uint8_t phy_mode_id;
    uint16_t chan_count;
    bool is_submode;
    bool rf_cfg_found = false;
    int i, j = 0;

    memset(ctxt->phy_operating_modes, 0, ARRAY_SIZE(ctxt->phy_operating_modes));

    // MDR with custom domains are not yet supported
    if (!chan_params || !phy_params)
        return;

    while (spinel_remaining_size(buf)) {
        chan0_freq = spinel_pop_u32(buf);
        chan_spacing = spinel_pop_u32(buf);
        chan_count = spinel_pop_u16(buf);
        rail_phy_mode_id = spinel_pop_u8(buf);
        is_submode = spinel_pop_bool(buf);

        phy_mode_id = 0;
        for (i = 0; phy_params_table[i].phy_mode_id; i++)
            if (phy_params_table[i].rail_phy_mode_id == rail_phy_mode_id)
                phy_mode_id = phy_params_table[i].phy_mode_id;
        if (!phy_mode_id)
            break; // unknown rail_phy_mode_id

        if (phy_mode_id == phy_params->phy_mode_id
            && chan0_freq == chan_params->chan0_freq
            && chan_spacing == chan_params->chan_spacing
            && chan_count == chan_params->chan_count
            && !is_submode) {
            rf_cfg_found = true;
        } else if (rf_cfg_found && is_submode) {
            ctxt->phy_operating_modes[j++] = phy_mode_id;
        } else if (rf_cfg_found && !is_submode) {
            return;
        }
    }
}

static void print_rf_config_list(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf)
{
    uint32_t chan0_freq;
    uint32_t chan_spacing;
    uint8_t rail_phy_mode_id;
    uint16_t chan_count;
    bool phy_mode_found, chan_plan_found, is_submode;
    char tmp_buf[256][150]; // max: 256 lines of 150 characters. FIXME: 38kB is too much for a stack allocation
    int i, j, k = 0;

    INFO("dom  cla chan phy  mode modula mcs ofdm mod    data    chan    chan  #chans  chans");
    INFO("-ain -ss plan mode      -tion      opt. idx    rate    base    space        allowed");
    while (spinel_remaining_size(buf)) {
        BUG_ON(k >= ARRAY_SIZE(tmp_buf));
        chan0_freq = spinel_pop_u32(buf);
        chan_spacing = spinel_pop_u32(buf);
        chan_count = spinel_pop_u16(buf);
        rail_phy_mode_id = spinel_pop_u8(buf);
        is_submode = spinel_pop_u8(buf); // can only be used with mode switch
        // the loops below allow several entries to match
        phy_mode_found = false;
        chan_plan_found = false;

        if (is_submode)
            continue;
        for (i = 0; phy_params_table[i].phy_mode_id; i++) {
            if (phy_params_table[i].rail_phy_mode_id == rail_phy_mode_id) {
                phy_mode_found = true;
                for (j = 0; chan_params_table[j].chan0_freq; j++) {
                    if (chan_params_table[j].chan0_freq == chan0_freq &&
                        chan_params_table[j].chan_spacing == chan_spacing &&
                        chan_params_table[j].chan_count == chan_count) {
                        chan_plan_found = true;
                        print_rf_config(ctxt, tmp_buf[k++], &phy_params_table[i], &chan_params_table[j], chan0_freq, chan_spacing, chan_count, phy_params_table[i].phy_mode_id);
                    }
                }
                if (!chan_plan_found)
                    print_rf_config(ctxt, tmp_buf[k++], &phy_params_table[i], NULL, chan0_freq, chan_spacing, chan_count, phy_params_table[i].phy_mode_id);
            }
        }
        if (!phy_mode_found)
            print_rf_config(ctxt, tmp_buf[k++], NULL, NULL, chan0_freq, chan_spacing, chan_count, rail_phy_mode_id);
    }
    qsort(tmp_buf, k, sizeof(tmp_buf[0]), (int (*)(const void *, const void *))strcmp);
    for (i = 0; i < k; i++)
        INFO("%s", tmp_buf[i]);
}

static void handle_crc_error(struct wsbr_ctxt *ctxt, uint16_t crc, uint32_t frame_len, uint8_t header, uint8_t irq_err_counter)
{
    struct retransmission_frame *buffers = ctxt->os_ctxt->retransmission_buffers;
    int buffers_len = ARRAY_SIZE(ctxt->os_ctxt->retransmission_buffers);
    int extra_frame;
    int i;

    for (i = 0; i < buffers_len; i++) {
        if (buffers[i].crc == crc) {
            if (buffers[i].frame_len < frame_len) {
                extra_frame = (i + buffers_len - 1) % buffers_len;
                if (buffers[extra_frame].frame[0] != header) {
                    WARN("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): 1 packet lost, %d bytes recovered",
                         irq_err_counter, frame_len, header, crc, buffers[i].frame_len);
                } else {
                    DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d + %d bytes recovered",
                          irq_err_counter, frame_len, header, crc,
                          buffers[extra_frame].frame_len, buffers[i].frame_len);
                    write(ctxt->os_ctxt->data_fd, buffers[extra_frame].frame, buffers[extra_frame].frame_len);
                }
            } else {
                DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d bytes recovered",
                      irq_err_counter, frame_len, header, crc, buffers[i].frame_len);
            }
            write(ctxt->os_ctxt->data_fd, buffers[i].frame, buffers[i].frame_len);
            return;
        }
    }
    for (i = 0; i < buffers_len; i++) {
        if (buffers[i].frame[0] == header) {
            write(ctxt->os_ctxt->data_fd, buffers[i].frame, buffers[i].frame_len);
            if (buffers[i].frame_len < frame_len) {
                extra_frame = (i + 1) % buffers_len;
                DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d + %d bytes recovered (header match)",
                      irq_err_counter, frame_len, header, crc,
                      buffers[i].frame_len, buffers[extra_frame].frame_len);
                write(ctxt->os_ctxt->data_fd, buffers[extra_frame].frame, buffers[extra_frame].frame_len);
            } else {
                DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d bytes recovered (header match)",
                      irq_err_counter, frame_len, header, crc, buffers[i].frame_len);
            }
            return;
        }
    }
    WARN("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): one or several packets lost",
         irq_err_counter, frame_len, header, crc);
}

static void wsbr_spinel_is(struct wsbr_ctxt *ctxt, int prop, struct spinel_buffer *buf)
{
    switch (prop) {
    case SPINEL_PROP_WS_DEVICE_TABLE: {
        struct mlme_device_descriptor data;
        mlme_get_conf_t req = {
            .attr = macDeviceTable,
            .value_pointer = &data,
            .value_size = sizeof(data),
        };

        req.attr_index    = spinel_pop_uint(buf);
        data.PANId        = spinel_pop_u16(buf);
        data.ShortAddress = spinel_pop_u16(buf);
        spinel_pop_fixed_u8_array(buf, data.ExtAddress, 8);
        data.FrameCounter = spinel_pop_u32(buf);
        data.Exempt       = spinel_pop_bool(buf);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_FRAME_COUNTER: {
        uint32_t data;
        mlme_get_conf_t req = {
            .attr = macFrameCounter,
            .value_pointer = &data,
            .value_size = sizeof(data),
        };

        req.attr_index = spinel_pop_uint(buf);
        data           = spinel_pop_u32(buf);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_CCA_THRESHOLD: {
        mlme_get_conf_t req = {
            .attr = macCCAThreshold,
        };

        req.value_size = spinel_pop_data_ptr(buf, (uint8_t **)&req.value_pointer);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_GET, &req);
        break;
    }
    case SPINEL_PROP_WS_MLME_IND: {
        int id;
        uint8_t *data;

        id = spinel_pop_uint(buf);
        spinel_pop_data_ptr(buf, &data);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        ctxt->mac_api.mlme_ind_cb(&ctxt->mac_api, id, data);
        break;
    }
    case SPINEL_PROP_WS_MCPS_DROP: {
        struct mcps_purge_conf req = { };

        req.msduHandle = spinel_pop_u8(buf);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        ctxt->mac_api.purge_conf_cb(&ctxt->mac_api, &req);
        break;
    }
    case SPINEL_PROP_STREAM_STATUS: {
        mcps_data_conf_t req = { };
        mcps_data_conf_payload_t conf_req = { };

        req.status      = spinel_pop_u8(buf);
        req.msduHandle  = spinel_pop_u8(buf);
        req.timestamp   = spinel_pop_u32(buf);
        req.cca_retries = spinel_pop_u8(buf);
        req.tx_retries  = spinel_pop_u8(buf);
        conf_req.headerIeListLength  = spinel_pop_data_ptr(buf, &conf_req.headerIeList);
        conf_req.payloadIeListLength = spinel_pop_data_ptr(buf, &conf_req.payloadIeList);
        conf_req.payloadLength       = spinel_pop_data_ptr(buf, &conf_req.payloadPtr);
        if (spinel_remaining_size(buf)) {
            spinel_pop_raw(buf, (uint8_t *)req.retry_per_rate, sizeof(mcps_data_retry_t) * MAX_PHY_MODE_ID_PER_FRAME);
            req.success_phy_mode_id = spinel_pop_u8(buf);
        }
        if (!spinel_prop_is_valid(buf, prop))
            return;
        adjust_rcp_time_diff(ctxt, req.timestamp);
        // Note: we don't support data_conf_cb()
        ctxt->mac_api.data_conf_ext_cb(&ctxt->mac_api, &req, &conf_req);
        break;
    }
    case SPINEL_PROP_STREAM_RAW: {
        mcps_data_ind_t req = { };
        mcps_data_ie_list_t ie_ext = { };

        req.msduLength             = spinel_pop_data_ptr(buf, &req.msdu_ptr);
        req.SrcAddrMode            = spinel_pop_u8(buf);
        req.SrcPANId               = spinel_pop_u16(buf);
        spinel_pop_fixed_u8_array(buf, req.SrcAddr, 8);
        req.DstAddrMode            = spinel_pop_u8(buf);
        req.DstPANId               = spinel_pop_u16(buf);
        spinel_pop_fixed_u8_array(buf, req.DstAddr, 8);
        req.mpduLinkQuality        = spinel_pop_u8(buf);
        req.signal_dbm             = spinel_pop_i8(buf);
        req.timestamp              = spinel_pop_u32(buf);
        req.DSN_suppressed         = spinel_pop_bool(buf);
        req.DSN                    = spinel_pop_u8(buf);
        req.Key.SecurityLevel      = spinel_pop_u8(buf);
        req.Key.KeyIdMode          = spinel_pop_u8(buf);
        req.Key.KeyIndex           = spinel_pop_u8(buf);
        spinel_pop_fixed_u8_array(buf, req.Key.Keysource, 8);
        ie_ext.headerIeListLength  = spinel_pop_data_ptr(buf, &ie_ext.headerIeList);
        ie_ext.payloadIeListLength = spinel_pop_data_ptr(buf, &ie_ext.payloadIeList);
        if (spinel_remaining_size(buf)) {
            req.TxAckReq           = spinel_pop_bool(buf);
            req.PendingBit         = spinel_pop_bool(buf);
            req.PanIdSuppressed    = spinel_pop_bool(buf);
            if (ctxt->config.pcap_file[0])
                wsbr_pcapng_write_frame(ctxt, &req, &ie_ext);
        }
        if (!spinel_prop_is_valid(buf, prop))
            return;
        adjust_rcp_time_diff(ctxt, req.timestamp);
        // Note: we don't support data_ind_cb()
        ctxt->mac_api.data_ind_ext_cb(&ctxt->mac_api, &req, &ie_ext);
        break;
    }
    case SPINEL_PROP_HWADDR: {
        spinel_pop_fixed_u8_array(buf, ctxt->hw_mac, 8);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        ctxt->rcp_init_state |= RCP_HAS_HWADDR;
        break;
    }
    case SPINEL_PROP_WS_RX_SENSITIVITY: {
        int val = spinel_pop_i16(buf);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        // from -174dBm to + 80dBm, so add + 174 to real sensitivity
        ws_device_min_sens_set(ctxt->rcp_if_id, val + 174);
        break;
    }
    case SPINEL_PROP_WS_RF_CONFIGURATION_LIST: {
        store_rf_config_list(ctxt, buf);
        spinel_reset(buf);
        spinel_pop_u8(buf); // header
        spinel_pop_uint(buf); // cmd == SPINEL_CMD_PROP_IS
        spinel_pop_uint(buf); // prop == SPINEL_PROP_WS_RF_CONFIGURATION_LIST
        if (ctxt->config.list_rf_configs)
            print_rf_config_list(ctxt, buf);
        ctxt->rcp_init_state |= RCP_HAS_RF_CONFIG_LIST;
        break;
    }
    // FIXME: for now, only SPINEL_PROP_WS_START return a SPINEL_PROP_LAST_STATUS
    // SPINEL_PROP_WS_RF_CONFIGURATION should also return a
    // SPINEL_PROP_LAST_STATUS, but it is not the case.
    case SPINEL_PROP_LAST_STATUS: {
        ctxt->mac_api.mlme_conf_cb(&ctxt->mac_api, MLME_START, NULL);
        break;
    }
    case SPINEL_PROP_WS_RF_CONFIGURATION: {
        int val = spinel_pop_uint(buf);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        if (val)
            FATAL(2, "RF configuration not supported by the RCP");
        break;
    }
    case SPINEL_PROP_WS_RCP_CRC_ERR: {
        uint16_t crc            = spinel_pop_u16(buf);
        uint32_t frame_len      = spinel_pop_u32(buf);
        uint8_t header          = spinel_pop_u8(buf);
        uint8_t irq_err_counter = spinel_pop_u8(buf);
        if (!spinel_prop_is_valid(buf, prop))
            return;
        handle_crc_error(ctxt, crc, frame_len, header, irq_err_counter);
        break;
    }
    default:
        WARN("not implemented");
        break;
    }
}

static bool wsbr_init_state_is_valid(struct wsbr_ctxt *ctxt, int prop)
{
    if (!(ctxt->rcp_init_state & RCP_HAS_RESET))
        return false;
    if (!(ctxt->rcp_init_state & RCP_HAS_HWADDR))
        return prop == SPINEL_PROP_HWADDR;
    if (!fw_api_older_than(ctxt, 0, 11, 0) && !(ctxt->rcp_init_state & RCP_HAS_RF_CONFIG_LIST))
        return prop == SPINEL_PROP_WS_RF_CONFIGURATION_LIST;
    return true;
}

void rcp_rx(struct wsbr_ctxt *ctxt)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(4096);
    int cmd, prop;

    buf->len = ctxt->rcp_rx(ctxt->os_ctxt, buf->frame, buf->len);
    if (!buf->len)
        return;
    spinel_trace(buf, "hif rx: ");
    spinel_pop_u8(buf); /* packet header */
    cmd = spinel_pop_uint(buf);

    switch (cmd) {
    case SPINEL_CMD_NOOP:
        /* empty */
        break;
    case SPINEL_CMD_PROP_IS:
        prop = spinel_pop_uint(buf);
        if (!wsbr_init_state_is_valid(ctxt, prop)) {
            WARN("ignoring unexpected boot-up sequence");
            return;
        }
        wsbr_spinel_is(ctxt, prop, buf);
        break;
    case SPINEL_CMD_RESET: {
        const char *version_fw_str;

        if (spinel_remaining_size(buf) < 16)
            FATAL(1, "unknown RESET format (bad firmware?)");
        // FIXME: CMD_RESET should reply with SPINEL_PROP_LAST_STATUS ==
        // STATUS_RESET_SOFTWARE
        ctxt->rcp_version_api = spinel_pop_u32(buf);
        ctxt->rcp_version_fw = spinel_pop_u32(buf);
        version_fw_str = spinel_pop_str(buf);
        spinel_pop_bool(buf); // is_hw_reset is no more used
        ctxt->storage_sizes.device_description_table_size = spinel_pop_u8(buf);
        if (ctxt->storage_sizes.device_description_table_size <= MAX_NEIGH_TEMPORARY_EAPOL_SIZE
                        + WS_SMALL_TEMPORARY_NEIGHBOUR_ENTRIES)
            FATAL(1, "RCP size of \"neighbor_timings\" table is too small (should be > %d)", MAX_NEIGH_TEMPORARY_EAPOL_SIZE
                        + WS_SMALL_TEMPORARY_NEIGHBOUR_ENTRIES);
        ctxt->storage_sizes.device_description_table_size -= MAX_NEIGH_TEMPORARY_EAPOL_SIZE;
        ctxt->storage_sizes.key_description_table_size = spinel_pop_u8(buf);
        ctxt->storage_sizes.key_lookup_size = spinel_pop_u8(buf);
        ctxt->storage_sizes.key_usage_size = spinel_pop_u8(buf);
        wsbr_handle_reset(ctxt, version_fw_str);
        break;
    }
    case SPINEL_CMD_REPLAY_TIMERS:
        wsbr_spinel_replay_timers(buf);
        break;
    case SPINEL_CMD_REPLAY_INTERFACE:
        wsbr_spinel_replay_interface(buf);
        break;
    default:
        WARN("%s: not implemented: %02x", __func__, cmd);
        return;
    }
}

void rcp_tx(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf)
{
    spinel_trace(buf, "hif tx: ");
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

uint8_t wsbr_get_spinel_hdr(struct wsbr_ctxt *ctxt)
{
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

void spinel_push_hdr_set_prop(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop)
{
    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(buf, SPINEL_CMD_PROP_SET);
    spinel_push_uint(buf, prop);
}

void spinel_push_hdr_get_prop(struct wsbr_ctxt *ctxt, struct spinel_buffer *buf, unsigned int prop)
{
    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(buf, SPINEL_CMD_PROP_GET);
    spinel_push_uint(buf, prop);
}

void wsbr_spinel_set_bool(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(bool));

    BUG_ON(data_len != sizeof(bool));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_bool(buf, *(bool *)data);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_u8(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(uint8_t));

    BUG_ON(data_len != sizeof(uint8_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u8(buf, *(uint8_t *)data);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_u16(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(uint16_t));

    BUG_ON(data_len != sizeof(uint16_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u16(buf, *(uint16_t *)data);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_u32(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + sizeof(uint32_t));

    BUG_ON(data_len != sizeof(uint32_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u32(buf, *(uint32_t *)data);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_eui64(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 8);

    BUG_ON(data_len != 8);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_fixed_u8_array(buf, data, 8);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_cca_threshold_start(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 4);
    const uint8_t *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_CCA_THRESHOLD_START);
    BUG_ON(data_len != 4);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_fixed_u8_array(buf, req, 4);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_rf_configuration(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 27);
    const struct phy_rf_channel_configuration *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_RF_CONFIGURATION);
    BUG_ON(data_len != sizeof(struct phy_rf_channel_configuration));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u32(buf, req->channel_0_center_frequency);
    spinel_push_u32(buf, req->channel_spacing);
    spinel_push_u32(buf, req->datarate);
    spinel_push_u16(buf, req->number_of_channels);
    spinel_push_u8(buf,  req->modulation);
    spinel_push_u8(buf,  req->modulation_index);
    if (!fw_api_older_than(ctxt, 0, 6, 0)) {
        spinel_push_bool(buf, req->fec);
        spinel_push_uint(buf, req->ofdm_option);
        spinel_push_uint(buf, req->ofdm_mcs);
    }
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_request_restart(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 16);
    const struct mlme_request_restart_config *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_REQUEST_RESTART);
    BUG_ON(data_len != sizeof(struct mlme_request_restart_config));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u8(buf,  req->cca_failure_restart_max);
    spinel_push_u8(buf,  req->tx_failure_restart_max);
    spinel_push_u16(buf, req->blacklist_min_ms);
    spinel_push_u16(buf, req->blacklist_max_ms);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_mac_filter_start(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 8);
    const mlme_request_mac_filter_start_t *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_START);
    BUG_ON(data_len != sizeof(mlme_request_mac_filter_start_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_u16(buf, req->lqi_m);
    spinel_push_u16(buf, req->lqi_add);
    spinel_push_u16(buf, req->dbm_m);
    spinel_push_u16(buf, req->dbm_add);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_mac_filter_clear(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_CLEAR);
    BUG_ON(data_len != 0);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_mac_filter_add_long(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 16);
    const mlme_request_mac_filter_add_long_t *req = data;

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_ADD_LONG);
    BUG_ON(data_len != sizeof(mlme_request_mac_filter_add_long_t));
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    spinel_push_fixed_u8_array(buf, req->mac64, 8);
    spinel_push_u16(buf, req->lqi_m);
    spinel_push_u16(buf, req->lqi_add);
    spinel_push_u16(buf, req->dbm_m);
    spinel_push_u16(buf, req->dbm_add);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_mac_filter_stop(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    BUG_ON(prop != SPINEL_PROP_WS_MAC_FILTER_STOP);
    BUG_ON(data_len != 0);
    spinel_push_hdr_set_prop(ctxt, buf, prop);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_device_table(struct wsbr_ctxt *ctxt, int entry_idx, const mlme_device_descriptor_t *req)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 20);

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_DEVICE_TABLE);
    spinel_push_u8(buf,   entry_idx);
    spinel_push_u16(buf,  req->PANId);
    spinel_push_u16(buf,  req->ShortAddress);
    spinel_push_fixed_u8_array(buf, req->ExtAddress, 8);
    spinel_push_u32(buf,  req->FrameCounter);
    spinel_push_bool(buf, req->Exempt);
    rcp_tx(ctxt, buf);
}

static void wsbr_spinel_set_key_table(struct wsbr_ctxt *ctxt, int entry_idx,
                                      const mlme_key_descriptor_entry_t *req)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 32);
    int lookup_len;

    BUG_ON(sizeof(req->Key) != 16);
    BUG_ON(req->KeyIdLookupListEntries > 1);
    BUG_ON(req->KeyUsageListEntries);
    BUG_ON(req->KeyDeviceListEntries);
    if (!req->KeyIdLookupListEntries)
        lookup_len = 0;
    else if (req->KeyIdLookupList->LookupDataSize)
        lookup_len = 9;
    else
        lookup_len = 5;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_KEY_TABLE);
    spinel_push_u8(buf, entry_idx);
    spinel_push_fixed_u8_array(buf, req->Key, 16);
    spinel_push_data(buf, req->KeyIdLookupList->LookupData, lookup_len);
    rcp_tx(ctxt, buf);
    dbus_emit_keys_change(ctxt);
}

static void wsbr_spinel_set_frame_counter(struct wsbr_ctxt *ctxt, int counter, uint32_t val)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 7);

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FRAME_COUNTER);
    spinel_push_uint(buf, counter);
    spinel_push_u32(buf, val);
    rcp_tx(ctxt, buf);
}

void wsbr_rcp_reset(struct wsbr_ctxt *ctxt)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3);

    spinel_push_u8(buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(buf, SPINEL_CMD_RESET);
    rcp_tx(ctxt, buf);
}

void wsbr_rcp_get_hw_addr(struct wsbr_ctxt *ctxt)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 3);

    spinel_push_hdr_get_prop(ctxt, buf, SPINEL_PROP_HWADDR);
    spinel_push_uint(buf, 0);
    rcp_tx(ctxt, buf);
}

void wsbr_rcp_get_rf_config_list(struct wsbr_ctxt *ctxt)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    spinel_push_hdr_get_prop(ctxt, buf, SPINEL_PROP_WS_RF_CONFIGURATION_LIST);
    rcp_tx(ctxt, buf);
}

static const struct {
    mlme_attr_e attr;
    void (*prop_set)(struct wsbr_ctxt *ctxt, unsigned int prop, const void *data, int data_len);
    unsigned int prop;
} mlme_prop_cstr[] = {
    { macRxOnWhenIdle,                 wsbr_spinel_set_bool,                  SPINEL_PROP_WS_RX_ON_WHEN_IDLE,                  },
    { macSecurityEnabled,              wsbr_spinel_set_bool,                  SPINEL_PROP_WS_SECURITY_ENABLED,                 },
    { macAcceptByPassUnknowDevice,     wsbr_spinel_set_bool,                  SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE,      },
    { macEdfeForceStop,                wsbr_spinel_set_bool,                  SPINEL_PROP_WS_EDFE_FORCE_STOP,                  },
    { phyCurrentChannel,               wsbr_spinel_set_u8,                    SPINEL_PROP_PHY_CHAN,                            },
    { macAutoRequestKeyIdMode,         wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_ID_MODE,         },
    { macAutoRequestKeyIndex,          wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_KEY_INDEX,           },
    { macAutoRequestSecurityLevel,     wsbr_spinel_set_u8,                    SPINEL_PROP_WS_AUTO_REQUEST_SECURITY_LEVEL,      },
    { macMaxFrameRetries,              wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_FRAME_RETRIES,                },
    { macTXPower,                      wsbr_spinel_set_u8,                    SPINEL_PROP_PHY_TX_POWER,                        },
    { macMaxCSMABackoffs,              wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_CSMA_BACKOFFS,                },
    { macMinBE,                        wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MIN_BE,                           },
    { macMaxBE,                        wsbr_spinel_set_u8,                    SPINEL_PROP_WS_MAX_BE,                           },
    { macCCAThreshold,                 wsbr_spinel_set_u8,                    SPINEL_PROP_WS_CCA_THRESHOLD,                    },
    { macPANId,                        wsbr_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_PANID,                      },
    { macCoordShortAddress,            wsbr_spinel_set_u16,                   SPINEL_PROP_WS_COORD_SHORT_ADDRESS,              },
    { macShortAddress,                 wsbr_spinel_set_u16,                   SPINEL_PROP_MAC_15_4_SADDR,                      },
    { macAckWaitDuration,              wsbr_spinel_set_u16,                   SPINEL_PROP_WS_ACK_WAIT_DURATION,                },
    { mac802_15_4Mode,                 wsbr_spinel_set_u32,                   SPINEL_PROP_WS_15_4_MODE,                        },
    { macRegionalRegulation,           wsbr_spinel_set_u32,                   SPINEL_PROP_WS_REGIONAL_REGULATION,              },
    { macAsyncFragmentation,           wsbr_spinel_set_u32,                   SPINEL_PROP_WS_ASYNC_FRAGMENTATION,              },
    { macAutoRequestKeySource,         wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_AUTO_REQUEST_KEY_SOURCE,          },
    { macCoordExtendedAddress,         wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS,           },
    { macDefaultKeySource,             wsbr_spinel_set_eui64,                 SPINEL_PROP_WS_DEFAULT_KEY_SOURCE,               },
    { macCCAThresholdStart,            wsbr_spinel_set_cca_threshold_start,   SPINEL_PROP_WS_CCA_THRESHOLD_START,              },
    { macRfConfiguration,              wsbr_spinel_set_rf_configuration,      SPINEL_PROP_WS_RF_CONFIGURATION,                 },
    { macRequestRestart,               wsbr_spinel_set_request_restart,       SPINEL_PROP_WS_REQUEST_RESTART,                  },
    { macFilterStart,                  wsbr_spinel_set_mac_filter_start,      SPINEL_PROP_WS_MAC_FILTER_START,                 },
    { macFilterClear,                  wsbr_spinel_set_mac_filter_clear,      SPINEL_PROP_WS_MAC_FILTER_CLEAR,                 },
    { macFilterAddLong,                wsbr_spinel_set_mac_filter_add_long,   SPINEL_PROP_WS_MAC_FILTER_ADD_LONG,              },
    { macFilterStop,                   wsbr_spinel_set_mac_filter_stop,       SPINEL_PROP_WS_MAC_FILTER_STOP,                  },
    { macRxSensitivity,                NULL /* get only */,                   SPINEL_PROP_WS_RX_SENSITIVITY                    },
    { macDeviceTable,                  NULL /* Special */,                    SPINEL_PROP_WS_DEVICE_TABLE,                     },
    { macKeyTable,                     NULL /* Special */,                    SPINEL_PROP_WS_KEY_TABLE,                        },
    { macFrameCounter,                 NULL /* Special */,                    SPINEL_PROP_WS_FRAME_COUNTER,                    },
    { }
};

static void wsbr_mlme_set(const struct mac_api *api, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    const mlme_set_t *req = data;
    int i;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    // SPINEL_CMD_PROP_SET
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (req->attr == mlme_prop_cstr[i].attr)
            break;
    if (mlme_prop_cstr[i].prop_set) {
        // Normally, req->attr_index == 0, but nanostack is not rigorous on that
        mlme_prop_cstr[i].prop_set(ctxt, mlme_prop_cstr[i].prop, req->value_pointer, req->value_size);
    } else if (req->attr == macDeviceTable) {
        BUG_ON(req->value_size != sizeof(mlme_device_descriptor_t));
        wsbr_spinel_set_device_table(ctxt, req->attr_index, req->value_pointer);
    } else if (req->attr == macKeyTable) {
        BUG_ON(req->value_size != sizeof(mlme_key_descriptor_entry_t));
        wsbr_spinel_set_key_table(ctxt, req->attr_index, req->value_pointer);
    } else if (req->attr == macFrameCounter) {
        BUG_ON(req->value_size != sizeof(uint32_t));
        wsbr_spinel_set_frame_counter(ctxt, req->attr_index, *(uint32_t *)req->value_pointer);
    } else {
        WARN("unknown message: %02x", req->attr);
    }
}

static void wsbr_mlme_get(const struct mac_api *api, const void *data)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 3);
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    const mlme_get_t *req = data;
    int i, index = 0;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    for (i = 0; mlme_prop_cstr[i].prop; i++)
        if (req->attr == mlme_prop_cstr[i].attr)
            break;
    if (mlme_prop_cstr[i].prop == SPINEL_PROP_WS_DEVICE_TABLE ||
        mlme_prop_cstr[i].prop == SPINEL_PROP_WS_KEY_TABLE ||
        mlme_prop_cstr[i].prop == SPINEL_PROP_WS_FRAME_COUNTER)
        index = req->attr_index;

    spinel_push_hdr_get_prop(ctxt, buf, mlme_prop_cstr[i].prop);
    spinel_push_uint(buf, index);
    rcp_tx(ctxt, buf);
}

static void wsbr_mlme_start(const struct mac_api *api, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 20);
    const mlme_start_t *req = data;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    // FIXME: consider SPINEL_PROP_PHY_ENABLED
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_START);
    spinel_push_u16(buf,  req->PANId);
    spinel_push_u8(buf,   req->LogicalChannel);
    spinel_push_u8(buf,   req->ChannelPage);
    spinel_push_u32(buf,  req->StartTime);
    spinel_push_u8(buf,   req->BeaconOrder);
    spinel_push_u8(buf,   req->SuperframeOrder);
    spinel_push_bool(buf, req->PANCoordinator);
    rcp_tx(ctxt, buf);
}

static void wsbr_mlme_reset(const struct mac_api *api, const void *data)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 1 + 4);
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    const mlme_reset_t *req = data;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    // SPINEL_CMD_RESET or SPINEL_PROP_PHY_ENABLED
    // It seems that SPINEL_CMD_RESET is too wide. It reset the whole device
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_RESET);
    spinel_push_bool(buf, req->SetDefaultPIB);
    spinel_push_u32(buf, version_daemon_api);
    rcp_tx(ctxt, buf);
}

int8_t wsbr_mlme(const struct mac_api *api, mlme_primitive_e id, const void *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    static const struct {
        uint32_t    val;
        void (*fn)(const struct mac_api *, const void *);
    } table[] = {
        { MLME_GET,           wsbr_mlme_get },
        { MLME_SET,           wsbr_mlme_set },
        { MLME_START,         wsbr_mlme_start },
        { MLME_RESET,         wsbr_mlme_reset },
        // Never used
        { MLME_SCAN,          NULL },
        { MLME_POLL,          NULL }, // Only used with Thread?
        { MLME_ASSOCIATE,     NULL },
        { MLME_DISASSOCIATE,  NULL },
        { MLME_RX_ENABLE,     NULL },
        { MLME_SYNC,          NULL },
        { MLME_GTS,           NULL },
        // These ones only make sense with mlme_ind_cb()
        { MLME_BEACON_NOTIFY, NULL },
        { MLME_ORPHAN,        NULL },
        { MLME_COMM_STATUS,   NULL },
        { MLME_SYNC_LOSS,     NULL },
        { -1, },
    };
    int i;

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    for (i = 0; table[i].val != -1; i++)
        if (id == table[i].val)
            break;
    if (!table[i].fn)
        WARN("Try to reach unexpected API: id");
    else
        table[i].fn(api, data);
    return 0;
}

void wsbr_mcps_req_ext(const struct mac_api *api,
                       const struct mcps_data_req *data,
                       const struct mcps_data_req_ie_list *ie_ext,
                       const struct channel_list *async_channel_list,
                       mac_data_priority_e priority, uint8_t phy_id)
{
    const struct channel_list default_chan_list = {
        .channel_page = CHANNEL_PAGE_UNDEFINED,
    };
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 75 + MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE + 3);
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    int total, i;

    BUG_ON(ctxt != &g_ctxt);
    BUG_ON(data->TxAckReq && async_channel_list);
    BUG_ON(!ie_ext);
    if (!async_channel_list)
        async_channel_list = &default_chan_list;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_STREAM_RAW);
    spinel_push_data(buf, data->msdu, data->msduLength);
    spinel_push_u8(buf,   data->SrcAddrMode);
    spinel_push_u8(buf,   data->DstAddrMode);
    spinel_push_u16(buf,  data->DstPANId);
    spinel_push_fixed_u8_array(buf, data->DstAddr, 8);
    spinel_push_u8(buf,   data->msduHandle);
    spinel_push_bool(buf, data->TxAckReq);
    spinel_push_bool(buf, data->InDirectTx);
    spinel_push_bool(buf, data->PendingBit);
    spinel_push_bool(buf, data->SeqNumSuppressed);
    spinel_push_bool(buf, data->PanIdSuppressed);
    spinel_push_bool(buf, data->ExtendedFrameExchange);
    spinel_push_u8(buf,   data->Key.SecurityLevel);
    spinel_push_u8(buf,   data->Key.KeyIdMode);
    spinel_push_u8(buf,   data->Key.KeyIndex);
    spinel_push_fixed_u8_array(buf, data->Key.Keysource, 8);
    spinel_push_u16(buf,  priority);
    spinel_push_uint(buf, async_channel_list->channel_page);
    spinel_push_fixed_u8_array(buf, async_channel_list->channel_mask, 32);

    total = 0;
    for (i = 0; i < ie_ext->payloadIovLength; i++)
        total += ie_ext->payloadIeVectorList[i].iovLen;
    spinel_push_u16(buf, total);
    for (i = 0; i < ie_ext->payloadIovLength; i++)
        spinel_push_raw(buf, ie_ext->payloadIeVectorList[i].ieBase,
                        ie_ext->payloadIeVectorList[i].iovLen);

    total = 0;
    for (i = 0; i < ie_ext->headerIovLength; i++)
        total += ie_ext->headerIeVectorList[i].iovLen;
    spinel_push_u16(buf, total);
    for (i = 0; i < ie_ext->headerIovLength; i++)
        spinel_push_raw(buf, ie_ext->headerIeVectorList[i].ieBase,
                        ie_ext->headerIeVectorList[i].iovLen);
    if (!fw_api_older_than(ctxt, 0, 7, 0))
        spinel_push_u16(buf, async_channel_list->next_channel_number);
    if (!fw_api_older_than(ctxt, 0, 12,0))
        spinel_push_u8(buf, phy_id);

    rcp_tx(ctxt, buf);
}

void wsbr_mcps_req(const struct mac_api *api,
                   const struct mcps_data_req *data)
{
    return wsbr_mcps_req_ext(api, data, NULL, NULL, MAC_DATA_NORMAL_PRIORITY, 0);
}

uint8_t wsbr_mcps_purge(const struct mac_api *api,
                        const struct mcps_purge *data)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 1);
    struct mcps_purge_conf conf = {
        .msduHandle = data->msduHandle,
    };

    BUG_ON(!api);
    BUG_ON(ctxt != &g_ctxt);
    if (!fw_api_older_than(ctxt, 0, 4, 0)) {
        spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_MCPS_DROP);
        spinel_push_u8(buf, data->msduHandle);
        rcp_tx(ctxt, buf);
    } else {
        api->purge_conf_cb(api, &conf);
    }
    return 0;
}

int8_t wsbr_mac_addr_set(const struct mac_api *api, const uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);
    BUG_ON(ctxt != &g_ctxt);

    if (memcmp(ctxt->dynamic_mac, mac64, 8))
        WARN("%s: Not implemented", __func__);

    memcpy(ctxt->dynamic_mac, mac64, 8);
    return 0;
}

int8_t wsbr_mac_addr_get(const struct mac_api *api,
                     mac_extended_address_type_e type, uint8_t *mac64)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!mac64);
    BUG_ON(ctxt != &g_ctxt);

    switch (type) {
    case MAC_EXTENDED_READ_ONLY:
        memcpy(mac64, ctxt->hw_mac, 8);
        return 0;
    case MAC_EXTENDED_DYNAMIC:
        memcpy(mac64, ctxt->dynamic_mac, 8);
        return 0;
    default:
        BUG("Unknown address_type: %d", type);
    }
}

int8_t wsbr_mac_storage_sizes_get(const struct mac_api *api,
                                  struct mac_description_storage_size *buffer)
{
    struct wsbr_ctxt *ctxt = container_of(api, struct wsbr_ctxt, mac_api);

    BUG_ON(!api);
    BUG_ON(!buffer);
    BUG_ON(ctxt != &g_ctxt);

    memcpy(buffer, &ctxt->storage_sizes, sizeof(struct mac_description_storage_size));
    return 0;
}

int8_t wsbr_mac_mcps_ext_init(struct mac_api *api,
                              mcps_data_indication_ext *data_ind_cb,
                              mcps_data_confirm_ext *data_cnf_cb,
                              mcps_ack_data_req_ext *ack_data_req_cb)
{
    BUG_ON(!api);

    api->data_conf_ext_cb = data_cnf_cb;
    api->data_ind_ext_cb = data_ind_cb;
    api->enhanced_ack_data_req_cb = ack_data_req_cb;
    return 0;
}

int8_t wsbr_mac_edfe_ext_init(struct mac_api *api,
                              mcps_edfe_handler *edfe_ind_cb)
{
    BUG_ON(!api);

    api->edfe_ind_cb = edfe_ind_cb;
    return 0;
}

int8_t wsbr_mac_init(struct mac_api *api,
                     mcps_data_confirm *data_conf_cb,
                     mcps_data_indication *data_ind_cb,
                     mcps_purge_confirm *purge_conf_cb,
                     mlme_confirm *mlme_conf_cb,
                     mlme_indication *mlme_ind_cb,
                     int8_t parent_id)
{
    BUG_ON(!api);

    api->data_conf_cb = data_conf_cb;
    api->data_ind_cb = data_ind_cb;
    api->purge_conf_cb = purge_conf_cb;
    api->mlme_conf_cb = mlme_conf_cb;
    api->mlme_ind_cb = mlme_ind_cb;
    api->parent_id = parent_id;
    return 0;
}
