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
#include "stack/mac/fhss_ws_extension.h"
#include "stack/mac/platform/arm_hal_phy.h"

#include "common/version.h"
#include "common/iobuf.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"

#include "wsbr_mac.h"
#include "wsbr.h"
#include "rcp_api.h"

static void rcp_set_bool(unsigned int prop, bool val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, prop);
    spinel_push_bool(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_u8(unsigned int prop, uint8_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, prop);
    spinel_push_u8(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_u16(unsigned int prop, uint16_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, prop);
    spinel_push_u16(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_u32(unsigned int prop, uint32_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, prop);
    spinel_push_u32(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_eui64(unsigned int prop, const uint8_t val[8])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, prop);
    spinel_push_fixed_u8_array(&buf, val, 8);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}


void rcp_noop()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_u8(&buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(&buf, SPINEL_CMD_NOOP);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_reset()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_u8(&buf, wsbr_get_spinel_hdr(ctxt));
    spinel_push_uint(&buf, SPINEL_CMD_RESET);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_allocate_fhss(const struct fhss_ws_configuration *timing_info)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_CREATE);
    spinel_push_u8(&buf, timing_info->ws_uc_channel_function);
    spinel_push_u8(&buf, timing_info->ws_bc_channel_function);
    spinel_push_u16(&buf, timing_info->bsi);
    spinel_push_u8(&buf, timing_info->fhss_uc_dwell_interval);
    spinel_push_u32(&buf, timing_info->fhss_broadcast_interval);
    spinel_push_u8(&buf, timing_info->fhss_bc_dwell_interval);
    spinel_push_u8(&buf, timing_info->unicast_fixed_channel);
    spinel_push_u8(&buf, timing_info->broadcast_fixed_channel);
    spinel_push_fixed_u8_array(&buf, timing_info->domain_channel_mask, 32);
    spinel_push_fixed_u8_array(&buf, timing_info->unicast_channel_mask, 32);
    spinel_push_u16(&buf, timing_info->channel_mask_size);
    spinel_push_u8(&buf, timing_info->config_parameters.number_of_channel_retries);
    if (!version_older_than(ctxt->rcp_version_api, 0, 12, 0))
        spinel_push_fixed_u8_array(&buf, timing_info->broadcast_channel_mask, 32);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_register_fhss()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_REGISTER);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_unregister_fhss()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_UNREGISTER);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_release_fhss()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_DELETE);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_get_rx_sensitivity(void)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_get_prop(ctxt, &buf, SPINEL_PROP_WS_RX_SENSITIVITY);
    spinel_push_uint(&buf, 0);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_rf_config(const struct phy_rf_channel_configuration *config)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_RF_CONFIGURATION);
    spinel_push_u32(&buf, config->channel_0_center_frequency);
    spinel_push_u32(&buf, config->channel_spacing);
    spinel_push_u32(&buf, config->datarate);
    spinel_push_u16(&buf, config->number_of_channels);
    spinel_push_u8(&buf,  config->modulation);
    spinel_push_u8(&buf,  config->modulation_index);
    if (!version_older_than(ctxt->rcp_version_api, 0, 6, 0)) {
        spinel_push_bool(&buf, config->fec);
        spinel_push_uint(&buf, config->ofdm_option);
        spinel_push_uint(&buf, config->ofdm_mcs);
    }
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}


void rcp_set_802154_mode(phy_802_15_4_mode_e val)
{
    rcp_set_u32(SPINEL_PROP_WS_15_4_MODE, val);
}

void rcp_set_ack_wait_duration(uint16_t val)
{
    rcp_set_u16(SPINEL_PROP_WS_ACK_WAIT_DURATION, val);
}

void rcp_set_cca_threshold(uint8_t number_of_channels, uint8_t default_dbm,
                           uint8_t high_limit, uint8_t low_limit)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_CCA_THRESHOLD_START);
    spinel_push_u8(&buf, number_of_channels);
    spinel_push_u8(&buf, default_dbm);
    spinel_push_u8(&buf, high_limit);
    spinel_push_u8(&buf, low_limit);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_max_rf_retry(uint8_t max_cca_failure, uint8_t max_tx_failure,
                          uint16_t blacklist_min_ms, uint16_t blacklist_max_ms)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_REQUEST_RESTART);
    spinel_push_u8(&buf, max_cca_failure);
    spinel_push_u8(&buf, max_tx_failure);
    spinel_push_u16(&buf, blacklist_min_ms);
    spinel_push_u16(&buf, blacklist_max_ms);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_max_mac_retry(uint8_t val)
{
    rcp_set_u8(SPINEL_PROP_WS_MAX_FRAME_RETRIES, val);
}

void rcp_set_max_csma_backoffs(uint8_t val)
{
    rcp_set_u8(SPINEL_PROP_WS_MAX_CSMA_BACKOFFS, val);
}

void rcp_set_min_be(uint8_t val)
{
    rcp_set_u8(SPINEL_PROP_WS_MIN_BE, val);
}

void rcp_set_max_be(uint8_t val)
{
    rcp_set_u8(SPINEL_PROP_WS_MAX_BE, val);
}

void rcp_set_fhss_timings(const struct fhss_ws_configuration *timing_info)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_SET_CONF);
    spinel_push_u8(&buf, timing_info->ws_uc_channel_function);
    spinel_push_u8(&buf, timing_info->ws_bc_channel_function);
    spinel_push_u16(&buf, timing_info->bsi);
    spinel_push_u8(&buf, timing_info->fhss_uc_dwell_interval);
    spinel_push_u32(&buf, timing_info->fhss_broadcast_interval);
    spinel_push_u8(&buf, timing_info->fhss_bc_dwell_interval);
    spinel_push_u8(&buf, timing_info->unicast_fixed_channel);
    spinel_push_u8(&buf, timing_info->broadcast_fixed_channel);
    spinel_push_fixed_u8_array(&buf, timing_info->domain_channel_mask, 32);
    spinel_push_fixed_u8_array(&buf, timing_info->unicast_channel_mask, 32);
    spinel_push_u16(&buf, timing_info->channel_mask_size);
    spinel_push_u8(&buf, timing_info->config_parameters.number_of_channel_retries);
    if (!version_older_than(ctxt->rcp_version_api, 0, 18, 0))
        spinel_push_fixed_u8_array(&buf, timing_info->broadcast_channel_mask, 32);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_parent(const uint8_t parent[8],
                         const struct broadcast_timing_info *timing_info,
                         bool force_synch)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_SET_PARENT);
    spinel_push_fixed_u8_array(&buf, parent, 8);
    spinel_push_bool(&buf, force_synch);
    spinel_push_u8(&buf, timing_info->broadcast_channel_function);
    spinel_push_u8(&buf, timing_info->broadcast_dwell_interval);
    spinel_push_u16(&buf, timing_info->fixed_channel);
    spinel_push_u16(&buf, timing_info->broadcast_slot);
    spinel_push_u16(&buf, timing_info->broadcast_schedule_id);
    spinel_push_u32(&buf, timing_info->broadcast_interval_offset);
    spinel_push_u32(&buf, timing_info->broadcast_interval);
    spinel_push_u32(&buf, timing_info->bt_rx_timestamp);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_neighbor(const uint8_t neigh[8],
                           const struct fhss_ws_neighbor_timing_info *timing_info)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_UPDATE_NEIGHBOR);
    spinel_push_fixed_u8_array(&buf, neigh, 8);
    spinel_push_u8(&buf, timing_info->clock_drift);
    spinel_push_u8(&buf, timing_info->timing_accuracy);
    spinel_push_u16(&buf, timing_info->uc_channel_list.channel_count);
    spinel_push_fixed_u8_array(&buf, timing_info->uc_channel_list.channel_mask, 32);
    spinel_push_u8(&buf, timing_info->uc_timing_info.unicast_channel_function);
    spinel_push_u8(&buf, timing_info->uc_timing_info.unicast_dwell_interval);
    spinel_push_u16(&buf, timing_info->uc_timing_info.unicast_number_of_channels);
    spinel_push_u16(&buf, timing_info->uc_timing_info.fixed_channel);
    spinel_push_u32(&buf, timing_info->uc_timing_info.ufsi);
    spinel_push_u32(&buf, timing_info->uc_timing_info.utt_rx_timestamp);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}
void rcp_drop_fhss_neighbor(const uint8_t eui64[8])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_DROP_NEIGHBOR);
    spinel_push_fixed_u8_array(&buf, eui64, 8);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_hop_count(int hop_count)
{
    rcp_set_u8(SPINEL_PROP_WS_FHSS_SET_HOP_COUNT, hop_count);
}

void rcp_set_tx_allowance_level(fhss_ws_tx_allow_level_e normal,
                                fhss_ws_tx_allow_level_e expedited_forwarding)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_SET_TX_ALLOWANCE_LEVEL);
    spinel_push_uint(&buf, normal);
    spinel_push_uint(&buf, expedited_forwarding);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_frame_counter_per_key(bool enable)
{
    rcp_set_bool(SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY, enable);
}

void rcp_set_frame_counter(int slot, uint32_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FRAME_COUNTER);
    spinel_push_uint(&buf, slot);
    spinel_push_u32(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

