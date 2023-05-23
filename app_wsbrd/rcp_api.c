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
#include "stack/mac/mlme.h"
#include "stack/mac/channel_list.h"
#include "stack/mac/fhss_ws_extension.h"
#include "stack/mac/platform/arm_hal_phy.h"
#include "stack/ws_management_api.h"

#include "common/version.h"
#include "common/iobuf.h"
#include "common/utils.h"
#include "common/endian.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_neighbor_class.h"

#include "wsbr_pcapng.h"
#include "wsbr_mac.h"
#include "wsbr.h"
#include "version.h"
#include "rcp_api.h"


uint8_t rcp_get_spinel_hdr()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    uint8_t hdr = FIELD_PREP(0xC0, 0x2) | FIELD_PREP(0x30, ctxt->spinel_iid);

    ctxt->spinel_tid = (ctxt->spinel_tid + 1) % 0x10;
    if (!ctxt->spinel_tid)
        ctxt->spinel_tid = 1;
    hdr |= FIELD_PREP(0x0F, ctxt->spinel_tid);
    return hdr;
}

static void spinel_push_hdr_set_prop(struct iobuf_write *buf, unsigned int prop)
{
    spinel_push_u8(buf, rcp_get_spinel_hdr());
    spinel_push_uint(buf, SPINEL_CMD_PROP_SET);
    spinel_push_uint(buf, prop);
}

static void spinel_push_hdr_get_prop(struct iobuf_write *buf, unsigned int prop)
{
    spinel_push_u8(buf, rcp_get_spinel_hdr());
    spinel_push_uint(buf, SPINEL_CMD_PROP_GET);
    spinel_push_uint(buf, prop);
}

static void rcp_set_bool(unsigned int prop, bool val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, prop);
    spinel_push_bool(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_u8(unsigned int prop, uint8_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, prop);
    spinel_push_u8(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_u16(unsigned int prop, uint16_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, prop);
    spinel_push_u16(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_u32(unsigned int prop, uint32_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, prop);
    spinel_push_u32(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

static void rcp_set_eui64(unsigned int prop, const uint8_t val[8])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, prop);
    spinel_push_fixed_u8_array(&buf, val, 8);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}


void rcp_noop()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_u8(&buf, rcp_get_spinel_hdr());
    spinel_push_uint(&buf, SPINEL_CMD_NOOP);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_reset()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_u8(&buf, rcp_get_spinel_hdr());
    spinel_push_uint(&buf, SPINEL_CMD_RESET);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_reset_stack()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_RESET);
    spinel_push_bool(&buf, true);
    spinel_push_u32(&buf, version_daemon_api);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_start(uint16_t channel, uint16_t panid, bool coordinator)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_START);
    spinel_push_u16(&buf,  panid);
    spinel_push_u8(&buf,   channel);
    spinel_push_u8(&buf,   0);
    spinel_push_u32(&buf,  0);
    spinel_push_u8(&buf,   0x0F);
    spinel_push_u8(&buf,   0x0F);
    spinel_push_bool(&buf, coordinator);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_allocate_fhss(const struct fhss_ws_configuration *timing_info)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_CREATE);
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
    if (!version_older_than(ctxt->rcp.version_api, 0, 12, 0))
        spinel_push_fixed_u8_array(&buf, timing_info->broadcast_channel_mask, 32);
    if (!version_older_than(ctxt->rcp.version_api, 0, 23, 0))
        spinel_push_u32(&buf, timing_info->lfn_bc_interval);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_register_fhss()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_REGISTER);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_unregister_fhss()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_UNREGISTER);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_release_fhss()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_DELETE);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_get_rx_sensitivity(void)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_get_prop(&buf, SPINEL_PROP_WS_RX_SENSITIVITY);
    spinel_push_uint(&buf, 0);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_get_hw_addr()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_get_prop(&buf, SPINEL_PROP_HWADDR);
    spinel_push_uint(&buf, 0);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_get_rf_config_list()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_get_prop(&buf, SPINEL_PROP_WS_RF_CONFIGURATION_LIST);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_rf_config_legacy(const struct phy_rf_channel_configuration *config)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_RF_CONFIGURATION_LEGACY);
    spinel_push_u32(&buf, config->channel_0_center_frequency);
    spinel_push_u32(&buf, config->channel_spacing);
    spinel_push_u32(&buf, config->datarate);
    spinel_push_u16(&buf, config->number_of_channels);
    spinel_push_u8(&buf,  config->modulation);
    spinel_push_u8(&buf,  config->modulation_index);
    if (!version_older_than(ctxt->rcp.version_api, 0, 6, 0)) {
        spinel_push_bool(&buf, config->fec);
        spinel_push_uint(&buf, config->ofdm_option);
        spinel_push_uint(&buf, config->ofdm_mcs);
    }
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

#define RF_CONFIG_FLAGS_MCS_MASK     0x0F
#define RF_CONFIG_FLAGS_USE_POM_MASK 0x10

void rcp_set_rf_config(const struct phy_rf_channel_configuration *config)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_RF_CONFIG);
    spinel_push_u16(&buf, FIELD_PREP(RF_CONFIG_FLAGS_MCS_MASK, config->ofdm_mcs) |
                          FIELD_PREP(RF_CONFIG_FLAGS_USE_POM_MASK, config->use_phy_op_modes));
    spinel_push_u16(&buf, config->rcp_config_index);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);

    // Contrary to PROP_SET/RF_CONFIG_LEGACY, no confirmation is returned.
    // However it should not be possible to send incorrect radio parameters.
    ctxt->rcp.init_state |= RCP_HAS_RF_CONFIG;
}

void rcp_set_regional_regulation(uint32_t val)
{
    rcp_set_u32(SPINEL_PROP_WS_REGIONAL_REGULATION, val);
}

void rcp_set_rx_on_idle(bool enable)
{
    rcp_set_bool(SPINEL_PROP_WS_RX_ON_WHEN_IDLE, enable);
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

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_CCA_THRESHOLD_START);
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

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_REQUEST_RESTART);
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

void rcp_set_max_async_duration(uint32_t val)
{
    rcp_set_u32(SPINEL_PROP_WS_ASYNC_FRAGMENTATION, val);
}

void rcp_set_tx_power(int8_t val)
{
    rcp_set_u8(SPINEL_PROP_PHY_TX_POWER, (uint8_t)val);
}

void rcp_set_fhss_timings(const struct fhss_ws_configuration *timing_info)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_SET_CONF);
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
    if (!version_older_than(ctxt->rcp.version_api, 0, 18, 0))
        spinel_push_fixed_u8_array(&buf, timing_info->broadcast_channel_mask, 32);
    if (!version_older_than(ctxt->rcp.version_api, 0, 23, 0))
        spinel_push_u32(&buf, timing_info->lfn_bc_interval);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_parent(const uint8_t parent[8],
                         const struct fhss_ws_neighbor_timing_info *timing_info,
                         bool force_synch)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_SET_PARENT);
    spinel_push_fixed_u8_array(&buf, parent, 8);
    spinel_push_bool(&buf, force_synch);
    spinel_push_u8(&buf, timing_info->bc_chan_func);
    spinel_push_u8(&buf, timing_info->ffn.bc_dwell_interval_ms);
    spinel_push_u16(&buf, timing_info->bc_chan_fixed);
    spinel_push_u16(&buf, timing_info->ffn.bc_slot);
    spinel_push_u16(&buf, timing_info->ffn.bsi);
    spinel_push_u32(&buf, timing_info->ffn.bc_interval_offset_ms);
    spinel_push_u32(&buf, timing_info->ffn.bc_interval_ms);
    spinel_push_u32(&buf, timing_info->ffn.bt_rx_tstamp_us);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_neighbor(const uint8_t neigh[8],
                           const struct fhss_ws_neighbor_timing_info *timing_info)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_UPDATE_NEIGHBOR);
    spinel_push_fixed_u8_array(&buf, neigh, 8);
    spinel_push_u8(&buf, timing_info->clock_drift);
    spinel_push_u8(&buf, timing_info->timing_accuracy);
    spinel_push_u16(&buf, timing_info->uc_channel_list.channel_count);
    spinel_push_fixed_u8_array(&buf, timing_info->uc_channel_list.channel_mask, 32);
    spinel_push_u8(&buf, timing_info->uc_chan_func);
    spinel_push_u8(&buf, timing_info->ffn.uc_dwell_interval_ms);
    spinel_push_u16(&buf, timing_info->uc_chan_count);
    spinel_push_u16(&buf, timing_info->uc_chan_fixed);
    spinel_push_u32(&buf, timing_info->ffn.ufsi);
    spinel_push_u32(&buf, timing_info->ffn.utt_rx_tstamp_us);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}
void rcp_drop_fhss_neighbor(const uint8_t eui64[8])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_DROP_NEIGHBOR);
    spinel_push_fixed_u8_array(&buf, eui64, 8);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_fhss_hop_count(int hop_count)
{
    rcp_set_u8(SPINEL_PROP_WS_FHSS_SET_HOP_COUNT, hop_count);
}

void rcp_set_coordinator_mac64(uint8_t val[8])
{
    rcp_set_eui64(SPINEL_PROP_WS_COORD_EXTENDED_ADDRESS, val);
}

void rcp_set_coordinator_mac16(uint16_t val)
{
    rcp_set_u16(SPINEL_PROP_WS_COORD_SHORT_ADDRESS, val);
}

void rcp_set_tx_allowance_level(fhss_ws_tx_allow_level_e normal,
                                fhss_ws_tx_allow_level_e expedited_forwarding)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FHSS_SET_TX_ALLOWANCE_LEVEL);
    spinel_push_uint(&buf, normal);
    spinel_push_uint(&buf, expedited_forwarding);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_security(bool enable)
{
    rcp_set_bool(SPINEL_PROP_WS_SECURITY_ENABLED, enable);
}

void rcp_set_accept_unknown_secured_frames(bool enable)
{
    rcp_set_bool(SPINEL_PROP_WS_ACCEPT_BYPASS_UNKNOW_DEVICE, enable);
}

void rcp_set_frame_counter_per_key(bool enable)
{
    rcp_set_bool(SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY, enable);
}

void rcp_set_frame_counter(int slot, uint32_t val)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_FRAME_COUNTER);
    spinel_push_uint(&buf, slot);
    spinel_push_u32(&buf, val);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_get_frame_counter(int slot)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_get_prop(&buf, SPINEL_PROP_WS_FRAME_COUNTER);
    spinel_push_uint(&buf, slot);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_key(uint8_t slot, const uint8_t *lookup_data, const uint8_t *key)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };
    uint8_t empty_key[16] = { };

    BUG_ON(key && !lookup_data);
    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_KEY_TABLE);
    spinel_push_u8(&buf, slot);
    if (key) {
        spinel_push_fixed_u8_array(&buf, key, 16);
        // In 15.4, lookup_data could have a size of 5, but not with Wi-SUN
        spinel_push_data(&buf, lookup_data, 9);
    } else {
        spinel_push_fixed_u8_array(&buf, empty_key, 16);
        spinel_push_data(&buf, NULL, 0);
    }
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_set_default_key_source(const uint8_t lookup_data[8])
{
    rcp_set_eui64(SPINEL_PROP_WS_DEFAULT_KEY_SOURCE, lookup_data);
}

void rcp_set_neighbor(uint8_t slot, uint16_t panid, uint16_t mac16, uint8_t *mac64, uint32_t frame_counter)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };
    uint8_t empty_mac64[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_DEVICE_TABLE);
    spinel_push_u8(&buf, slot);
    spinel_push_u16(&buf, panid);
    spinel_push_u16(&buf, mac16);
    if (mac64)
        spinel_push_fixed_u8_array(&buf, mac64, 8);
    else
        spinel_push_fixed_u8_array(&buf, empty_mac64, 8);
    spinel_push_u32(&buf, frame_counter);
    spinel_push_bool(&buf, false);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_enable_mac_filter(bool forward_unknown)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_MAC_FILTER_START);
    spinel_push_u16(&buf, forward_unknown ? 0x100 : 0);
    spinel_push_u16(&buf, 0);
    spinel_push_u16(&buf, forward_unknown ? 0x200 : 0);
    spinel_push_u16(&buf, 0);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_disable_mac_filter()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_MAC_FILTER_STOP);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_add_mac_filter_entry(uint8_t mac64[8], bool forward)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_MAC_FILTER_ADD_LONG);
    spinel_push_fixed_u8_array(&buf, mac64, 8);
    spinel_push_u16(&buf, forward ? 0x100 : 0);
    spinel_push_u16(&buf, 0);
    spinel_push_u16(&buf, forward ? 0x200 : 0);
    spinel_push_u16(&buf, 0);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_clear_mac_filters()
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_WS_MAC_FILTER_CLEAR);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_abort_edfe()
{
    rcp_set_bool(SPINEL_PROP_WS_EDFE_FORCE_STOP, false);
}

void rcp_tx_req_legacy(const struct mcps_data_req *tx_req,
                       const struct iovec *header_ie,
                       const struct iovec *payload_ie,
                       const struct iovec *mpx_ie,
                       const struct channel_list *channel_list)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };
    uint8_t empty_channel_mask[32] = { };
    int len;

    BUG_ON(!tx_req);
    BUG_ON((tx_req->fhss_type == HIF_FHSS_TYPE_ASYNC) != !!channel_list);
    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_STREAM_RAW);
    spinel_push_data(&buf, tx_req->msdu, tx_req->msduLength);
    spinel_push_u8(&buf,   tx_req->SrcAddrMode);
    spinel_push_u8(&buf,   tx_req->DstAddrMode);
    spinel_push_u16(&buf,  tx_req->DstPANId);
    spinel_push_fixed_u8_array(&buf, tx_req->DstAddr, 8);
    spinel_push_u8(&buf,   tx_req->msduHandle);
    spinel_push_bool(&buf, tx_req->TxAckReq);
    spinel_push_bool(&buf, false);
    spinel_push_bool(&buf, tx_req->PendingBit);
    spinel_push_bool(&buf, tx_req->SeqNumSuppressed);
    spinel_push_bool(&buf, tx_req->PanIdSuppressed);
    spinel_push_bool(&buf, tx_req->ExtendedFrameExchange);
    spinel_push_u8(&buf,   tx_req->Key.SecurityLevel);
    spinel_push_u8(&buf,   tx_req->Key.KeyIdMode);
    spinel_push_u8(&buf,   tx_req->Key.KeyIndex);
    spinel_push_fixed_u8_array(&buf, tx_req->Key.Keysource, 8);
    spinel_push_u16(&buf,  tx_req->priority);
    if (channel_list) {
        spinel_push_uint(&buf, channel_list->channel_page);
        spinel_push_fixed_u8_array(&buf, channel_list->channel_mask, 32);
    } else {
        spinel_push_uint(&buf, CHANNEL_PAGE_UNDEFINED);
        spinel_push_fixed_u8_array(&buf, empty_channel_mask, 32);
    }
    len = 0;
    if (payload_ie)
        len += payload_ie->iov_len;
    if (mpx_ie)
        len += mpx_ie->iov_len;
    spinel_push_u16(&buf, len);
    if (payload_ie)
        spinel_push_raw(&buf, payload_ie->iov_base, payload_ie->iov_len);
    if (mpx_ie)
        spinel_push_raw(&buf, mpx_ie->iov_base, mpx_ie->iov_len);
    if (header_ie)
        spinel_push_data(&buf, header_ie->iov_base, header_ie->iov_len);
    else
        spinel_push_data(&buf, NULL, 0);
    if (!version_older_than(ctxt->rcp.version_api, 0, 7, 0)) {
        if (channel_list)
            spinel_push_u16(&buf, channel_list->next_channel_number);
        else
            spinel_push_u16(&buf, 0);
    }
    if (!version_older_than(ctxt->rcp.version_api, 0, 12,0))
        spinel_push_u8(&buf, tx_req->phy_id);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

/*
 * Values for flags field of PROP_FRAME
 */
#define HIF_FHSS_TYPE_MASK      0x0007
#define HIF_FHSS_RESERVED1      0x0008
// Values for this mask are the same than Wi-SUN: WS_FIXED_CHANNEL, WS_DH1CF and WS_TR51CF
#define HIF_FHSS_CHAN_FUNC_MASK   0x0030
#define   HIF_FHSS_CHAN_FUNC_FIXED   WS_FIXED_CHANNEL  // 0x00
#define   HIF_FHSS_CHAN_FUNC_TR51    WS_TR51CF         // 0x01
#define   HIF_FHSS_CHAN_FUNC_DH1     WS_DH1CF          // 0x02
#define   HIF_FHSS_CHAN_FUNC_AUTO    0x03
#define HIF_FHSS_RESERVED2        0x0040
#define HIF_FHSS_EDFE_MASK        0x0080
#define HIF_FHSS_MODE_SWITCH_MASK 0x0100
#define HIF_FHSS_PRIORITY_MASK    0x0600

void rcp_tx_req(const uint8_t *frame, int frame_len,
                const struct ws_neighbor_class_entry *neighbor_ws,
                uint8_t handle, uint8_t fhss_type, bool is_edfe,
                uint8_t priority, uint8_t phy_id)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct iobuf_write buf = { };
    int flags, flags_offset, len;

    spinel_push_hdr_set_prop(&buf, SPINEL_PROP_FRAME);
    spinel_push_u8(&buf, handle);
    spinel_push_data(&buf, frame, frame_len);

    flags = 0;
    flags_offset = buf.len;
    spinel_push_u16(&buf, 0);

    flags |= FIELD_PREP(HIF_FHSS_TYPE_MASK, fhss_type);
    switch (fhss_type) {
    case HIF_FHSS_TYPE_FFN_UC:
        BUG_ON(!neighbor_ws);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.ffn.utt_rx_tstamp_us);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.ffn.ufsi);
        spinel_push_u8(&buf, neighbor_ws->fhss_data.ffn.uc_dwell_interval_ms);
        spinel_push_u8(&buf, neighbor_ws->fhss_data.clock_drift);
        spinel_push_u8(&buf, neighbor_ws->fhss_data.timing_accuracy);
        break;
    case HIF_FHSS_TYPE_FFN_BC:
        flags |= FIELD_PREP(HIF_FHSS_CHAN_FUNC_MASK, HIF_FHSS_CHAN_FUNC_AUTO);
        break;
    case HIF_FHSS_TYPE_LFN_UC:
        BUG_ON(!neighbor_ws);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.lfn.lutt_rx_tstamp_us);
        spinel_push_u16(&buf, neighbor_ws->fhss_data.lfn.uc_slot_number);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.lfn.uc_interval_offset_ms);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.lfn.uc_listen_interval_ms);
        break;
    case HIF_FHSS_TYPE_LFN_BC:
        flags |= FIELD_PREP(HIF_FHSS_CHAN_FUNC_MASK, HIF_FHSS_CHAN_FUNC_AUTO);
        break;
    case HIF_FHSS_TYPE_ASYNC:
        spinel_push_u32(&buf, ctxt->config.ws_async_frag_duration);
        break;
    case HIF_FHSS_TYPE_LFN_PA:
        BUG_ON(!neighbor_ws);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.lfn.lnd_rx_tstamp_us);
        spinel_push_u32(&buf, neighbor_ws->fhss_data.lfn.lpa_response_delay_ms);
        spinel_push_u8(&buf,  neighbor_ws->fhss_data.lfn.lpa_slot_duration_ms);
        spinel_push_u8(&buf,  neighbor_ws->fhss_data.lfn.lpa_slot_count);
        spinel_push_u16(&buf, neighbor_ws->fhss_data.lfn.lpa_slot_first);
        break;
    default:
        BUG();
    }
    if (fhss_type == HIF_FHSS_TYPE_FFN_UC || fhss_type == HIF_FHSS_TYPE_LFN_UC || fhss_type == HIF_FHSS_TYPE_LFN_PA) {
        switch (neighbor_ws->fhss_data.uc_chan_func) {
        case WS_FIXED_CHANNEL:
            flags |= FIELD_PREP(HIF_FHSS_CHAN_FUNC_MASK, WS_FIXED_CHANNEL);
            spinel_push_u16(&buf, neighbor_ws->fhss_data.uc_chan_fixed);
            break;
        case WS_DH1CF:
            flags |= FIELD_PREP(HIF_FHSS_CHAN_FUNC_MASK, WS_DH1CF);
            len = roundup(neighbor_ws->fhss_data.uc_chan_count, 8) / 8;
            spinel_push_u8(&buf, len);
            spinel_push_fixed_u8_array(&buf, neighbor_ws->fhss_data.uc_channel_list.channel_mask, len);
            break;
        default:
            BUG();
        }
    } else {
        flags |= FIELD_PREP(HIF_FHSS_CHAN_FUNC_MASK, HIF_FHSS_CHAN_FUNC_AUTO);
    }
    flags |= FIELD_PREP(HIF_FHSS_EDFE_MASK, is_edfe);
    if (phy_id) {
        flags |= FIELD_PREP(HIF_FHSS_MODE_SWITCH_MASK, 1);
        spinel_push_u8(&buf, 10);
        spinel_push_u8(&buf, phy_id);
        spinel_push_u16(&buf, 0);
        spinel_push_u16(&buf, 0);
        spinel_push_u16(&buf, 0);
    }
    flags |= FIELD_PREP(HIF_FHSS_PRIORITY_MASK, priority);
    write_le16(&buf.data[flags_offset], flags);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
}

void rcp_tx_drop(uint8_t handle)
{
    rcp_set_u8(SPINEL_PROP_WS_MCPS_DROP, handle);
}

static void rcp_rx_no_op(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
}

static void rcp_rx_reset(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    if (iobuf_remaining_size(buf) < 16)
        FATAL(1, "unknown RESET format (bad firmware?)");
    ctxt->rcp.version_api = spinel_pop_u32(buf);
    ctxt->rcp.version_fw = spinel_pop_u32(buf);
    ctxt->rcp.version_label = strdup(spinel_pop_str(buf));
    spinel_pop_bool(buf); /* Formerly: is_hw_reset */
    ctxt->rcp.neighbors_table_size = spinel_pop_u8(buf);
    spinel_pop_u8(buf); /* Formerly: key_description_table_size */
    spinel_pop_u8(buf); /* Formerly: key_lookup_size */
    spinel_pop_u8(buf); /* Formerly: key_usage_size */
    if (iobuf_remaining_size(buf))
        ctxt->rcp.lfn_limit = spinel_pop_u8(buf);
    ctxt->rcp.init_state |= RCP_HAS_RESET;
    WARN_ON(!ctxt->rcp.on_reset);
    if (ctxt->rcp.on_reset)
        ctxt->rcp.on_reset(ctxt);
}

static void rcp_rx_crc_err(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    uint16_t crc            = spinel_pop_u16(buf);
    uint32_t frame_len      = spinel_pop_u32(buf);
    uint8_t header          = spinel_pop_u8(buf);
    uint8_t irq_err_counter = spinel_pop_u8(buf);

    if (!spinel_prop_is_valid(buf, prop))
        return;
    WARN_ON(!ctxt->rcp.on_crc_error);
    if (ctxt->rcp.on_crc_error)
        ctxt->rcp.on_crc_error(ctxt->os_ctxt, crc, frame_len, header, irq_err_counter);
}

static void rcp_rx_rf_config_status(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    int val = spinel_pop_uint(buf);

    if (val || !spinel_prop_is_valid(buf, prop))
        return;
    ctxt->rcp.init_state |= RCP_HAS_RF_CONFIG;
}

static void rcp_rx_sensitivity(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    int val = spinel_pop_i16(buf);

    if (!spinel_prop_is_valid(buf, prop))
        return;
    // FIXME: remove this hack
    // from -174dBm to + 80dBm, so add + 174 to real sensitivity
    DEVICE_MIN_SENS = 174 + val;
}

static void rcp_rx_rf_list(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    int phy_mode_group = 0;
    bool is_submode, is_submode_prev;
    int i = 0;

    BUG_ON(ctxt->rcp.rail_config_list);
    is_submode_prev = true;
    while (iobuf_remaining_size(buf)) {
        ctxt->rcp.rail_config_list = reallocarray(ctxt->rcp.rail_config_list, i + 2, sizeof(struct rcp_rail_config));
        ctxt->rcp.rail_config_list[i].index = i;
        ctxt->rcp.rail_config_list[i].chan0_freq = spinel_pop_u32(buf);
        ctxt->rcp.rail_config_list[i].chan_spacing = spinel_pop_u32(buf);
        ctxt->rcp.rail_config_list[i].chan_count = spinel_pop_u16(buf);
        ctxt->rcp.rail_config_list[i].rail_phy_mode_id = spinel_pop_u8(buf);
        is_submode = spinel_pop_bool(buf);
        FATAL_ON(i == 0 && is_submode, 3, "corrupted RAIL configuration");
        if (is_submode && !is_submode_prev)
            ctxt->rcp.rail_config_list[i - 1].phy_mode_group = ++phy_mode_group;
        ctxt->rcp.rail_config_list[i].phy_mode_group = is_submode ? phy_mode_group : 0;
        is_submode_prev = is_submode;
        i++;
    }
    memset(&ctxt->rcp.rail_config_list[i], 0, sizeof(struct rcp_rail_config));
    if (!spinel_prop_is_valid(buf, prop))
        return;
    ctxt->rcp.init_state |= RCP_HAS_RF_CONFIG_LIST;
}

static void rcp_rx_hwaddr(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    spinel_pop_fixed_u8_array(buf, ctxt->rcp.eui64, 8);
    if (!spinel_prop_is_valid(buf, prop))
        return;
    ctxt->rcp.init_state |= RCP_HAS_HWADDR;
}

static void rcp_rx_frame_counter(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    uint32_t value;

    spinel_pop_uint(buf); /* Unused: key_index */
    value = spinel_pop_u32(buf);
    if (!spinel_prop_is_valid(buf, prop))
        return;
    ctxt->rcp.frame_counter = value;
}

static void rcp_rx_err(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    mlme_comm_status_t *status;
    int id;

    id = spinel_pop_uint(buf);
    if (id != MLME_COMM_STATUS) {
        ERROR("%s: received unsupported message: %02x", __func__, id);
        return;
    }
    spinel_pop_data_ptr(buf, (const uint8_t **)&status);
    if (!spinel_prop_is_valid(buf, prop))
        return;
    WARN_ON(!ctxt->rcp.on_rx_err);
    if (ctxt->rcp.on_rx_err)
        ctxt->rcp.on_rx_err(status->SrcAddr, status->status);
}

static void rcp_rx_ind(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
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
    if (iobuf_remaining_size(buf)) {
        req.TxAckReq           = spinel_pop_bool(buf);
        req.PendingBit         = spinel_pop_bool(buf);
        req.PanIdSuppressed    = spinel_pop_bool(buf);
        // FIXME: remove this hack
        if (ctxt->config.pcap_file[0])
            wsbr_pcapng_write_frame(ctxt, &req, &ie_ext);
    }
    if (!spinel_prop_is_valid(buf, prop))
        return;
    ctxt->rcp.on_rx_ind(ctxt->rcp_if_id, &req, &ie_ext);
}

static void rcp_tx_cnf(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
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
    if (iobuf_remaining_size(buf)) {
        spinel_pop_raw(buf, (uint8_t *)req.retry_per_rate, sizeof(mcps_data_retry_t) * MAX_PHY_MODE_ID_PER_FRAME);
        req.success_phy_mode_id = spinel_pop_u8(buf);
    }
    if (!spinel_prop_is_valid(buf, prop))
        return;
    ctxt->rcp.on_tx_cnf(ctxt->rcp_if_id, &req, &conf_req);
}

// Some debug tools (fuzzers) may deflect this struct. So keep it public.
struct rcp_rx_cmds rx_cmds[] = {
    { SPINEL_CMD_NOOP,             (uint32_t)-1,                         rcp_rx_no_op },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_MCPS_DROP,             rcp_rx_no_op },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_STREAM_STATUS,            rcp_tx_cnf },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_STREAM_RAW,               rcp_rx_ind  },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_MLME_IND,              rcp_rx_err  },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_FRAME_COUNTER,         rcp_rx_frame_counter},
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_HWADDR,                   rcp_rx_hwaddr },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_RX_SENSITIVITY,        rcp_rx_sensitivity },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_RF_CONFIGURATION_LIST, rcp_rx_rf_list },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_RF_CONFIGURATION_LEGACY, rcp_rx_rf_config_status },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_LAST_STATUS,              rcp_rx_no_op },
    { SPINEL_CMD_PROP_IS,          SPINEL_PROP_WS_RCP_CRC_ERR,           rcp_rx_crc_err },
    { SPINEL_CMD_RESET,            (uint32_t)-1,                         rcp_rx_reset },
    { SPINEL_CMD_REPLAY_TIMERS,    (uint32_t)-1,                         rcp_rx_no_op },
    { SPINEL_CMD_REPLAY_INTERFACE, (uint32_t)-1,                         rcp_rx_no_op },
    { (uint32_t)-1,                (uint32_t)-1,                         NULL },
};

void rcp_tx(struct wsbr_ctxt *ctxt, struct iobuf_write *buf)
{
    spinel_trace_tx(buf);
    ctxt->rcp.device_tx(ctxt->os_ctxt, buf->data, buf->len);
}

static bool rcp_init_state_is_valid(struct wsbr_ctxt *ctxt, int prop)
{
    if (!(ctxt->rcp.init_state & RCP_HAS_RESET))
        return false;
    if (!(ctxt->rcp.init_state & RCP_HAS_HWADDR))
        return prop == SPINEL_PROP_HWADDR;
    if (!version_older_than(ctxt->rcp.version_api, 0, 11, 0) && !(ctxt->rcp.init_state & RCP_HAS_RF_CONFIG_LIST))
        return prop == SPINEL_PROP_WS_RF_CONFIGURATION_LIST;
    return true;
}

void rcp_rx(struct wsbr_ctxt *ctxt)
{
    static uint8_t rx_buf[4096];
    struct iobuf_read buf = {
        .data = rx_buf,
    };
    uint32_t cmd, prop;
    int i;

    buf.data_size = ctxt->rcp.device_rx(ctxt->os_ctxt, rx_buf, sizeof(rx_buf));
    if (!buf.data_size)
        return;
    spinel_trace_rx(&buf);
    spinel_pop_u8(&buf); /* packet header */
    cmd = spinel_pop_uint(&buf);
    if (cmd != SPINEL_CMD_PROP_IS) {
        prop = (uint32_t)-1;
    } else {
        prop = spinel_pop_uint(&buf);
        if (!rcp_init_state_is_valid(ctxt, prop)) {
            WARN("ignoring unexpected boot-up sequence");
            return;
        }
    }
    for (i = 0; rx_cmds[i].cmd != (uint32_t)-1; i++)
        if (rx_cmds[i].cmd == cmd && rx_cmds[i].prop == prop)
            return rx_cmds[i].fn(ctxt, prop, &buf);
    ERROR("%s: command %04x/%04x not implemented", __func__, cmd, prop);
}
