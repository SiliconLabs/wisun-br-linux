/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* Interface with nanostack/source/Service_Libs/fhss that is now relocated to
 * the device.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "nanostack/fhss_config.h"
#include "nanostack/fhss_api.h"

#include "host-common/spinel.h"
#include "host-common/spinel_buffer.h"
#include "wsbr.h"
#include "wsbr_mac.h"
#include "wsbr_fhss_net.h"

#include "host-common/log.h"

struct fhss_api *ns_fhss_ws_create(const struct fhss_ws_configuration *config,
                                   const fhss_timer_t *fhss_timer)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 100);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    // fhss_timer is filled by wsbr_configure(). We know we know we pass -1.
    BUG_ON(fhss_timer != (fhss_timer_t *)-1);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_CREATE);
    spinel_push_u8(buf, config->ws_uc_channel_function);
    spinel_push_u8(buf, config->ws_bc_channel_function);
    spinel_push_u16(buf, config->bsi);
    spinel_push_u8(buf, config->fhss_uc_dwell_interval);
    spinel_push_u32(buf, config->fhss_broadcast_interval);
    spinel_push_u8(buf, config->fhss_bc_dwell_interval);
    spinel_push_u8(buf, config->unicast_fixed_channel);
    spinel_push_u8(buf, config->broadcast_fixed_channel);
    spinel_push_fixed_u32_array(buf, config->channel_mask, 8);
    spinel_push_fixed_u32_array(buf, config->unicast_channel_mask, 8);
    spinel_push_u16(buf, config->channel_mask_size);
    spinel_push_u8(buf, config->config_parameters.number_of_channel_retries);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    ctxt->fhss_conf_valid = true;
    memcpy(&ctxt->fhss_conf, config, sizeof(*config));
    // Upper layers absolutly want something != NULL
    return FHSS_API_PLACEHOLDER;
}

int ns_fhss_delete(struct fhss_api *fhss_api)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_DELETE);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    ctxt->fhss_conf_valid = false;
    return 0;
}

const struct fhss_ws_configuration *ns_fhss_ws_configuration_get(const struct fhss_api *fhss_api)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    if (ctxt->fhss_conf_valid)
        return &ctxt->fhss_conf;
    else
        return NULL;
}

int ns_fhss_ws_configuration_set(const struct fhss_api *fhss_api,
                                 const struct fhss_ws_configuration *config)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 100);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(!ctxt->fhss_conf_valid);
    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_SET_CONF);
    spinel_push_u8(buf, config->ws_uc_channel_function);
    spinel_push_u8(buf, config->ws_bc_channel_function);
    spinel_push_u16(buf, config->bsi);
    spinel_push_u8(buf, config->fhss_uc_dwell_interval);
    spinel_push_u32(buf, config->fhss_broadcast_interval);
    spinel_push_u8(buf, config->fhss_bc_dwell_interval);
    spinel_push_u8(buf, config->unicast_fixed_channel);
    spinel_push_u8(buf, config->broadcast_fixed_channel);
    spinel_push_fixed_u32_array(buf, config->channel_mask, 8);
    spinel_push_fixed_u32_array(buf, config->unicast_channel_mask, 8);
    spinel_push_u16(buf, config->channel_mask_size);
    spinel_push_u8(buf, config->config_parameters.number_of_channel_retries);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    memcpy(&ctxt->fhss_conf, config, sizeof(*config));
    return 0;
}

int ns_fhss_ws_set_tx_allowance_level(const fhss_api_t *fhss_api,
                                      const fhss_ws_tx_allow_level global_level,
                                      const fhss_ws_tx_allow_level ef_level)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 6);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_SET_TX_ALLOWANCE_LEVEL);
    spinel_push_int(buf, global_level);
    spinel_push_int(buf, ef_level);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    return 0;
}

int ns_fhss_ws_set_parent(const struct fhss_api *fhss_api, const uint8_t eui64[8],
                          const broadcast_timing_info_t *bc_timing_info, const bool force_synch)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 30);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_SET_PARENT);
    spinel_push_fixed_u8_array(buf, eui64, 8);
    spinel_push_bool(buf, force_synch);
    spinel_push_u8(buf, bc_timing_info->broadcast_channel_function);
    spinel_push_u8(buf, bc_timing_info->broadcast_dwell_interval);
    spinel_push_u16(buf, bc_timing_info->fixed_channel);
    spinel_push_u16(buf, bc_timing_info->broadcast_slot);
    spinel_push_u16(buf, bc_timing_info->broadcast_schedule_id);
    spinel_push_u32(buf, bc_timing_info->broadcast_interval_offset);
    spinel_push_u32(buf, bc_timing_info->broadcast_interval);
    spinel_push_u32(buf, bc_timing_info->bt_rx_timestamp);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    ctxt->fhss_conf.fhss_bc_dwell_interval = bc_timing_info->broadcast_dwell_interval;
    ctxt->fhss_conf.fhss_broadcast_interval = bc_timing_info->broadcast_interval;
    return 0;
}

void ns_fhss_ws_update_neighbor(const uint8_t eui64[8],
                                fhss_ws_neighbor_timing_info_t *fhss_data)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 60);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_UPDATE_NEIGHBOR);
    spinel_push_fixed_u8_array(buf, eui64, 8);
    spinel_push_u8(buf, fhss_data->clock_drift);
    spinel_push_u8(buf, fhss_data->timing_accuracy);
    spinel_push_u16(buf, fhss_data->uc_channel_list.channel_count);
    spinel_push_fixed_u32_array(buf, fhss_data->uc_channel_list.channel_mask, 8);
    spinel_push_u8(buf, fhss_data->uc_timing_info.unicast_channel_function);
    spinel_push_u8(buf, fhss_data->uc_timing_info.unicast_dwell_interval);
    spinel_push_u16(buf, fhss_data->uc_timing_info.unicast_number_of_channels);
    spinel_push_u16(buf, fhss_data->uc_timing_info.fixed_channel);
    spinel_push_u32(buf, fhss_data->uc_timing_info.ufsi);
    spinel_push_u32(buf, fhss_data->uc_timing_info.utt_rx_timestamp);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

void ns_fhss_ws_drop_neighbor(const uint8_t eui64[8])
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 8);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_DROP_NEIGHBOR);
    spinel_push_fixed_u8_array(buf, eui64, 8);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
}

int ns_fhss_set_neighbor_info_fp(const struct fhss_api *fhss_api,
                                 fhss_get_neighbor_info *get_neighbor_info)
{
    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    //BUG_ON(get_neighbor_info != ws_get_neighbor_info);
    return 0;
}

int ns_fhss_ws_set_hop_count(const struct fhss_api *fhss_api, const uint8_t hop_count)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 1);
    struct wsbr_ctxt *ctxt = &g_ctxt;

    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_SET_HOP_COUNT);
    spinel_push_u8(buf, hop_count);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    return 0;
}

