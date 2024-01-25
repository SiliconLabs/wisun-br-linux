/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/parsers.h"
#include "common/rand.h"
#include "common/ws_regdb.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/ns_list.h"
#include "common/mathutils.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ws.h"
#include "common/events_scheduler.h"

#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"
#include "6lowpan/ws/ws_bbr_api.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_management_api.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_stats.h"
#include "6lowpan/ws/ws_ie_lib.h"

#include "6lowpan/ws/ws_common.h"

#define TRACE_GROUP "wscm"

int DEVICE_MIN_SENS = -93;

int8_t ws_common_generate_channel_list(const struct net_if *cur,
                                       uint8_t *channel_mask,
                                       uint16_t number_of_channels,
                                       uint8_t regulatory_domain,
                                       uint8_t operating_class,
                                       uint8_t channel_plan_id)
{
    const struct chan_params *chan_params;

    chan_params = ws_regdb_chan_params(regulatory_domain, channel_plan_id, operating_class);
    WARN_ON(chan_params && chan_params->chan_count != number_of_channels);

    memset(channel_mask, 0xFF, 32);
    if (chan_params && chan_params->chan_allowed)
        parse_bitmask(channel_mask, 32, chan_params->chan_allowed);
    if (cur->ws_info.regulation == HIF_REG_ARIB) {
        // For now, ARIB is not supported for custom channel plans
        BUG_ON(!chan_params);
        // For now, ARIB is not supported outside of Japan
        BUG_ON(chan_params->reg_domain != REG_DOMAIN_JP);
        // Note: if user specify a FAN1.1 channel plan, these mask are already
        // applied
        if (chan_params->op_class == 1)
            bitfill(channel_mask, false, 0, 8); // Allowed channels: "9-255"
        if (chan_params->op_class == 2)
            bitfill(channel_mask, false, 0, 3); // Allowed channels: "4-255"
        if (chan_params->op_class == 3)
            bitfill(channel_mask, false, 0, 2); // Allowed channels: "3-255"
    }
    bitfill(channel_mask, false, number_of_channels, 255);
    return 0;
}

int8_t ws_common_regulatory_domain_config(struct net_if *cur, ws_hopping_schedule_t *hopping_schedule)
{
    const struct chan_params *chan_params;

    // Check if phy_mode_id is valid
    if (!ws_regdb_phy_params(hopping_schedule->phy_mode_id, hopping_schedule->operating_mode))
        return -1;

    // Case where channel parameters are provided by the user
    if (hopping_schedule->regulatory_domain == REG_DOMAIN_UNDEF)
        return 0;

    if (hopping_schedule->channel_plan_id && hopping_schedule->channel_plan_id != 255)
        hopping_schedule->channel_plan = 2;
    else
        hopping_schedule->channel_plan = 0;
    chan_params = ws_regdb_chan_params(hopping_schedule->regulatory_domain, hopping_schedule->channel_plan_id,
                                       hopping_schedule->operating_class);
    if (!chan_params)
        return -1;

    hopping_schedule->ch0_freq = chan_params->chan0_freq;
    hopping_schedule->number_of_channels = chan_params->chan_count;
    hopping_schedule->channel_spacing = chan_params->chan_spacing;
    BUG_ON(hopping_schedule->channel_spacing < 0);

    return 0;
}

int8_t ws_common_allocate_and_init(struct net_if *cur)
{
    memset(&cur->ws_info, 0, sizeof(ws_info_t));

    cur->ws_info.network_pan_id = 0xffff;
    cur->ws_info.pan_information.use_parent_bs = true;
    cur->ws_info.pan_information.rpl_routing_method = true;
    cur->ws_info.pan_information.pan_version_set = false;
    cur->ws_info.pan_information.version = WS_FAN_VERSION_1_0;
    cur->ws_info.pending_key_index_info.state = NO_PENDING_PROCESS;

    cur->ws_info.hopping_schedule.regulatory_domain = REG_DOMAIN_EU;
    cur->ws_info.hopping_schedule.operating_mode = OPERATING_MODE_3;
    cur->ws_info.hopping_schedule.operating_class = 2;
    // Clock drift value 255 indicates that information is not provided
    cur->ws_info.hopping_schedule.clock_drift = 255;
    // Timing accuracy is given from 0 to 2.55msec with 10usec resolution
    cur->ws_info.hopping_schedule.timing_accuracy = 100;
    ws_common_regulatory_domain_config(cur, &cur->ws_info.hopping_schedule);
    cur->ws_info.pending_key_index_info.state = NO_PENDING_PROCESS;
    return 0;
}

void ws_common_seconds_timer(int seconds)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (!(cur->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    ws_bootstrap_seconds_timer(cur, seconds);
}

void ws_common_fast_timer(int ticks)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (!(cur->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    ws_bootstrap_trickle_timer(cur, ticks);
}

uint8_t ws_common_allow_child_registration(struct net_if *interface, const uint8_t *eui64, uint16_t aro_timeout)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, eui64);
    ws_neigh_t *neigh_table = interface->ws_info.neighbor_storage.neigh_info_list;
    uint32_t lifetime_s = aro_timeout * 60;
    uint8_t child_count = 0;

    if (!ws_neigh)
        return ARO_TOPOLOGICALLY_INCORRECT;

    if (aro_timeout == 0) {
        //DeRegister Address Reg
        return ARO_SUCCESS;
    }

    //Validate Is EUI64 already allocated for any address
    if (ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, eui64)) {
        ws_neigh_refresh(ws_neigh, lifetime_s);
        return ARO_SUCCESS;
    }

    for (uint8_t i = 0; i < interface->ws_info.neighbor_storage.list_size; i++) {
        if (!neigh_table[i].in_use)
            continue;
        if (ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, neigh_table[i].mac64))
            child_count++;
    }

    if (child_count >= interface->ws_info.neighbor_storage.list_size) {
        tr_warn("Child registration not allowed %d/%d", child_count, interface->ws_info.neighbor_storage.list_size);
        return ARO_FULL;
    }

    ws_neigh_refresh(ws_neigh, lifetime_s);
    tr_info("Child registration allowed %d/%d", child_count, interface->ws_info.neighbor_storage.list_size);

    ws_stats_update(interface, STATS_WS_CHILD_ADD, 1);
    return ARO_SUCCESS;
}

bool ws_common_negative_aro_mark(struct net_if *interface, const uint8_t *eui64)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, eui64);

    if (!ws_neigh)
        return false;

    ws_neigh_refresh(ws_neigh, WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME);
    return true;
}

uint32_t ws_common_datarate_get_from_phy_mode(uint8_t phy_mode_id, uint8_t operating_mode)
{
    const struct phy_params *phy_params;

    phy_params = ws_regdb_phy_params(phy_mode_id, operating_mode);
    if (!phy_params)
        return 0;
    return phy_params->datarate;
}

uint32_t ws_common_datarate_get(struct net_if *cur)
{
    return ws_common_datarate_get_from_phy_mode(cur->ws_info.hopping_schedule.phy_mode_id, cur->ws_info.hopping_schedule.operating_mode);
}

bool ws_common_is_valid_nr(uint8_t node_role)
{
    switch (node_role) {
    case WS_NR_ROLE_BR:
    case WS_NR_ROLE_ROUTER:
    case WS_NR_ROLE_LFN:
        return true;
    }
    return false;
}

uint8_t ws_common_calc_plf(uint16_t pan_size, uint8_t network_size)
{
    uint16_t max_size;

    switch (network_size) {
    case NETWORK_SIZE_SMALL:
        max_size = 100;
        break;
    case NETWORK_SIZE_MEDIUM:
        max_size = 1000;
        break;
    case NETWORK_SIZE_LARGE:
        max_size = 10000;
        break;
    default:
        return UINT8_MAX;
    }
    return MIN(100 * pan_size / max_size, 100);
}
