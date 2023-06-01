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
#include "common/utils.h"
#include "service_libs/etx/etx.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/blacklist/blacklist.h"
#include "common/events_scheduler.h"
#include "stack/net_interface.h"
#include "stack/ws_management_api.h"
#include "stack/mac/fhss_config.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mac_api.h"

#include "common_protocols/icmpv6.h"
#include "rpl/rpl_protocol.h"
#include "rpl/rpl_control.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"
#include "6lowpan/ws/ws_bootstrap_ffn.h"
#include "6lowpan/ws/ws_bootstrap_lfn.h"
#include "6lowpan/ws/ws_bbr_api_internal.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_stats.h"
#include "6lowpan/ws/ws_ie_lib.h"

#include "6lowpan/ws/ws_common.h"

#define TRACE_GROUP "wscm"

// estimated sensitivity -93 dbm converted to Wi-SUN RSL range
// This provides a range of -174 (0) to +80 (254) dBm
uint8_t DEVICE_MIN_SENS = 174 - 93;



uint16_t test_max_child_count_override = 0xffff;

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
    if (cur->ws_info.regulation == REG_REGIONAL_ARIB) {
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
    hopping_schedule->channel_spacing = ws_regdb_chan_spacing_id(chan_params->chan_spacing);
    BUG_ON(hopping_schedule->channel_spacing < 0);

    return 0;
}

uint16_t ws_common_channel_number_calc(uint8_t regulatory_domain, uint8_t operating_class, uint8_t channel_plan_id)
{
    const struct chan_params *params;

    params = ws_regdb_chan_params(regulatory_domain, channel_plan_id, operating_class);
    if (!params)
        return 0;
    return params->chan_count;
}

int8_t ws_common_allocate_and_init(struct net_if *cur)
{
    memset(&cur->ws_info, 0, sizeof(ws_info_t));
    ns_list_init(&cur->ws_info.active_nud_process);
    ns_list_init(&cur->ws_info.free_nud_entries);

    ns_list_init(&cur->ws_info.parent_list_free);
    ns_list_init(&cur->ws_info.parent_list_reserved);

    cur->ws_info.version = test_pan_version;

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

    // initialize for FAN 1.1 defaults
    if (ws_version_1_1(cur)) {
        cur->ws_info.pan_information.version = WS_FAN_VERSION_1_1;
    }
    return 0;
}

int ws_common_init(int8_t interface_id, net_6lowpan_mode_e bootstrap_mode)
{
    return ws_bootstrap_init(interface_id, bootstrap_mode);
}

void ws_common_state_machine(struct net_if *cur)
{
    if (cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_HOST) {
        // Configure for LFN device
        ws_bootstrap_lfn_state_machine(cur);
    } else if (cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_ROUTER) {
        // Configure FFN device
        ws_bootstrap_ffn_state_machine(cur);
    } else if (cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        // Configure as Border router
        ws_bootstrap_6lbr_state_machine(cur);
    }

}

void ws_common_seconds_timer(int seconds)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (!(cur->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    ws_bbr_seconds_timer(cur, seconds);
    ws_bootstrap_seconds_timer(cur, seconds);
    ws_bootstrap_6lbr_seconds_timer(cur, seconds);
    ws_bootstrap_ffn_seconds_timer(cur, seconds);
    ws_bootstrap_lfn_seconds_timer(cur, seconds);
    blacklist_ttl_update(seconds);
}

void ws_common_fast_timer(int ticks)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (!(cur->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    ws_bootstrap_trickle_timer(cur, ticks);
    ws_nud_active_timer(cur, ticks);
    ws_llc_fast_timer(cur, ticks);
}

void ws_common_create_ll_address(uint8_t *ll_address, const uint8_t *mac64)
{
    memcpy(ll_address, ADDR_LINK_LOCAL_PREFIX, 8);
    memcpy(ll_address + 8, mac64, 8);
    ll_address[8] ^= 2;
}

void ws_common_neighbor_update(struct net_if *cur, const uint8_t *ll_address)
{
    //Neighbor connectected update
    mac_neighbor_table_entry_t *mac_neighbor = mac_neighbor_entry_get_by_ll64(cur->mac_parameters.mac_neighbor_table, ll_address, false, NULL);
    if (mac_neighbor) {
        ws_nud_entry_remove_active(cur, mac_neighbor);
    }
}

void ws_common_black_list_neighbour(const uint8_t *ll_address, uint8_t nd_status)
{
    if (nd_status == ARO_FULL) {
        blacklist_update(ll_address, false);
    }
}

void ws_common_aro_failure(struct net_if *cur, const uint8_t *ll_address)
{
    tr_warn("ARO registration Failure %s", tr_ipv6(ll_address));
    ws_bootstrap_aro_failure(cur, ll_address);
}

void ws_common_neighbor_remove(struct net_if *cur, const uint8_t *ll_address)
{
    tr_debug("neighbor remove %s", tr_ipv6(ll_address));
    ws_bootstrap_neighbor_remove(cur, ll_address);
}

uint8_t ws_common_temporary_entry_size(uint8_t mac_table_size)
{
    if (mac_table_size >= 128) {
        return (WS_LARGE_TEMPORARY_NEIGHBOUR_ENTRIES);
    } else if (mac_table_size >= 64) {
        return (WS_MEDIUM_TEMPORARY_NEIGHBOUR_ENTRIES);
    } else if (mac_table_size >= WS_SMALL_TEMPORARY_NEIGHBOUR_ENTRIES) {
        return WS_SMALL_TEMPORARY_NEIGHBOUR_ENTRIES;
    } else {
        BUG();
    }
}

static void ws_common_neighbour_address_reg_link_update(struct net_if *interface, const uint8_t *eui64, uint32_t link_lifetime)
{
    if (link_lifetime > WS_NEIGHBOR_LINK_TIMEOUT) {
        link_lifetime = WS_NEIGHBOR_LINK_TIMEOUT;
    }
    /*
     * ARO registration from child can update the link timeout so we don't need to send extra NUD if ARO received
     */
    mac_neighbor_table_entry_t *mac_neighbor = mac_neighbor_entry_get_by_mac64(interface->mac_parameters.mac_neighbor_table, eui64, false, false);

    if (mac_neighbor) {
        if (mac_neighbor->link_lifetime < link_lifetime) {
            //Set Stable timeout for temporary entry here
            if (link_lifetime > WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME && mac_neighbor->link_lifetime  < WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME) {
                tr_info("Added new neighbor %s : index:%u", tr_eui64(eui64), mac_neighbor->index);
            }
            mac_neighbor->link_lifetime = WS_NEIGHBOR_LINK_TIMEOUT;

        }
        //Refresh
        mac_neighbor->lifetime = mac_neighbor->link_lifetime;
    }
}

uint8_t ws_common_allow_child_registration(struct net_if *interface, const uint8_t *eui64, uint16_t aro_timeout)
{
    uint8_t child_count = 0;
    uint8_t max_child_count = interface->mac_parameters.mac_neighbor_table->list_total_size - ws_common_temporary_entry_size(interface->mac_parameters.mac_neighbor_table->list_total_size);

    if (aro_timeout == 0) {
        //DeRegister Address Reg
        return ARO_SUCCESS;
    }
    uint32_t link_lifetime = (aro_timeout * 60) + 1;

    // Test API to limit child count
    if (test_max_child_count_override != 0xffff) {
        max_child_count = test_max_child_count_override;
    }

    //Validate Is EUI64 already allocated for any address
    if (ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, eui64)) {
        ws_common_neighbour_address_reg_link_update(interface, eui64, link_lifetime);
        tr_info("Child registration from old child");

        return ARO_SUCCESS;
    }

    //Verify that we have Selected Parent
    if (interface->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER && !rpl_control_parent_candidate_list_size(interface, true)) {
        tr_info("Do not accept new ARO child: no selected parent");
        return ARO_TOPOLOGICALLY_INCORRECT;
    }

    ns_list_foreach_safe(mac_neighbor_table_entry_t, cur, &interface->mac_parameters.mac_neighbor_table->neighbour_list) {

        if (ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, cur->mac64)) {
            child_count++;
        }
    }

    if (child_count >= max_child_count) {
        tr_warn("Child registration not allowed %d/%d, max:%d", child_count, max_child_count, interface->mac_parameters.mac_neighbor_table->list_total_size);
        return ARO_FULL;
    }

    ws_common_neighbour_address_reg_link_update(interface, eui64, link_lifetime);
    tr_info("Child registration allowed %d/%d, max:%d", child_count, max_child_count, interface->mac_parameters.mac_neighbor_table->list_total_size);

    ws_stats_update(interface, STATS_WS_CHILD_ADD, 1);
    return ARO_SUCCESS;
}

bool ws_common_negative_aro_mark(struct net_if *interface, const uint8_t *eui64)
{
    mac_neighbor_table_entry_t *neighbour = mac_neighbor_table_address_discover(interface->mac_parameters.mac_neighbor_table, eui64, ADDR_802_15_4_LONG);
    if (!neighbour) {
        return false;
    }

    ws_bootstrap_mac_neighbor_short_time_set(interface, eui64, WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME);
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

void ws_common_primary_parent_update(struct net_if *interface, mac_neighbor_table_entry_t *neighbor)
{
    ws_bootstrap_primary_parent_update(interface, neighbor);
}

void ws_common_secondary_parent_update(struct net_if *interface)
{
    ws_bootstrap_secondary_parent_update(interface);
}

void ws_common_border_router_alive_update(struct net_if *interface)
{
    if (interface->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        return;
    }

    // After successful DAO ACK connection to border router is verified
    interface->ws_info.pan_timeout_timer = interface->ws_info.cfg->timing.pan_timeout;
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
