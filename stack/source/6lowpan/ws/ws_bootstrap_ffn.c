/*
 * Copyright (c) 2021, Pelion and affiliates.
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
#include <inttypes.h>
#include "common/log.h"
#include "common/rand.h"
#include "common/trickle.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/events_scheduler.h"
#include "common/serial_number_arithmetic.h"
#include "service_libs/etx/etx.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/blacklist/blacklist.h"
#include "service_libs/random_early_detection/random_early_detection_api.h"
#include "stack/net_interface.h"
#include "stack/ws_management_api.h"
#include "stack/net_rpl.h"
#include "stack/mac/platform/topo_trace.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/fhss_config.h"
#include "stack/mac/sw_mac.h"
#include "stack/timers.h"

#include "app_wsbrd/rcp_api.h"
#include "nwk_interface/protocol.h"
#include "ipv6_stack/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "rpl/rpl_protocol.h"
#include "rpl/rpl_control.h"
#include "rpl/rpl_data.h"
#include "rpl/rpl_policy.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/ip.h"
#include "legacy/dhcpv6_utils.h"
#include "legacy/dhcpv6_service.h"
#include "legacy/dhcpv6_client.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"

#include "6lowpan/ws/ws_bbr_api_internal.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_bootstrap_ffn.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_eapol_auth_relay.h"
#include "6lowpan/ws/ws_eapol_pdu.h"
#include "6lowpan/ws/ws_eapol_relay.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_ie_validation.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_neighbor_class.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_stats.h"

#define TRACE_GROUP "wsbs"

static void ws_bootstrap_ffn_ip_stack_addr_clear(struct net_if *cur)
{
    tr_debug("ip stack address clear");
    ns_list_foreach_safe(if_address_entry_t, addr, &cur->ip_addresses) {
        if (addr->source != ADDR_SOURCE_STATIC &&
                addr_ipv6_scope(addr->address, cur) > IPV6_SCOPE_LINK_LOCAL) {
            // Remove all exept User set address
            addr_delete_entry(cur, addr);
        }
    }
}

static void ws_bootstrap_ffn_decode_exclude_range_to_mask_by_range(void *mask_buffer, ws_excluded_channel_range_t *range_info, uint16_t number_of_channels)
{
    uint16_t range_start, range_stop;
    uint8_t mask_index = 0;
    //uint8_t channel_index = 0;
    const uint8_t *range_ptr = range_info->range_start;
    uint32_t *mask_ptr = mask_buffer;
    while (range_info->number_of_range) {
        range_start = read_le16(range_ptr);
        range_ptr += 2;
        range_stop = read_le16(range_ptr);
        range_ptr += 2;
        range_info->number_of_range--;
        for (uint16_t channel = 0; channel < number_of_channels; channel++) {

            if (channel && (channel % 32 == 0)) {
                mask_index++;
                //channel_index = 0;
            }
            if (channel >= range_start && channel <= range_stop) {
                //mask_ptr[mask_index] |= 1u << (31 - channel_index);
                mask_ptr[channel / 32] |= 1u << (31 - (channel % 32));
            } else if (channel > range_stop) {
                break;
            }
        }
    }
    // Exclusion Mask is stored most significant byte first
    for (uint16_t i = 0; i < (number_of_channels + 31) / 32; ++i) {
        write_be32((uint8_t *)&mask_ptr[i], mask_ptr[i]);
    }
}

void ws_bootstrap_ffn_candidate_table_reset(struct net_if *cur)
{
    //Empty active list
    ns_list_foreach_safe(parent_info_t, entry, &cur->ws_info.parent_list_free) {
        ns_list_remove(&cur->ws_info.parent_list_free, entry);
    }

    //Empty free list
    ns_list_foreach_safe(parent_info_t, entry, &cur->ws_info.parent_list_reserved) {
        ns_list_remove(&cur->ws_info.parent_list_reserved, entry);
    }
    //Add to free list to full
    for (int i = 0; i < WS_PARENT_LIST_SIZE; i++) {
        ns_list_add_to_end(&cur->ws_info.parent_list_free, &cur->ws_info.parent_info[i]);
    }
}

static void ws_bootstrap_ffn_candidate_parent_store(parent_info_t *parent, const struct mcps_data_ind *data, ws_utt_ie_t *ws_utt, ws_us_ie_t *ws_us, ws_pan_information_t *pan_information)
{
    parent->ws_utt = *ws_utt;
    // Saved from unicast IE
    parent->ws_us = *ws_us;

    //copy excluded channel here if it is inline
    if (ws_us->chan_plan.excluded_channel_ctrl == WS_EXC_CHAN_CTRL_RANGE) {
        memset(parent->excluded_channel_data, 0, 32);
        //Decode Range to mask here
        ws_bootstrap_ffn_decode_exclude_range_to_mask_by_range(parent->excluded_channel_data, &parent->ws_us.chan_plan.excluded_channels.range, 256);
        parent->ws_us.chan_plan.excluded_channels.mask.channel_mask = parent->excluded_channel_data;
        parent->ws_us.chan_plan.excluded_channels.mask.mask_len_inline = 32;
        parent->ws_us.chan_plan.excluded_channel_ctrl = WS_EXC_CHAN_CTRL_BITMASK;
    } else if (ws_us->chan_plan.excluded_channel_ctrl == WS_EXC_CHAN_CTRL_BITMASK) {
        parent->ws_us.chan_plan.excluded_channels.mask.channel_mask = parent->excluded_channel_data;
        memcpy(parent->excluded_channel_data, ws_us->chan_plan.excluded_channels.mask.channel_mask, ws_us->chan_plan.excluded_channels.mask.mask_len_inline);
    }

    // Saved from Pan information, do not overwrite pan_version as it is not valid here
    parent->pan_information.pan_size = pan_information->pan_size;
    parent->pan_information.routing_cost = pan_information->routing_cost;
    parent->pan_information.use_parent_bs = pan_information->use_parent_bs;
    parent->pan_information.rpl_routing_method = pan_information->rpl_routing_method;
    parent->pan_information.version = pan_information->version;

    // Saved from message
    parent->timestamp = data->timestamp;
    parent->pan_id = data->SrcPANId;
    parent->link_quality = data->mpduLinkQuality;
    parent->signal_dbm = data->signal_dbm;
    memcpy(parent->addr, data->SrcAddr, 8);

    if (ws_neighbor_class_rsl_from_dbm_calculate(parent->signal_dbm) > (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERISIS)) {
        parent->link_acceptable = true;
    }
    if (ws_neighbor_class_rsl_from_dbm_calculate(parent->signal_dbm) < (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD - CAND_PARENT_HYSTERISIS)) {
        parent->link_acceptable = false;
    }
    parent->age = g_monotonic_time_100ms;
}

static parent_info_t *ws_bootstrap_ffn_candidate_parent_get_best(struct net_if *cur)
{
    ns_list_foreach_safe(parent_info_t, entry, &cur->ws_info.parent_list_reserved) {
        tr_info("candidate list a:%s panid:%x cost:%d size:%d rssi:%d txFailure:%u age:%"PRIu32, tr_eui64(entry->addr), entry->pan_id, entry->pan_information.routing_cost, entry->pan_information.pan_size, entry->signal_dbm, entry->tx_fail, g_monotonic_time_100ms - entry->age);
    }

    return ns_list_get_first(&cur->ws_info.parent_list_reserved);
}

static parent_info_t *ws_bootstrap_ffn_candidate_parent_allocate(struct net_if *cur, const uint8_t *addr)
{
    parent_info_t *entry = ns_list_get_first(&cur->ws_info.parent_list_free);
    if (entry) {
        memcpy(entry->addr, addr, 8);
        ns_list_remove(&cur->ws_info.parent_list_free, entry);
        ns_list_add_to_end(&cur->ws_info.parent_list_reserved, entry);
    } else {
        // If there is no free entries always allocate the last one of reserved as it is the worst
        entry = ns_list_get_last(&cur->ws_info.parent_list_reserved);

    }
    if (entry) {
        entry->tx_fail = 0;
        entry->link_acceptable = false;
    }
    return entry;
}

parent_info_t *ws_bootstrap_ffn_candidate_parent_get(struct net_if *cur, const uint8_t *addr, bool create)
{
    ns_list_foreach_safe(parent_info_t, entry, &cur->ws_info.parent_list_reserved) {
        if (memcmp(entry->addr, addr, 8) == 0) {
            return entry;
        }
    }
    if (create) {
        return ws_bootstrap_ffn_candidate_parent_allocate(cur, addr);
    }
    return NULL;
}

static bool ws_bootstrap_ffn_candidate_parent_compare(parent_info_t *p1, parent_info_t *p2)
{
    // Return true if P2 is better
    // signal lower than threshold for both
    // pan_cost
    // signal quality

    if (p2->tx_fail > p1->tx_fail) {
        return false;
    }

    if (p2->tx_fail < p1->tx_fail) {
        return true;
    }

    if (p1->link_acceptable && !p2->link_acceptable) {
        // Link acceptable is always better than not
        return true;
    }
    if (!p1->link_acceptable && p2->link_acceptable) {
        // Link acceptable is always better than not
        return false;
    }

    // Select the lowest PAN cost
    uint16_t p1_pan_cost = (p1->pan_information.routing_cost / PRC_WEIGHT_FACTOR) + (p1->pan_information.pan_size / PS_WEIGHT_FACTOR);
    uint16_t p2_pan_cost = (p2->pan_information.routing_cost / PRC_WEIGHT_FACTOR) + (p2->pan_information.pan_size / PS_WEIGHT_FACTOR);
    if (p1_pan_cost > p2_pan_cost) {
        return true;
    } else if (p1_pan_cost < p2_pan_cost) {
        return false;
    }

    // If pan cost is the same then we select the one we hear highest
    if (p1->signal_dbm < p2->signal_dbm) {
        return true;
    }
    return false;
}

static void ws_bootstrap_ffn_candidate_parent_sort(struct net_if *cur, parent_info_t *new_entry)
{
    //Remove from the list

    ns_list_foreach_safe(parent_info_t, entry, &cur->ws_info.parent_list_reserved) {

        if (entry == new_entry) {
            // own entry skip it
            continue;
        }

        if (ws_bootstrap_ffn_candidate_parent_compare(entry, new_entry)) {
            // New entry is better
            //tr_debug("candidate list new is better");
            ns_list_remove(&cur->ws_info.parent_list_reserved, new_entry);
            ns_list_add_before(&cur->ws_info.parent_list_reserved, entry, new_entry);
            return;
        }
    }
    // This is the last entry
    ns_list_remove(&cur->ws_info.parent_list_reserved, new_entry);
    ns_list_add_to_end(&cur->ws_info.parent_list_reserved, new_entry);
}

static void ws_bootstrap_ffn_candidate_parent_mark_failure(struct net_if *cur, const uint8_t *addr)
{
    parent_info_t *entry = ws_bootstrap_ffn_candidate_parent_get(cur, addr, false);
    if (entry) {
        if (entry->tx_fail >= 2) {
            ns_list_remove(&cur->ws_info.parent_list_reserved, entry);
            ns_list_add_to_end(&cur->ws_info.parent_list_free, entry);
        } else {
            entry->tx_fail++;
            ws_bootstrap_ffn_candidate_parent_sort(cur, entry);
        }

    }
}

static void ws_bootstrap_ffn_candidate_list_clean(struct net_if *cur, uint8_t pan_max, uint32_t current_time, uint16_t pan_id)
{
    int pan_count = 0;

    ns_list_foreach_safe(parent_info_t, entry, &cur->ws_info.parent_list_reserved) {

        if ((current_time - entry->age) > WS_PARENT_LIST_MAX_AGE) {
            ns_list_remove(&cur->ws_info.parent_list_reserved, entry);
            ns_list_add_to_end(&cur->ws_info.parent_list_free, entry);
            continue;
        }
        if (entry->pan_id == pan_id) {
            // Same panid if there is more than limited amount free those
            pan_count++;
            if (pan_count > pan_max) {
                ns_list_remove(&cur->ws_info.parent_list_reserved, entry);
                ns_list_add_to_end(&cur->ws_info.parent_list_free, entry);
                continue;
            }
        }
    }
}

static int8_t ws_bootstrap_ffn_neighbor_set(struct net_if *cur, parent_info_t *parent_ptr, bool clear_list)
{
    uint16_t pan_id = cur->ws_info.network_pan_id;

    // Add EAPOL neighbor
    cur->ws_info.network_pan_id = parent_ptr->pan_id;
    cur->ws_info.pan_information.pan_size = parent_ptr->pan_information.pan_size;
    cur->ws_info.pan_information.routing_cost = parent_ptr->pan_information.routing_cost;
    cur->ws_info.pan_information.use_parent_bs = parent_ptr->pan_information.use_parent_bs;
    cur->ws_info.pan_information.pan_version = 0; // This is learned from actual configuration
    cur->ws_info.pan_information.lpan_version = 0; // This is learned from actual configuration

    // If PAN ID changes, clear learned neighbors and activate FHSS
    if (pan_id != cur->ws_info.network_pan_id) {
        if (clear_list) {
            ws_bootstrap_neighbor_list_clean(cur);
        }
        ws_bootstrap_fhss_activate(cur);
    }

    llc_neighbour_req_t neighbor_info;
    if (!ws_bootstrap_neighbor_get(cur, parent_ptr->addr, &neighbor_info) &&
        !ws_bootstrap_neighbor_add(cur, parent_ptr->addr, &neighbor_info, WS_NR_ROLE_ROUTER)) {
        //Remove Neighbour and set Link setup back
        ns_list_remove(&cur->ws_info.parent_list_reserved, parent_ptr);
        ns_list_add_to_end(&cur->ws_info.parent_list_free, parent_ptr);
        return -1;
    }
    ws_bootstrap_neighbor_set_stable(cur, parent_ptr->addr);
    ws_neighbor_class_ut_update(neighbor_info.ws_neighbor, parent_ptr->ws_utt.ufsi, parent_ptr->timestamp, parent_ptr->addr);
    ws_neighbor_class_us_update(cur, neighbor_info.ws_neighbor, &parent_ptr->ws_us.chan_plan,
                                parent_ptr->ws_us.dwell_interval, parent_ptr->addr);
    return 0;
}

static void ws_bootstrap_ffn_pan_information_store(struct net_if *cur, const struct mcps_data_ind *data, ws_utt_ie_t *ws_utt, ws_us_ie_t *ws_us, ws_pan_information_t *pan_information)
{

    parent_info_t *new_entry;
    /* Have List of 20 heard neighbours
     * Order those as best based on pan cost
     * In single pan order based on signal quality
     * in single PAN limit the amount of devices to 5
     * If there is no advertisement heard for last hour Clear the neigbour.
     */

    // Discovery state processing
    //tr_info("neighbour: addr:%s panid:%x signal:%d", tr_eui64(data->SrcAddr), data->SrcPANId, data->signal_dbm);

    // Clean old entries
    ws_bootstrap_ffn_candidate_list_clean(cur, WS_PARENT_LIST_MAX_PAN_IN_DISCOVERY, g_monotonic_time_100ms, data->SrcPANId);

    new_entry = ws_bootstrap_ffn_candidate_parent_get(cur, data->SrcAddr, true);
    if (!new_entry) {
        tr_warn("neighbour creation fail");
        return;
    }
    // Safe the information
    ws_bootstrap_ffn_candidate_parent_store(new_entry, data, ws_utt, ws_us, pan_information);
    if (!new_entry->link_acceptable) {
        // This entry is either poor quality or changed to poor quality link so we will remove this
        // Todo in future possibility to try poor link parents if we have not found any good link parents
        tr_info("neighbour not accepted: addr:%s panid:%x rsl:%d device_min_sens: %d", tr_eui64(new_entry->addr), new_entry->pan_id, ws_neighbor_class_rsl_from_dbm_calculate(new_entry->signal_dbm), DEVICE_MIN_SENS);
        ns_list_remove(&cur->ws_info.parent_list_reserved, new_entry);
        ns_list_add_to_end(&cur->ws_info.parent_list_free, new_entry);
        return;
    }
    // set to the correct place in list
    ws_bootstrap_ffn_candidate_parent_sort(cur, new_entry);

    return;
}

static int8_t ws_bootstrap_ffn_fhss_configure(struct net_if *cur, bool discovery)
{
    ws_bootstrap_fhss_set_defaults(cur, &cur->ws_info.fhss_conf);
    ws_bootstrap_fhss_configure_channel_masks(cur, &cur->ws_info.fhss_conf);

    // Discovery is done using fixed channel
    if (discovery) {
        cur->ws_info.fhss_conf.ws_uc_channel_function = WS_FIXED_CHANNEL;
    } else {
        cur->ws_info.fhss_conf.ws_uc_channel_function = (fhss_ws_channel_functions_e)cur->ws_info.cfg->fhss.fhss_uc_channel_function;
    }
    cur->ws_info.fhss_conf.ws_bc_channel_function = WS_FIXED_CHANNEL;
    cur->ws_info.fhss_conf.fhss_broadcast_interval = 0;
    uint8_t tmp_uc_fixed_channel = ws_bootstrap_randomize_fixed_channel(cur->ws_info.cfg->fhss.fhss_uc_fixed_channel, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.fhss_conf.domain_channel_mask);
    uint8_t tmp_bc_fixed_channel = ws_bootstrap_randomize_fixed_channel(cur->ws_info.cfg->fhss.fhss_bc_fixed_channel, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.fhss_conf.domain_channel_mask);
    cur->ws_info.fhss_conf.unicast_fixed_channel = tmp_uc_fixed_channel;
    cur->ws_info.fhss_conf.broadcast_fixed_channel = tmp_bc_fixed_channel;
    rcp_set_fhss_timings(&cur->ws_info.fhss_conf);
    rcp_set_fhss_hop_count(0xff);
    ws_bootstrap_llc_hopping_update(cur, &cur->ws_info.fhss_conf);

    return 0;
}

void ws_bootstrap_ffn_network_discovery_configure(struct net_if *cur)
{
    // Reset information to defaults
    cur->ws_info.network_pan_id = 0xffff;

    ws_common_regulatory_domain_config(cur, &cur->ws_info.hopping_schedule);
    ws_bootstrap_set_domain_rf_config(cur);
    ws_bootstrap_ffn_fhss_configure(cur, true);

    //Set Network names, Pan information configure, hopping schedule & GTKHash
    ws_llc_set_network_name(cur, (uint8_t *)cur->ws_info.cfg->gen.network_name, strlen(cur->ws_info.cfg->gen.network_name));
}

// Start network scan
static void ws_bootstrap_ffn_start_discovery(struct net_if *cur)
{
    tr_debug("router discovery start");
    // Remove network keys from MAC
    ws_pae_controller_nw_keys_remove(cur);
    ws_bootstrap_state_change(cur, ER_ACTIVE_SCAN);
    cur->ws_info.configuration_learned = false;
    cur->ws_info.pan_timeout_timer = 0;
    cur->ws_info.weakest_received_rssi = 0;

    // Clear learned candidate parents
    ws_bootstrap_ffn_candidate_table_reset(cur);

    // Clear RPL information
    rpl_control_free_domain_instances_from_interface(cur);
    // Clear EAPOL relay address
    ws_eapol_relay_delete(cur);

    // Clear ip stack from old information
    ws_bootstrap_ip_stack_reset(cur);
    // New network scan started old addresses not assumed valid anymore
    ws_bootstrap_ffn_ip_stack_addr_clear(cur);

    if ((cur->lowpan_info & INTERFACE_NWK_BOOTSTRAP_ACTIVE) != INTERFACE_NWK_BOOTSTRAP_ACTIVE) {
        // we have sent bootstrap ready event and now
        // restarted discovery so bootstrap down event is sent
        cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ACTIVE;
    }

    // Start advertisement solicit trickle and calculate when we are checking the status
    cur->ws_info.mngt.trickle_pas_running = true;
    if (cur->ws_info.mngt.trickle_pas.I != cur->ws_info.mngt.trickle_params.Imin) {
        // Trickle not reseted so starting a new interval
        trickle_start(&cur->ws_info.mngt.trickle_pas, "ADV SOL", &cur->ws_info.mngt.trickle_params);
    }

    // Discovery statemachine is checkked after we have sent the Solicit
    uint32_t time_to_solicit = 0;
    if (cur->ws_info.mngt.trickle_pas.t > cur->ws_info.mngt.trickle_pas.now) {
        time_to_solicit = cur->ws_info.mngt.trickle_pas.t - cur->ws_info.mngt.trickle_pas.now;
    }

    time_to_solicit += cur->ws_info.mngt.trickle_params.Imin + rand_get_random_in_range(0, cur->ws_info.mngt.trickle_params.Imin);

    if (time_to_solicit > 0xffff) {
        time_to_solicit = 0xffff;
    }
    cur->bootstrap_state_machine_cnt = time_to_solicit;

    tr_info("Making parent selection in %u s", (cur->bootstrap_state_machine_cnt / 10));
}

// Start configuration learning
static void ws_bootstrap_ffn_start_configuration_learn(struct net_if *cur)
{
    tr_debug("router configuration learn start");
    ws_bootstrap_state_change(cur, ER_SCAN);

    cur->ws_info.configuration_learned = false;

    // Clear all temporary information
    ws_bootstrap_ip_stack_reset(cur);

    cur->ws_info.mngt.pcs_count = 0;
    //Calculate max time for config learn state
    cur->ws_info.mngt.pcs_max_timeout = trickle_timer_max(&cur->ws_info.mngt.trickle_params, PCS_MAX);
    // Reset advertisement solicit trickle to start discovering network
    cur->ws_info.mngt.trickle_pcs_running = true;
    trickle_start(&cur->ws_info.mngt.trickle_pcs, "CFG SOL", &cur->ws_info.mngt.trickle_params);
    trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pcs, &cur->ws_info.mngt.trickle_params);
}

static void ws_bootstrap_ffn_pan_advertisement_analyse_active(struct net_if *cur, ws_pan_information_t *pan_information)
{
    if (pan_information->routing_cost != 0xFFFF &&
        pan_information->routing_cost >= ws_bootstrap_routing_cost_calculate(cur)) {
        trickle_consistent_heard(&cur->ws_info.mngt.trickle_pa);
    }
}

static void ws_bootstrap_ffn_pan_advertisement_analyse(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, ws_utt_ie_t *ws_utt, ws_us_ie_t *ws_us)
{

    //Validate Pan Conrfirmation is at packet
    ws_pan_information_t pan_information;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_pan_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &pan_information)) {
        // Corrupted
        tr_error("No pan information");
        return;
    }

    if (ws_us->chan_plan.excluded_channel_ctrl) {
        //Validate that we can storage data
        if (ws_us->chan_plan.excluded_channel_ctrl == WS_EXC_CHAN_CTRL_BITMASK && ws_us->chan_plan.excluded_channels.mask.mask_len_inline > 32) {
            return;
        }
    }

    // Check pan flags so that it is valid
    if (!pan_information.rpl_routing_method) {
        // NOT RPL routing
        //tr_warn("Not supported routing");
        return;
    }

    // Store heard pans and possible candidate parents
    ws_bootstrap_ffn_pan_information_store(cur, data, ws_utt, ws_us, &pan_information);

    if (!(ws_bootstrap_state_active(cur) ||
            ws_bootstrap_state_wait_rpl(cur))) {
        // During discovery/eapol/config learn we dont do further processing for advertisements
        return;
    }
    // Active state processing
    //tr_debug("Advertisement active");

    // In active operation less neighbours per pan is allowed
    ws_bootstrap_ffn_candidate_list_clean(cur, WS_PARENT_LIST_MAX_PAN_IN_ACTIVE, g_monotonic_time_100ms, data->SrcPANId);

    // Check if valid PAN
    if (data->SrcPANId != cur->ws_info.network_pan_id) {
        return;
    }

    // Save route cost for all known neighbors
    llc_neighbour_req_t neighbor_info;
    neighbor_info.neighbor = NULL;
    if (ws_bootstrap_neighbor_get(cur, data->SrcAddr, &neighbor_info))
        neighbor_info.ws_neighbor->routing_cost = pan_information.routing_cost;

    ws_bootstrap_ffn_pan_advertisement_analyse_active(cur, &pan_information);

    // Learn latest network information
    if (cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER && neighbor_info.neighbor) {
        uint8_t ll_address[16];
        ws_common_create_ll_address(ll_address, neighbor_info.neighbor->mac64);

        if (rpl_control_is_dodag_parent(cur, ll_address)) {
            cur->ws_info.pan_information.pan_size = pan_information.pan_size;
            cur->ws_info.pan_information.routing_cost = pan_information.routing_cost;
            cur->ws_info.pan_information.rpl_routing_method = pan_information.rpl_routing_method;
            cur->ws_info.pan_information.use_parent_bs = pan_information.use_parent_bs;
        }
    }
}

static void ws_bootstrap_ffn_pan_advertisement_solicit_analyse(struct net_if *cur, const struct mcps_data_ind *data, ws_utt_ie_t *ws_utt, ws_us_ie_t *ws_us)
{

    (void)data;
    (void)ws_utt;
    (void)ws_us;
    /*
     * An inconsistent transmission is defined as:
     * A PAN Advertisement Solicit with NETNAME-IE matching that of the receiving node.
     */
    trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pa, &cur->ws_info.mngt.trickle_params);
    /*
     *  A consistent transmission is defined as
     *  a PAN Advertisement Solicit with NETNAME-IE / Network Name matching that configured on the receiving node.
     */
    trickle_consistent_heard(&cur->ws_info.mngt.trickle_pas);
    /*
     *  Optimized PAN discovery to select the parent faster if we hear solicit from someone else
     */

    if (ws_bootstrap_state_discovery(cur)  && ws_cfg_network_config_get(cur) <= CONFIG_MEDIUM &&
            cur->bootstrap_state_machine_cnt > cur->ws_info.mngt.trickle_params.Imin * 2) {

        cur->bootstrap_state_machine_cnt = cur->ws_info.mngt.trickle_params.Imin + rand_get_random_in_range(0, cur->ws_info.mngt.trickle_params.Imin);

        tr_info("Making parent selection in %u s", (cur->bootstrap_state_machine_cnt / 10));
    }

    if (ws_bootstrap_state_active(cur) && cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_address_discover(cur->mac_parameters.mac_neighbor_table, data->SrcAddr, ADDR_802_15_4_LONG);
        if (neighbor && neighbor->link_role == PRIORITY_PARENT_NEIGHBOUR) {
            ws_bootstrap_parent_confirm(cur, NULL);
        }
    }
}

static void ws_bootstrap_ffn_pan_config_lfn_analyze(struct net_if *cur, const struct mcps_data_ie_list *ie_ext)
{
    if (!ws_version_1_1(cur) || cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        return;
    }

    ws_lfnver_ie_t lfn_version;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_lfnver_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &lfn_version)) {
        return; // LFN version
    }

    //Read LFNGTKHASH
    gtkhash_t lgtkhash[3];
    unsigned active_lgtk_index;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_lgtkhash_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, lgtkhash, &active_lgtk_index)) {
        return;
    }

    if (!cur->ws_info.pan_information.lpan_version_set) {
        if (!cur->ws_info.configuration_learned) {
            trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params);
        }
    } else {
        if (cur->ws_info.pan_information.lpan_version == lfn_version.lfn_version) {
            return;
        }

        if (serial_number_cmp16(cur->ws_info.pan_information.lpan_version, lfn_version.lfn_version)) {
            // older version heard ignoring the message
            return;
        }
    }

    tr_info("Updated LFN PAN configuration own:%d, heard:%d",
            cur->ws_info.pan_information.lpan_version, lfn_version.lfn_version);
    cur->ws_info.pan_information.lpan_version = lfn_version.lfn_version;
    cur->ws_info.pan_information.lpan_version_set = true;

    //Set Active key index and hash inline bits
    ws_pae_controller_lgtk_hash_update(cur, lgtkhash);
    ws_pae_controller_nw_key_index_update(cur, active_lgtk_index + GTK_NUM);
    //TODO Analyze HASH's and set LFN group key index
}


static void ws_bootstrap_ffn_pan_config_analyse(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, ws_utt_ie_t *ws_utt, ws_us_ie_t *ws_us)
{
    gtkhash_t gtkhash[4];
    uint16_t pan_version;
    ws_bs_ie_t ws_bs_ie;
    ws_bt_ie_t ws_bt_ie;

    if (data->SrcPANId != cur->ws_info.network_pan_id)
        return;
    if (!ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_bt_ie)) {
        WARN("Received corrupted PAN config: no broadcast timing information");
        return;
    }
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_bs_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ws_bs_ie)) {
        WARN("Received corrupted PAN config: no broadcast schedule information");
        return;
    }
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_panver_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &pan_version)) {
        WARN("Received corrupted PAN config: no PAN version");
        return;
    }
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_gtkhash_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, gtkhash)) {
        WARN("Received corrupted PAN config: no GTK hash");
        return;
    }

    // TODO Add this to neighbor table
    // TODO save all information from config message if version number has changed

    llc_neighbour_req_t neighbor_info;
    bool neighbour_pointer_valid;

    //Validate BSI
    if (cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {

        if (cur->ws_info.ws_bsi_block.block_time && cur->ws_info.ws_bsi_block.old_bsi == ws_bs_ie.broadcast_schedule_identifier) {
            tr_debug("Do not accept a old BSI: %u in time %"PRIu32, cur->ws_info.ws_bsi_block.old_bsi, cur->ws_info.ws_bsi_block.block_time);
            //Refresh Block time when hear a old BSI
            cur->ws_info.ws_bsi_block.block_time = cur->ws_info.cfg->timing.pan_timeout;
            return;
        }

        //When Config is learned and USE Parent BS is enabled compare is this new BSI
        if (cur->ws_info.configuration_learned && cur->ws_info.pan_information.use_parent_bs && ws_bs_ie.broadcast_schedule_identifier != cur->ws_info.hopping_schedule.fhss_bsi) {
            //Accept only next possible BSI number
            if ((cur->ws_info.hopping_schedule.fhss_bsi + 1) != ws_bs_ie.broadcast_schedule_identifier) {
                tr_debug("Do not accept a unknown BSI: %u", ws_bs_ie.broadcast_schedule_identifier);
            } else {
                tr_debug("NEW Brodcast Schedule %u...BR rebooted", ws_bs_ie.broadcast_schedule_identifier);
                cur->ws_info.ws_bsi_block.block_time = cur->ws_info.cfg->timing.pan_timeout;
                cur->ws_info.ws_bsi_block.old_bsi = cur->ws_info.hopping_schedule.fhss_bsi;
                ws_bootstrap_event_disconnect(cur, WS_NORMAL_DISCONNECT);
            }
            return;
        }
    }


    if (cur->ws_info.configuration_learned || cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        //If we are border router or learned configuration we only update already learned neighbours.
        neighbour_pointer_valid = ws_bootstrap_neighbor_get(cur, data->SrcAddr, &neighbor_info);

    } else {
        neighbour_pointer_valid = ws_bootstrap_neighbor_get(cur, data->SrcAddr, &neighbor_info);
        if (!neighbour_pointer_valid)
            neighbour_pointer_valid = ws_bootstrap_neighbor_add(cur, data->SrcAddr, &neighbor_info, WS_NR_ROLE_ROUTER);
        if (!neighbour_pointer_valid)
            return;
        ws_bootstrap_neighbor_set_stable(cur, data->SrcAddr);
    }

    if (neighbour_pointer_valid) {
        //Update Neighbor Broadcast and Unicast Parameters
        ws_neighbor_class_ut_update(neighbor_info.ws_neighbor, ws_utt->ufsi, data->timestamp, data->SrcAddr);
        ws_neighbor_class_bt_update(neighbor_info.ws_neighbor, ws_bt_ie.broadcast_slot_number,
                                    ws_bt_ie.broadcast_interval_offset, data->timestamp);
        ws_neighbor_class_us_update(cur, neighbor_info.ws_neighbor, &ws_us->chan_plan, ws_us->dwell_interval, data->SrcAddr);
        ws_neighbor_class_bs_update(cur, neighbor_info.ws_neighbor, &ws_bs_ie.chan_plan, ws_bs_ie.dwell_interval,
                                    ws_bs_ie.broadcast_interval, ws_bs_ie.broadcast_schedule_identifier);
    }

    if (cur->ws_info.configuration_learned) {
        if (cur->ws_info.pan_information.pan_version == pan_version) {
            // Same version heard so it is consistent
            trickle_consistent_heard(&cur->ws_info.mngt.trickle_pc);

            if (neighbour_pointer_valid && neighbor_info.neighbor->link_role == PRIORITY_PARENT_NEIGHBOUR) {
                ws_bootstrap_primary_parent_set(cur, &neighbor_info, WS_PARENT_SOFT_SYNCH);
            }
            // no need to process more
            ws_bootstrap_ffn_pan_config_lfn_analyze(cur, ie_ext);
            return;
        } else  {
            // received version is different so we need to reset the trickle
            trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params);
            if (neighbour_pointer_valid && neighbor_info.neighbor->link_role == PRIORITY_PARENT_NEIGHBOUR) {
                ws_bootstrap_primary_parent_set(cur, &neighbor_info, WS_PARENT_HARD_SYNCH);
            }
            if (serial_number_cmp16(cur->ws_info.pan_information.pan_version, pan_version)) {
                // older version heard ignoring the message
                return;
            }
        }
    }

    if (cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        //Border router does not learn network information
        return;
    }

    /*
     * Learn new information from neighbor
     */
    tr_info("Updated PAN configuration own:%d, heard:%d", cur->ws_info.pan_information.pan_version, pan_version);

    // restart PAN version timer
    //Check Here Do we have a selected Primary parent
    if (!cur->ws_info.configuration_learned || cur->ws_info.rpl_state == RPL_EVENT_DAO_DONE) {
        ws_common_border_router_alive_update(cur);
    }

    cur->ws_info.pan_information.pan_version = pan_version;

    ws_pae_controller_gtk_hash_update(cur, gtkhash);

    ws_pae_controller_nw_key_index_update(cur, data->Key.KeyIndex - 1);

    ws_bootstrap_ffn_pan_config_lfn_analyze(cur, ie_ext);

    if (!cur->ws_info.configuration_learned) {
        // Generate own hopping schedules Follow first parent broadcast and plans and also use same unicast dwell
        tr_info("learn network configuration");
        cur->ws_info.configuration_learned = true;
        // return to state machine after 1-2 s
        cur->bootstrap_state_machine_cnt = rand_get_random_in_range(10, 20);
        // enable frequency hopping for unicast channel and start listening first neighbour
        ws_bootstrap_primary_parent_set(cur, &neighbor_info, WS_PARENT_HARD_SYNCH);
        // set neighbor as priority parent clear if there is others
        protocol_6lowpan_neighbor_priority_clear_all(cur->id, PRIORITY_1ST);
        neighbor_info.neighbor->link_role = PRIORITY_PARENT_NEIGHBOUR;
    }
}

static void ws_bootstrap_ffn_pan_config_solicit_analyse(struct net_if *cur, const struct mcps_data_ind *data, ws_utt_ie_t *ws_utt, ws_us_ie_t *ws_us)
{
    if (data->SrcPANId != cur->ws_info.network_pan_id) {
        return;
    }

    /* TODO smart neighbour process
     *
     * Unsecure packet we cant trust the device?
     *
     * Question mark in specification also present, now we create neighbour.
     * this is moved in future to NS/ND processing triggered by RPL
     *
     */

    llc_neighbour_req_t neighbor_info;
    if (ws_bootstrap_neighbor_get(cur, data->SrcAddr, &neighbor_info)) {
        ws_neighbor_class_ut_update(neighbor_info.ws_neighbor, ws_utt->ufsi, data->timestamp, data->SrcAddr);
        ws_neighbor_class_us_update(cur, neighbor_info.ws_neighbor, &ws_us->chan_plan, ws_us->dwell_interval, data->SrcAddr);
    }

    if (ws_bootstrap_state_active(cur) && cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_address_discover(cur->mac_parameters.mac_neighbor_table, data->SrcAddr, ADDR_802_15_4_LONG);
        if (neighbor && neighbor->link_role == PRIORITY_PARENT_NEIGHBOUR) {
            ws_bootstrap_parent_confirm(cur, NULL);
        }
    }

    /*
     * A consistent transmission is defined as a PAN Configuration Solicit with
     * a PAN-ID matching that of the receiving node and a NETNAME-IE / Network Name
     * matching that configured on the receiving node.
     */
    trickle_consistent_heard(&cur->ws_info.mngt.trickle_pcs);
    /*
     *  inconsistent transmission is defined as either:
     *  A PAN Configuration Solicit with a PAN-ID matching that of the receiving node and
     *  a NETNAME-IE / Network Name matching the network name configured on the receiving
     */
    trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params);
}

static bool ws_bootstrap_network_name_matches(const struct mcps_data_ie_list *ie_ext, const char *network_name_ptr)
{
    ws_wp_netname_t network_name;

    if (!network_name_ptr || !ie_ext) {
        return false;
    }

    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_netname_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &network_name)) {
        tr_warn("No network name IE");
        return false;
    }

    if (network_name.network_name_length != strlen(network_name_ptr)) {
        return false;
    }

    if (strncmp(network_name_ptr, (char *)network_name.network_name, network_name.network_name_length) != 0) {
        return false;
    }

    // names have equal length and same characters
    return true;
}

void ws_bootstrap_ffn_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type)
{
    // Store weakest heard packet RSSI
    if (cur->ws_info.weakest_received_rssi > data->signal_dbm) {
        cur->ws_info.weakest_received_rssi = data->signal_dbm;
    }

    if (data->SrcAddrMode != MAC_ADDR_MODE_64_BIT) {
        // Not from long address
        return;
    }
    ws_stats_update(cur, STATS_WS_ASYNCH_RX, 1);
    //Validate network name
    switch (message_type) {
        case WS_FT_PA:
        case WS_FT_PAS:
        case WS_FT_PCS:
        case WS_FT_LPA:
        case WS_FT_LPAS:
        case WS_FT_LPCS:
            //Check Network Name
            if (!ws_bootstrap_network_name_matches(ie_ext, cur->ws_info.cfg->gen.network_name)) {
                // Not in our network
                return;
            }
            break;
        case WS_FT_PC:
        case WS_FT_LPC:
            break;
        default:
            return;
    }
    //UTT-IE and US-IE are mandatory for all Asynch Messages
    ws_utt_ie_t ws_utt;
    if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_utt)) {
        // Corrupted
        return;
    }

    ws_us_ie_t ws_us;
    // FIXME: see comment in ws_llc_mngt_ind
    if (!ws_wp_nested_us_read(ie_ext->payloadIeList, ie_ext->payloadIeListLength, &ws_us)) {
        // Corrupted
        return;
    }

    if (!ws_ie_validate_us(&cur->ws_info, &ws_us))
        return;

    //Handle Message's
    switch (message_type) {
        case WS_FT_PA:
            // Analyse Advertisement
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PA, 1);
            ws_bootstrap_ffn_pan_advertisement_analyse(cur, data, ie_ext, &ws_utt, &ws_us);
            break;
        case WS_FT_PAS:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PAS, 1);
            ws_bootstrap_ffn_pan_advertisement_solicit_analyse(cur, data, &ws_utt, &ws_us);
            break;
        case WS_FT_PC:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PC, 1);
            ws_bootstrap_ffn_pan_config_analyse(cur, data, ie_ext, &ws_utt, &ws_us);
            break;
        case WS_FT_PCS:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PCS, 1);
            ws_bootstrap_ffn_pan_config_solicit_analyse(cur, data, &ws_utt, &ws_us);
            break;
        case WS_FT_LPA:
        case WS_FT_LPAS:
        case WS_FT_LPCS:
        case WS_FT_LPC:
            tr_warn("LFN messages are not yet supported");
        default:
            // Unknown message do not process
            break;
    }
}

void ws_bootstrap_ffn_asynch_confirm(struct net_if *interface, uint8_t asynch_message)
{
    if (asynch_message == WS_FT_PA)
        interface->pan_advert_running = false;
    else if (asynch_message == WS_FT_PC)
        interface->pan_config_running = false;
    ws_stats_update(interface, STATS_WS_ASYNCH_TX, 1);
}

void ws_bootstrap_ffn_event_handler(struct net_if *cur, struct event_payload *event)
{
    ws_bootstrap_event_type_e event_type;
    event_type = (ws_bootstrap_event_type_e)event->event_type;

    switch (event_type) {
        case WS_INIT_EVENT:
            tr_debug("Tasklet init");
            break;
        case WS_DISCOVERY_START:
            tr_info("Discovery start");
            rcp_reset_stack();
            ws_llc_reset(cur);
            lowpan_adaptation_interface_reset(cur->id);
            //Clear Pending Key Index State
            cur->ws_info.pending_key_index_info.state = NO_PENDING_PROCESS;
            cur->mac_parameters.mac_default_ffn_key_index = 0;

            ipv6_destination_cache_clean(cur->id);

            // Clear parent blacklist
            blacklist_clear();

            // All trickle timers stopped to allow entry from any state
            ws_bootstrap_asynch_trickle_stop(cur);
            //Init Packet congestion
            ws_bootstrap_packet_congestion_init(cur);

            ws_pae_controller_supp_init(cur);
            // Clear learned neighbours
            ws_bootstrap_neighbor_list_clean(cur);
            // Configure LLC for network discovery
            ws_bootstrap_ffn_network_discovery_configure(cur);
            ws_bootstrap_fhss_activate(cur);

            rcp_set_max_mac_retry(WS_MAX_FRAME_RETRIES_BOOTSTRAP);
            rcp_set_max_rf_retry(WS_CCA_REQUEST_RESTART_MAX, WS_TX_REQUEST_RESTART_MAX_BOOTSTRAP, WS_REQUEST_RESTART_BLACKLIST_MIN, WS_REQUEST_RESTART_BLACKLIST_MAX);
            rcp_set_max_csma_backoffs(WS_MAX_CSMA_BACKOFFS);
            rcp_set_min_be(WS_MAC_MIN_BE);
            rcp_set_max_be(WS_MAC_MAX_BE);
            // Start network scan
            ws_bootstrap_ffn_start_discovery(cur);
            break;

        case WS_CONFIGURATION_START:
            tr_info("Configuration start");
            // Old configuration is considered invalid stopping all
            ws_bootstrap_asynch_trickle_stop(cur);

            // Build list of possible neighbours and learn first broadcast schedule

            ws_bootstrap_ffn_start_configuration_learn(cur);
            break;
        case WS_OPERATION_START:
            tr_info("Operation start");
            // Advertisements stopped during the RPL scan
            ws_bootstrap_asynch_trickle_stop(cur);
            // Activate RPL
            // Activate IPv6 stack
            ws_bootstrap_ip_stack_activate(cur);
            ws_bootstrap_rpl_activate(cur);
            ws_bootstrap_network_start(cur);
            // Wait for RPL start
            ws_bootstrap_rpl_scan_start(cur);
            /* While in Join State 4, if a non Border Router determines it has been unable to communicate with the PAN Border
             * Router for an interval of PAN_TIMEOUT, a node MUST assume failure of the PAN Border Router and MUST
             * Transition to Join State 1
             */
            ws_common_border_router_alive_update(cur);
            break;
        case WS_ROUTING_READY:
            tr_info("Routing ready");
            // stopped all to make sure we can enter here from any state
            ws_bootstrap_asynch_trickle_stop(cur);

            // Indicate PAE controller that bootstrap is ready
            ws_pae_controller_bootstrap_done(cur);

            ws_bootstrap_advertise_start(cur);
            ws_bootstrap_state_change(cur, ER_BOOTSTRAP_DONE);
            break;
        case WS_FAST_DISCONNECT:
            ws_bootstrap_state_disconnect(cur, WS_FAST_DISCONNECT);
            break;
        case WS_NORMAL_DISCONNECT:
            ws_bootstrap_state_disconnect(cur, WS_NORMAL_DISCONNECT);
            break;

        case WS_TEST_PROC_TRIGGER:
            ws_bootstrap_test_procedure_trigger_exec(cur, (ws_bootstrap_procedure_e) event->data_ptr);
            break;

        default:
            tr_error("Invalid event received");
            break;
    }
}

/*
 * Statemachine state functions
 * */

static void ws_bootstrap_ffn_network_scan_process(struct net_if *cur)
{

    parent_info_t *selected_parent_ptr;

    tr_debug("analyze network discovery result");

select_best_candidate:
    selected_parent_ptr = ws_bootstrap_ffn_candidate_parent_get_best(cur);

    if (!selected_parent_ptr) {
        // Configure LLC for network discovery
        ws_bootstrap_ffn_network_discovery_configure(cur);
        // randomize new channel and start MAC
        ws_bootstrap_fhss_activate(cur);
        // Next check will be after one trickle
        uint32_t random_start = cur->ws_info.mngt.trickle_params.Imin + rand_get_random_in_range(0, cur->ws_info.mngt.trickle_params.Imin);
        if (random_start > 0xffff) {
            random_start = 0xffff;
        }
        cur->bootstrap_state_machine_cnt = random_start;

        tr_info("Making parent selection in %u s", (cur->bootstrap_state_machine_cnt / 10));
        return;
    }
    tr_info("selected parent:%s panid %u", tr_eui64(selected_parent_ptr->addr), selected_parent_ptr->pan_id);

    if (ws_bootstrap_ffn_neighbor_set(cur, selected_parent_ptr, false) < 0) {
        goto select_best_candidate;
    }

    ws_pae_controller_set_target(cur, selected_parent_ptr->pan_id, selected_parent_ptr->addr); // temporary!!! store since auth
    ws_bootstrap_event_authentication_start(cur);
    return;
}

static void ws_bootstrap_ffn_configure_process(struct net_if *cur)
{

    if (cur->ws_info.configuration_learned) {
        tr_debug("Start using PAN configuration");
        ws_bootstrap_event_operation_start(cur);
        return;
    }
    return;
}

void ws_bootstrap_ffn_rpl_wait_process(struct net_if *cur)
{

    if (cur->ws_info.rpl_state == RPL_EVENT_DAO_DONE) {
        // RPL routing is ready
        cur->ws_info.connected_time = cur->ws_info.uptime;
        ws_bootstrap_event_routing_ready(cur);
    } else if (!rpl_control_have_dodag(cur->rpl_domain)) {
        // RPL not ready send DIS message if possible
        if (cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_ROUTER) {
            // TODO Multicast DIS should be sent only if no DIO heard for some time
            rpl_control_transmit_dis(cur->rpl_domain, cur, 0, 0, NULL, 0, ADDR_LINK_LOCAL_ALL_RPL_NODES);
        }
        // set timer for next DIS
        cur->bootstrap_state_machine_cnt = rand_get_random_in_range(WS_RPL_DIS_TIMEOUT / 2, WS_RPL_DIS_TIMEOUT);
    }
    return;
}

static void ws_bootstrap_ffn_start_authentication(struct net_if *cur)
{
    // Set PAN ID and network name to controller
    ws_pae_controller_nw_info_set(cur, cur->ws_info.network_pan_id,
                                  cur->ws_info.pan_information.pan_version,
                                  cur->ws_info.pan_information.lpan_version,
                                  cur->ws_info.cfg->gen.network_name);

    ws_pae_controller_authenticate(cur);
}

/*
 * State machine
 */

void ws_bootstrap_ffn_state_machine(struct net_if *cur)
{

    switch (cur->nwk_bootstrap_state) {
        case ER_WAIT_RESTART:
            tr_debug("WS SM:Wait for startup");
            ws_bootstrap_event_discovery_start(cur);
            break;
        case ER_ACTIVE_SCAN:
            tr_debug("WS SM:Active Scan");
            ws_bootstrap_ffn_network_scan_process(cur);
            break;
        case ER_SCAN:
            tr_debug("WS SM:configuration Scan");
            ws_bootstrap_ffn_configure_process(cur);
            break;
        case ER_PANA_AUTH:
            tr_info("authentication start");
            // Advertisements stopped during the EAPOL
            ws_bootstrap_asynch_trickle_stop(cur);
            ws_bootstrap_ffn_fhss_configure(cur, false);
            int8_t new_default = cur->ws_info.weakest_received_rssi - 1;
            if ((new_default < CCA_DEFAULT_DBM) && (new_default >= CCA_LOW_LIMIT) && (new_default <= CCA_HIGH_LIMIT)) {
                // Restart automatic CCA threshold using weakest received RSSI as new default
                rcp_set_cca_threshold(cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.weakest_received_rssi - 1, CCA_HIGH_LIMIT, CCA_LOW_LIMIT);
            }
            ws_bootstrap_ffn_start_authentication(cur);
            break;
        case ER_RPL_SCAN:
            tr_debug("WS SM:Wait RPL to contact DODAG root");
            ws_bootstrap_ffn_rpl_wait_process(cur);
            break;
        case ER_BOOTSTRAP_DONE:
            tr_info("WS SM:Bootstrap Done");
            // Bootstrap_done event to application
            nwk_bootstrap_state_update(ARM_NWK_BOOTSTRAP_READY, cur);
            break;
        case ER_RPL_NETWORK_LEAVING:
            tr_debug("WS SM:RPL Leaving ready trigger discovery");
            ws_bootstrap_event_discovery_start(cur);
            break;
        default:
            tr_warn("WS SM:Invalid state %d", cur->nwk_bootstrap_state);
    }
}

void ws_bootstrap_ffn_seconds_timer(struct net_if *cur, uint32_t seconds)
{
    /* Border router keep alive check
     */
    if (cur->ws_info.pan_timeout_timer) {
        // PAN version timer running
        if (cur->ws_info.pan_timeout_timer > seconds) {
            cur->ws_info.pan_timeout_timer -= seconds;
            if (cur->ws_info.pan_timeout_timer < cur->ws_info.cfg->timing.pan_timeout / 10) {
                /* pan timeout is closing need to verify that DAO is tested before the pan times out.
                   This will give some extra time for RPL to find better parents.
                   Border router liveliness can be checked from version number change or from successful DAO registrations
                   in this case there has not been any version number changes during this PAN lifetime.
                */
                rpl_control_dao_timeout(cur->rpl_domain, 20);
            }
        } else {
            // Border router has timed out
            //Clear Timeout timer
            cur->ws_info.pan_timeout_timer = 0;
            tr_warn("Border router has timed out");
            ws_bootstrap_event_disconnect(cur, WS_FAST_DISCONNECT);
        }
    }
    if (cur->ws_info.aro_registration_timer) {
        if (cur->ws_info.aro_registration_timer > seconds) {
            cur->ws_info.aro_registration_timer -= seconds;
        } else {
            // Update all addressess. This function will update the timer value if needed
            cur->ws_info.aro_registration_timer = 0;
            ws_address_registration_update(cur, NULL);
        }
    }

    if (cur->ws_info.ws_bsi_block.block_time) {
        if (cur->ws_info.ws_bsi_block.block_time > seconds) {
            cur->ws_info.ws_bsi_block.block_time -= seconds;
        } else {
            //Clear A BSI blokker
            cur->ws_info.ws_bsi_block.block_time = 0;
            cur->ws_info.ws_bsi_block.old_bsi = 0;
        }
    }
}

void ws_bootstrap_ffn_eapol_parent_synch(struct net_if *cur, llc_neighbour_req_t *neighbor_info)
{
    BUG_ON(cur->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER);
    if (cur->ws_info.configuration_learned || !neighbor_info->ws_neighbor->broadcast_schedule_info_stored || !neighbor_info->ws_neighbor->broadcast_timing_info_stored) {
        return;
    }

    if (ws_bootstrap_ffn_candidate_parent_get(cur, neighbor_info->neighbor->mac64, false) == NULL) {
        return;
    }

    //Store Brodacst Shedule
    if (!neighbor_info->ws_neighbor->synch_done) {
        ws_bootstrap_primary_parent_set(cur, neighbor_info, WS_EAPOL_PARENT_SYNCH);
    } else {
        cur->ws_info.fhss_conf.fhss_bc_dwell_interval  = neighbor_info->ws_neighbor->fhss_data.ffn.bc_dwell_interval_ms;
        cur->ws_info.fhss_conf.fhss_broadcast_interval = neighbor_info->ws_neighbor->fhss_data.ffn.bc_interval_ms;
        rcp_set_fhss_parent(neighbor_info->neighbor->mac64, &neighbor_info->ws_neighbor->fhss_data, false);
    }
}

const uint8_t *ws_bootstrap_authentication_next_target(struct net_if *cur, const uint8_t *previous_eui_64, uint16_t *pan_id)
{
    ws_bootstrap_ffn_candidate_parent_mark_failure(cur, previous_eui_64);

    // Gets best target
    parent_info_t *parent_info = ws_bootstrap_ffn_candidate_parent_get_best(cur);
    if (parent_info) {
        /* On failure still continues with the new parent, and on next call,
           will try to set the neighbor again */
        ws_bootstrap_ffn_neighbor_set(cur, parent_info, true);
        *pan_id = parent_info->pan_id;
        return parent_info->addr;
    }

    // If no targets found, retries the last one
    return previous_eui_64;
}

void ws_bootstrap_authentication_completed(struct net_if *cur, auth_result_e result, uint8_t *target_eui_64)
{
    if (result == AUTH_RESULT_OK) {
        tr_info("authentication success eui64:%s", tr_eui64(target_eui_64));
        if (target_eui_64) {
            // Authentication was made contacting the authenticator
            cur->ws_info.authentication_time = cur->ws_info.uptime;
        }
        ws_bootstrap_event_configuration_start(cur);
    } else if (result == AUTH_RESULT_ERR_TX_ERR) {
        // eapol parent selected is not working
        tr_debug("authentication TX failed");

        ws_bootstrap_ffn_candidate_parent_mark_failure(cur, target_eui_64);
        // Go back for network scanning
        ws_bootstrap_state_change(cur, ER_ACTIVE_SCAN);

        // Start PAS interval between imin - imax.
        cur->ws_info.mngt.trickle_pas_running = true;
        trickle_start(&cur->ws_info.mngt.trickle_pas, "ADV SOL", &cur->ws_info.mngt.trickle_params);

        // Parent selection is made before imin/2 so if there is parent candidates solicit is not sent
        cur->bootstrap_state_machine_cnt = rand_get_random_in_range(10, cur->ws_info.mngt.trickle_params.Imin >> 1);
        tr_info("Making parent selection in %u s", (cur->bootstrap_state_machine_cnt / 10));
    } else {
        tr_debug("authentication failed");
        // What else to do to start over again...
        // Trickle is reseted when entering to discovery from state 2
        trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pas, &cur->ws_info.mngt.trickle_params);
        ws_bootstrap_event_discovery_start(cur);
    }
}

void ws_ffn_trickle_stop(struct ws_mngt *mngt)
{
    mngt->trickle_pas_running = false;
    mngt->trickle_pcs_running = false;
}

static void ws_bootstrap_pan_advert_solicit(struct net_if *cur)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PAS,
        .wh_ies.utt     = true,
        .wp_ies.us      = true,
        .wp_ies.netname = true,
        .wp_ies.pom     = ws_version_1_1(cur),
    };

    ws_stats_update(cur, STATS_WS_ASYNCH_TX_PAS, 1);
    ws_llc_asynch_request(cur, &req);
}

void ws_ffn_pas_trickle(struct net_if *cur, int ticks)
{
    if (cur->ws_info.mngt.trickle_pas_running &&
            trickle_timer(&cur->ws_info.mngt.trickle_pas, &cur->ws_info.mngt.trickle_params, ticks)) {
        // send PAN advertisement solicit
        ws_bootstrap_pan_advert_solicit(cur);
    }
}

void ws_ffn_pas_test_exec(struct net_if *cur, int procedure)
{
    tr_info("trigger PAN advertisement Solicit");
    if (procedure != PROCEDURE_PAS_TRICKLE_INCON) {
        tr_info("send PAN advertisement Solicit");
        ws_bootstrap_pan_advert_solicit(cur);
    }
    if (cur->ws_info.mngt.trickle_pas_running) {
        trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pas, &cur->ws_info.mngt.trickle_params);
    }
}

void ws_ffn_pas_test_trigger(struct net_if *cur, int seconds)
{
    if (cur->ws_info.mngt.trickle_pas_running) {
        if (cur->ws_info.test_proc_trg.pas_trigger_timer > seconds) {
            cur->ws_info.test_proc_trg.pas_trigger_timer -= seconds;
        } else  {
            if (cur->ws_info.test_proc_trg.pas_trigger_count > 2) {
                ws_bootstrap_test_procedure_trigger_exec(cur, PROCEDURE_PAS_TRICKLE_INCON);
            } else {
                cur->ws_info.test_proc_trg.pas_trigger_count++;
                ws_bootstrap_test_procedure_trigger_exec(cur, PROCEDURE_PAS);
            }
            cur->ws_info.test_proc_trg.pas_trigger_timer = (cur->ws_info.mngt.trickle_params.Imin / 10);
        }
        if (cur->ws_info.test_proc_trg.eapol_trigger_timer > seconds) {
            cur->ws_info.test_proc_trg.eapol_trigger_timer -= seconds;
        } else {
            ws_bootstrap_test_procedure_trigger_exec(cur, PROCEDURE_EAPOL);
            cur->ws_info.test_proc_trg.eapol_trigger_timer = (cur->ws_info.mngt.trickle_params.Imin / 10) / 2;
        }
    }
}

static void ws_bootstrap_pan_config_solicit(struct net_if *cur)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PCS,
        .wh_ies.utt     = true,
        .wp_ies.us      = true,
        .wp_ies.netname = true,
    };

    ws_stats_update(cur, STATS_WS_ASYNCH_TX_PCS, 1);
    ws_llc_asynch_request(cur, &req);
}

void ws_ffn_pcs_trickle(struct net_if *cur, int ticks)
{
    if (cur->ws_info.mngt.trickle_pcs_running) {

        //Update MAX config sol timeout timer
        if (cur->ws_info.mngt.pcs_max_timeout > ticks) {
            cur->ws_info.mngt.pcs_max_timeout -= ticks;
        } else {
            //Config sol state timeout
            cur->ws_info.mngt.pcs_max_timeout = 0;
        }

        if (trickle_timer(&cur->ws_info.mngt.trickle_pcs, &cur->ws_info.mngt.trickle_params, ticks)) {
            if (cur->ws_info.mngt.pcs_count < PCS_MAX) {
                // send PAN Configuration solicit
                ws_bootstrap_pan_config_solicit(cur);
            }
            //Update counter every time reason that we detect PCS_MAX higher state
            cur->ws_info.mngt.pcs_count++;
        }

        if (cur->ws_info.mngt.pcs_count > PCS_MAX || cur->ws_info.mngt.pcs_max_timeout == 0) {
            // if MAX PCS sent or max waited timeout restart discovery
            // Trickle is reseted when entering to discovery from state 3
            tr_info("PAN configuration Solicit timeout");
            trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pas, &cur->ws_info.mngt.trickle_params);
            ws_bootstrap_event_discovery_start(cur);
            return;
        }
    }
}

void ws_ffn_pcs_test_exec(struct net_if *cur, int procedure)
{
    if (cur->ws_info.mngt.trickle_pcs_running || ws_bootstrap_state_active(cur)) {
        tr_info("trigger PAN configuration Solicit");
        if (procedure != PROCEDURE_PCS_TRICKLE_INCON) {
            tr_info("send PAN configuration Solicit");
            ws_bootstrap_pan_config_solicit(cur);
        }
        if (cur->ws_info.mngt.trickle_pcs_running) {
            trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pcs, &cur->ws_info.mngt.trickle_params);
        }
    } else {
        tr_info("wrong state: PAN configuration Solicit not triggered");
    }
}

void ws_ffn_pcs_test_trigger(struct net_if *cur, int seconds)
{
    if (cur->ws_info.mngt.trickle_pcs_running) {
        if (cur->ws_info.test_proc_trg.pcs_trigger_timer > seconds) {
            cur->ws_info.test_proc_trg.pcs_trigger_timer -= seconds;
        } else  {
            if (cur->ws_info.test_proc_trg.pcs_trigger_count > 2) {
                ws_bootstrap_test_procedure_trigger_exec(cur, PROCEDURE_PCS_TRICKLE_INCON);
            } else {
                cur->ws_info.test_proc_trg.pcs_trigger_count++;
                ws_bootstrap_test_procedure_trigger_exec(cur, PROCEDURE_PCS);
            }
            cur->ws_info.test_proc_trg.pcs_trigger_timer = (cur->ws_info.mngt.trickle_params.Imin / 10);
        }
    }
}
