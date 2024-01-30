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
#include <inttypes.h>
#include "common/bits.h"
#include "common/log.h"
#include "common/rand.h"
#include "common/ws_regdb.h"
#include "common/trickle.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/mathutils.h"
#include "common/time_extra.h"
#include "common/string_extra.h"
#include "common/version.h"
#include "common/events_scheduler.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ws.h"
#include "service_libs/random_early_detection/random_early_detection.h"

#include "app_wsbrd/dbus.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/rcp_api_legacy.h"
#include "core/ns_address_internal.h"
#include "core/timers.h"
#include "nwk_interface/protocol.h"
#include "ipv6_stack/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "common_protocols/icmpv6.h"
#include "common/specs/ipv6.h"
#include "common/specs/ip.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/nd/nd_router_object.h"

#include "6lowpan/ws/ws_bbr_api.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_eapol_auth_relay.h"
#include "6lowpan/ws/ws_eapol_pdu.h"
#include "6lowpan/ws/ws_eapol_relay.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_management_api.h"
#include "6lowpan/ws/ws_neigh.h"
#include "6lowpan/ws/ws_pae_controller.h"

#include "6lowpan/ws/ws_bootstrap.h"

#define TRACE_GROUP "wsbs"

static void ws_bootstrap_neighbor_delete(struct net_if *interface, struct ws_neigh *neighbor)
{
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_legacy_drop_fhss_neighbor(neighbor->mac64);
    if (version_older_than(interface->rcp->version_api, 2, 0, 0))
        rcp_legacy_set_neighbor(neighbor->index, 0, 0, NULL, 0);
    ws_neigh_del(&interface->ws_info.neighbor_storage, neighbor->mac64);
    if (!ws_neigh_lfn_count(&interface->ws_info.neighbor_storage))
        ws_timer_stop(WS_TIMER_LTS);
}

void ws_bootstrap_llc_hopping_update(struct net_if *cur, const fhss_ws_configuration_t *fhss_configuration)
{
    cur->ws_info.hopping_schedule.uc_fixed_channel = fhss_configuration->unicast_fixed_channel;
    cur->ws_info.hopping_schedule.bc_fixed_channel = fhss_configuration->broadcast_fixed_channel;
    // Read UC channel function from WS info because FHSS might be temporarily configured to fixed channel during discovery.
    cur->ws_info.hopping_schedule.uc_channel_function = cur->ws_info.cfg->fhss.fhss_uc_channel_function;
    cur->ws_info.hopping_schedule.bc_channel_function = fhss_configuration->ws_bc_channel_function;
    cur->ws_info.hopping_schedule.fhss_bc_dwell_interval = fhss_configuration->fhss_bc_dwell_interval;
    cur->ws_info.hopping_schedule.fhss_broadcast_interval = fhss_configuration->fhss_broadcast_interval;
    cur->ws_info.hopping_schedule.fhss_uc_dwell_interval = fhss_configuration->fhss_uc_dwell_interval;
    cur->ws_info.hopping_schedule.fhss_bsi = fhss_configuration->bsi;
}

/**
 * @param chan_excl is filled with a list of excluded channels to be advertised
 *   in a schedule IE (US,BS,LCP)
 * @param chan_mask_custom is a user provided list of channels to use, ones not
 *   allowed by the regulation are ignored
 * @param chan_mask_reg is the list of active channels defined by the Wi-SUN
 *   PHY specification based on the configuration parameters (regulatory domain
 *   and class/ChanPlanId)
 */
static void ws_bootstrap_calc_chan_excl(ws_excluded_channel_data_t *chan_excl, const uint8_t chan_mask_custom[],
                                        const uint8_t chan_mask_reg[], uint16_t chan_count)
{
    bool in_range = false;
    int range_cnt = 0;

    memset(chan_excl, 0, sizeof(ws_excluded_channel_data_t));
    for (uint16_t i = 0; i < chan_count; i++) {
        if (!bittest(chan_mask_reg, i) || bittest(chan_mask_custom, i)) {
            if (in_range)
                in_range = false;
            continue;
        }

        bitset(chan_excl->channel_mask, i);
        chan_excl->excluded_channel_count++;

        if (!in_range) {
            in_range = true;
            range_cnt++;
            if (range_cnt < WS_EXCLUDED_MAX_RANGE_TO_SEND) {
                chan_excl->excluded_range[range_cnt - 1].range_start = i;
                chan_excl->excluded_range_length = range_cnt;
            }
        }
        if (range_cnt <= WS_EXCLUDED_MAX_RANGE_TO_SEND)
            chan_excl->excluded_range[range_cnt - 1].range_end = i;
    }
    chan_excl->channel_mask_bytes_inline = roundup(chan_count, 8) / 8;

    if (!range_cnt)
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_NONE;
    else if (range_cnt <= WS_EXCLUDED_MAX_RANGE_TO_SEND &&
             1 + range_cnt * 4 < chan_excl->channel_mask_bytes_inline)
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_RANGE;
    else
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_BITMASK;
}

void ws_bootstrap_fhss_configure_channel_masks(struct net_if *cur, fhss_ws_configuration_t *fhss_configuration)
{
    fhss_configuration->channel_mask_size = cur->ws_info.hopping_schedule.number_of_channels;
    ws_common_generate_channel_list(cur, fhss_configuration->domain_channel_mask, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.hopping_schedule.regulatory_domain, cur->ws_info.hopping_schedule.operating_class, cur->ws_info.hopping_schedule.channel_plan_id);
    ws_common_generate_channel_list(cur, fhss_configuration->unicast_channel_mask, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.hopping_schedule.regulatory_domain, cur->ws_info.hopping_schedule.operating_class, cur->ws_info.hopping_schedule.channel_plan_id);
    // using bitwise AND operation for user set channel mask to remove channels not allowed in this device
    bitand(fhss_configuration->unicast_channel_mask, cur->ws_info.cfg->fhss.fhss_channel_mask, 256);
    ws_bootstrap_calc_chan_excl(&cur->ws_info.hopping_schedule.uc_excluded_channels,
                                fhss_configuration->unicast_channel_mask,
                                fhss_configuration->domain_channel_mask,
                                cur->ws_info.hopping_schedule.number_of_channels);
    ws_common_generate_channel_list(cur, fhss_configuration->broadcast_channel_mask, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.hopping_schedule.regulatory_domain, cur->ws_info.hopping_schedule.operating_class, cur->ws_info.hopping_schedule.channel_plan_id);
    bitand(fhss_configuration->broadcast_channel_mask, cur->ws_info.cfg->fhss.fhss_channel_mask, 256);
    ws_bootstrap_calc_chan_excl(&cur->ws_info.hopping_schedule.bc_excluded_channels,
                                fhss_configuration->broadcast_channel_mask,
                                fhss_configuration->domain_channel_mask,
                                cur->ws_info.hopping_schedule.number_of_channels);
}

static int8_t ws_bootstrap_fhss_initialize(struct net_if *cur)
{
    // When FHSS doesn't exist yet, create one
    ws_bootstrap_fhss_configure_channel_masks(cur, &cur->ws_info.fhss_conf);
    ws_bootstrap_fhss_set_defaults(cur, &cur->ws_info.fhss_conf);
    if (version_older_than(cur->rcp->version_api, 2, 0, 0)) {
        rcp_legacy_allocate_fhss(&cur->ws_info.fhss_conf);
        rcp_legacy_register_fhss();
        rcp_legacy_set_tx_allowance_level(WS_TX_AND_RX_SLOT, WS_TX_AND_RX_SLOT);
    }
    return 0;
}

int8_t ws_bootstrap_fhss_set_defaults(struct net_if *cur, fhss_ws_configuration_t *fhss_configuration)
{
    fhss_configuration->fhss_uc_dwell_interval = cur->ws_info.cfg->fhss.fhss_uc_dwell_interval;
    fhss_configuration->ws_uc_channel_function = cur->ws_info.cfg->fhss.fhss_uc_channel_function;
    fhss_configuration->ws_bc_channel_function = cur->ws_info.cfg->fhss.fhss_bc_channel_function;
    fhss_configuration->fhss_bc_dwell_interval = cur->ws_info.cfg->fhss.fhss_bc_dwell_interval;
    fhss_configuration->fhss_broadcast_interval = cur->ws_info.cfg->fhss.fhss_bc_interval;
    fhss_configuration->lfn_bc_interval         = cur->ws_info.cfg->fhss.lfn_bc_interval;
    if (cur->ws_info.cfg->fhss.fhss_uc_fixed_channel != 0xffff) {
        fhss_configuration->unicast_fixed_channel = cur->ws_info.cfg->fhss.fhss_uc_fixed_channel;
    }
    fhss_configuration->broadcast_fixed_channel = cur->ws_info.cfg->fhss.fhss_bc_fixed_channel;
    return 0;
}

uint16_t ws_bootstrap_randomize_fixed_channel(uint16_t configured_fixed_channel, uint8_t number_of_channels, uint8_t *channel_mask)
{
    if (configured_fixed_channel == 0xFFFF) {
        uint16_t random_channel = rand_get_random_in_range(0, number_of_channels - 1);
        while (!bittest(channel_mask, random_channel))
            random_channel = rand_get_random_in_range(0, number_of_channels - 1);
        return random_channel;
    } else {
        return configured_fixed_channel;
    }
}

static int8_t ws_bootstrap_fhss_enable(struct net_if *cur)
{
    // Set the LLC information to follow the actual fhss settings
    ws_bootstrap_llc_hopping_update(cur, &cur->ws_info.fhss_conf);

    return 0;
}

bool ws_bootstrap_nd_ns_transmit(struct net_if *cur, ipv6_neighbour_t *entry,  bool unicast, uint8_t seq)
{
    (void)cur;
    (void)seq;

    if (unicast) {
        // Unicast NS is OK
        return false;
    }
    // Fail the resolution
    tr_warn("Link address lost for %s", tr_ipv6(entry->ip_address));
    ipv6_neighbour_entry_remove(&cur->ipv6_neighbour_cache, entry);
    // True means we skip the message sending
    return true;
}

int8_t ws_bootstrap_up(struct net_if *cur, const uint8_t *ipv6_address)
{
    int8_t ret_val = -1;

    BUG_ON(!ipv6_address);

    if (!cur) {
        return -1;
    }

    if ((cur->configure_flags & INTERFACE_SETUP_MASK) != INTERFACE_SETUP_READY) {
        tr_error("Interface not yet fully configured");
        return -2;
    }
    if (ws_bootstrap_fhss_initialize(cur) != 0) {
        tr_error("fhss initialization failed");
        return -3;
    }
    ws_bbr_init(cur);

    addr_interface_set_ll64(cur);
    // Trigger discovery for bootstrap
    ret_val = protocol_6lowpan_up(cur);
    if (ret_val) {
        goto cleanup;
    }

    /* Omit sending of NA if ARO SUCCESS */
    cur->ipv6_neighbour_cache.omit_na_aro_success = true;
    /* Omit sending of NA and consider ACK to be success */
    cur->ipv6_neighbour_cache.omit_na = true;
    /* Disable NUD Probes */
    cur->ipv6_neighbour_cache.send_nud_probes = false;
    /*Replace NS handler to disable multicast address queries */
    cur->if_ns_transmit = ws_bootstrap_nd_ns_transmit;

    addr_add(cur, ipv6_address, 64);
    ipv6_route_add(ipv6_address, 128, cur->id, NULL, ROUTE_LOOPBACK, 0xFFFFFFFF, 0);

    // Zero uptime counters
    cur->ws_info.uptime = 0;
    cur->ws_info.authentication_time = 0;
    cur->ws_info.connected_time = 0;

    return 0;
cleanup:
    return ret_val;
}

void ws_bootstrap_configuration_reset(struct net_if *cur)
{
    // Configure IP stack to operate as Wi-SUN node
    // Set default parameters to interface
    cur->configure_flags = INTERFACE_BOOTSTRAP_DEFINED;
    cur->configure_flags |= INTERFACE_SECURITY_DEFINED;
    cur->lowpan_info = 0;
    cur->lowpan_info |= INTERFACE_NWK_ROUTER_DEVICE;

    cur->ws_info.network_pan_id = 0xffff;
    ws_mngt_async_trickle_stop(cur);
}

// TODO: in wsbrd 2.0, this function must disappear.
static void ws_bootstrap_neighbor_table_clean(struct net_if *interface)
{
    uint8_t neigh_count = ws_neigh_get_neigh_count(&interface->ws_info.neighbor_storage);
    ws_neigh_t *neigh_table = interface->ws_info.neighbor_storage.neigh_info_list;
    time_t current_time_stamp = time_current(CLOCK_MONOTONIC);
    ws_neigh_t *oldest_neigh = NULL;

    if (neigh_count < interface->ws_info.neighbor_storage.list_size)
        return;

    WARN("neighbor table full");

    for (uint8_t i = 0; i < interface->ws_info.neighbor_storage.list_size; i++) {
        if (!neigh_table[i].in_use)
            continue;

        if (oldest_neigh && oldest_neigh->lifetime_s < neigh_table[i].lifetime_s)
            // We have already shorter link entry found this cannot replace it
            continue;

        if (neigh_table[i].lifetime_s > WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME)
            //Do not permit to remove configured temp life time
            continue;

        if (neigh_table[i].trusted_device)
            if (ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, neigh_table[i].mac64))
                // We have registered entry so we have been selected as parent
                continue;

        //Read current timestamp
        uint32_t time_from_last_unicast_schedule = current_time_stamp - neigh_table[i].host_rx_timestamp;
        if (time_from_last_unicast_schedule >= interface->ws_info.cfg->timing.temp_link_min_timeout) {
            //Accept only Enough Old Device
            if (!oldest_neigh) {
                //Accept first compare
                oldest_neigh = &neigh_table[i];
            } else {
                uint32_t compare_neigh_time = current_time_stamp - oldest_neigh->host_rx_timestamp;
                if (compare_neigh_time < time_from_last_unicast_schedule)  {
                    //Accept older RX timeout always
                    oldest_neigh = &neigh_table[i];
                }
            }
        }
    }

    if (oldest_neigh) {
        tr_info("dropped oldest neighbour %s", tr_eui64(oldest_neigh->mac64));
        ws_bootstrap_neighbor_del(oldest_neigh->mac64);
    }
}

struct ws_neigh *ws_bootstrap_neighbor_add(struct net_if *net_if, const uint8_t eui64[8], uint8_t role)
{
    struct ws_neigh *ws_neigh;
    struct ipv6_neighbour *ipv6_neighbor;

    ws_bootstrap_neighbor_table_clean(net_if);

    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, eui64);
    if (!ws_neigh) {
        ws_neigh = ws_neigh_add(&net_if->ws_info.neighbor_storage,
                                          eui64, role,
                                          net_if->ws_info.key_index_mask);
        if (ws_neigh && version_older_than(net_if->rcp->version_api, 2, 0, 0))
            rcp_legacy_set_neighbor(ws_neigh->index, mac_helper_panid_get(net_if), 0,
                                    ws_neigh->mac64, 0);
    }

    if (!ws_neigh)
        return NULL;
    if (role == WS_NR_ROLE_LFN && !g_timers[WS_TIMER_LTS].timeout)
        ws_timer_start(WS_TIMER_LTS);

    ipv6_neighbor = ipv6_neighbour_lookup_gua_by_eui64(&net_if->ipv6_neighbour_cache, eui64);
    if (ipv6_neighbor) {
        ws_neigh_trust(ws_neigh);
        ws_neigh_refresh(ws_neigh, ipv6_neighbor->lifetime_s);
    }
    return ws_neigh;
}

static void ws_neighbor_entry_remove_long_link_address_from_neighcache(struct net_if *cur, const uint8_t *mac64)
{
    uint8_t temp_ll[10];
    uint8_t *ptr = temp_ll;
    ptr = write_be16(ptr, cur->mac_parameters.pan_id);
    memcpy(ptr, mac64, 8);
    ipv6_neighbour_invalidate_ll_addr(&cur->ipv6_neighbour_cache,
                                      ADDR_802_15_4_LONG, temp_ll);
    nd_remove_registration(cur, ADDR_802_15_4_LONG, temp_ll);
}

void ws_bootstrap_neighbor_del(const uint8_t *mac64)
{
    struct net_if *cur = protocol_stack_interface_info_get();
    struct ws_neigh *ws_neigh = ws_neigh_get(&cur->ws_info.neighbor_storage, mac64);

    BUG_ON(!ws_neigh);

    lowpan_adaptation_free_messages_from_queues_by_address(cur, mac64, ADDR_802_15_4_LONG);
    ws_neighbor_entry_remove_long_link_address_from_neighcache(cur, mac64);
    ws_bootstrap_neighbor_delete(cur, ws_neigh);
}

static void ws_bootstrap_pan_version_increment(struct net_if *cur)
{
    (void)cur;
    ws_bbr_pan_version_increase(cur);
}

static void ws_bootstrap_lfn_version_increment(struct net_if *cur)
{
    (void)cur;
    ws_bbr_lfn_version_increase(cur);
}

static void ws_bootstrap_nw_key_set(struct net_if *cur,
                                    uint8_t key_index,
                                    const uint8_t key[16],
                                    uint32_t frame_counter)
{
    struct ws_neigh *neigh_list = cur->ws_info.neighbor_storage.neigh_info_list;

    BUG_ON(key_index < 1 || key_index > 7);
    // Firmware API < 0.15 crashes if slots > 3 are accessed
    if (!cur->ws_info.enable_lfn && key_index > 4)
        return;
    rcp_set_sec_key(cur->rcp, key_index, key, frame_counter);
    if (key) {
        dbus_emit_keys_change(&g_ctxt);
        cur->ws_info.key_index_mask |= 1u << key_index;
    } else {
        cur->ws_info.key_index_mask &= ~(1u << key_index);
    }
    for (int i = 0; i < cur->ws_info.neighbor_storage.list_size; i++)
        neigh_list[i].frame_counter_min[key_index - 1] = key ? 0 : UINT32_MAX;
}

static void ws_bootstrap_nw_key_index_set(struct net_if *cur, uint8_t index)
{
    if (cur->mac_parameters.mac_default_ffn_key_index != 0 &&
        cur->mac_parameters.mac_default_ffn_key_index != index + 1 &&
        index < 4) {
        /* Update the active key in the PAN Configs */
        tr_info("New Pending key Request %u", index);
        cur->ws_info.pending_key_index_info.state = PENDING_KEY_INDEX_ADVERTISMENT;
        cur->ws_info.pending_key_index_info.index = index;
        return;
    }
    if (cur->mac_parameters.mac_default_lfn_key_index != 0 &&
        cur->mac_parameters.mac_default_lfn_key_index != index + 1 &&
        index >= 4 && index < 7)
        // Notify LFNs that a new LGTK has been activated.
        ws_mngt_lpc_pae_cb(cur);

    /* Deprecated: Unused by the RCP. */
    if (index < 4)
        cur->mac_parameters.mac_default_ffn_key_index = index + 1;
    else if (index >= 4 && index < 7)
        cur->mac_parameters.mac_default_lfn_key_index = index + 1;
}

static void ws_bootstrap_nw_frame_counter_read(struct net_if *cur, uint8_t slot)
{
    if (version_older_than(cur->rcp->version_api, 2, 0, 0))
        rcp_legacy_get_frame_counter(slot);
}

static void ws_bootstrap_nw_info_updated(struct net_if *cur, uint16_t pan_id, uint16_t pan_version, uint16_t lfn_version)
{
    /* For border router, the PAE controller reads PAN ID, PAN version and network name from storage.
     * If they are set, takes them into use here.
     */
    // Get network name
    ws_gen_cfg_t gen_cfg;
    if (ws_cfg_gen_get(&gen_cfg) < 0) {
        return;
    }

    // If PAN ID has not been set, set it
    if (cur->ws_info.network_pan_id == 0xffff) {
        cur->ws_info.network_pan_id = pan_id;
        // Sets PAN version
        cur->ws_info.pan_information.pan_version = pan_version;
        cur->ws_info.pan_information.pan_version_set = true;
        cur->ws_info.pan_information.lfn_version = lfn_version;
        cur->ws_info.pan_information.lfn_version_set = true;
    }

    // Stores the settings
    ws_cfg_gen_set(cur, &gen_cfg, 0);
}

static bool ws_bootstrap_eapol_congestion_get(struct net_if *cur, uint16_t active_supp)
{
    if (cur == NULL || cur->random_early_detection == NULL || cur->llc_random_early_detection == NULL || cur->llc_eapol_random_early_detection == NULL) {
        return false;
    }

    bool return_value = false;
    static struct red_info *red_info = NULL;
    uint16_t adaptation_average = 0;
    uint16_t llc_average = 0;
    uint16_t llc_eapol_average = 0;
    uint16_t average_sum = 0;
    uint8_t active_max = 0;
    uint32_t heap_size = UINT32_MAX;

    /*
      * For different memory sizes the max simultaneous authentications will be
      * 32k:    (32k / 50k) * 2 + 1 = 1
      * 65k:    (65k / 50k) * 2 + 1 = 3
      * 250k:   (250k / 50k) * 2 + 1 = 11
      * 1000k:  (1000k / 50k) * 2 + 1 = 41
      * 2000k:  (2000k / 50k) * 2 + 1 = 50 (upper limit)
      */
    active_max = (heap_size / 50000) * 2 + 1;
    if (active_max > 50) {
        active_max = 50;
    }

    // Read the values for adaptation and LLC queues
    adaptation_average = random_early_detection_aq_read(cur->random_early_detection);
    llc_average = random_early_detection_aq_read(cur->llc_random_early_detection);
    llc_eapol_average  = random_early_detection_aq_read(cur->llc_eapol_random_early_detection);
    // Calculate combined average
    average_sum = adaptation_average + llc_average + llc_eapol_average;

    // Maximum for active supplicants based on memory reached, fail
    if (active_supp >= active_max) {
        return_value = true;
        goto congestion_get_end;
    }

    // Always allow at least five negotiations (if memory does not limit)
    if (active_supp < 5) {
        goto congestion_get_end;
    }

    if (red_info == NULL) {
        red_info = random_early_detection_create(
                       cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_min,
                       cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_max,
                       100, RED_AVERAGE_WEIGHT_DISABLED);
    }
    if (red_info == NULL) {
        goto congestion_get_end;
    }

    // Check drop probability
    average_sum = random_early_detection_aq_calc(red_info, average_sum);
    return_value = random_early_detection_congestion_check(red_info);

congestion_get_end:
    tr_info("Active supplicant limit, active: %i max: %i summed averageQ: %i adapt averageQ: %i LLC averageQ: %i LLC EAPOL averageQ: %i drop: %s", active_supp, active_max, average_sum, adaptation_average, llc_average, llc_eapol_average, return_value ? "T" : "F");

    return return_value;
}

int ws_bootstrap_init(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    ws_neigh_table_t neigh_info;
    uint32_t neighbors_table_size;
    int ret_val = 0;

    if (!cur)
        return -1;

    neigh_info.neigh_info_list = NULL;
    neigh_info.list_size = 0;
    neighbors_table_size = cur->rcp->neighbors_table_size - MAX_NEIGH_TEMPORARY_EAPOL_SIZE;

    if (version_older_than(cur->rcp->version_api, 2, 0, 0))
        rcp_legacy_set_frame_counter_per_key(true);

    if (!ws_neigh_table_allocate(&neigh_info, neighbors_table_size, ws_bootstrap_neighbor_del)) {
        ret_val = -1;
        goto init_fail;
    }

    //Disable always by default
    lowpan_adaptation_interface_mpx_register(interface_id, NULL, 0);

    ws_llc_create(cur, &ws_mngt_ind, &ws_mngt_cnf);

    mpx_api_t *mpx_api = ws_llc_mpx_api_get(cur);
    if (!mpx_api) {
        ret_val =  -4;
        goto init_fail;
    }

    if (ws_common_allocate_and_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    if (ws_cfg_settings_interface_set(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Register MPXUser to adapatation layer
    if (lowpan_adaptation_interface_mpx_register(interface_id, mpx_api, MPX_LOWPAN_ENC_USER_ID) != 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Init PAE controller and set callback
    if (ws_pae_controller_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_pae_controller_cb_register(cur,
                                      ws_bootstrap_nw_key_set,
                                      ws_bootstrap_nw_key_index_set,
                                      ws_bootstrap_nw_frame_counter_read,
                                      ws_bootstrap_pan_version_increment,
                                      ws_bootstrap_lfn_version_increment,
                                      ws_bootstrap_nw_info_updated,
                                      ws_bootstrap_eapol_congestion_get) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_pae_controller_configure(cur, &cur->ws_info.cfg->sec_timer, &cur->ws_info.cfg->sec_prot, &cur->ws_info.cfg->timing) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Init EAPOL PDU handler and register it to MPX
    if (ws_eapol_pdu_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_eapol_pdu_mpx_register(cur, mpx_api, MPX_KEY_MANAGEMENT_ENC_USER_ID != 0)) {
        ret_val =  -4;
        // add deallocs
        goto init_fail;
    }

    cur->ipv6_neighbour_cache.link_mtu = WS_MPX_MAX_MTU;

    cur->ws_info.neighbor_storage = neigh_info;

    ws_bootstrap_configuration_reset(cur);
    if (version_older_than(cur->rcp->version_api, 2, 0, 0))
        rcp_legacy_set_accept_unknown_secured_frames(true);

    // Specification is ruling out the compression mode, but we are now doing it.
    cur->mpl_seed = true;
    cur->mpl_seed_id_mode = MULTICAST_MPL_SEED_ID_IPV6_SRC_FOR_DOMAIN;

    cur->mpl_domain = mpl_domain_create(cur, ADDR_ALL_MPL_FORWARDERS, NULL, MULTICAST_MPL_SEED_ID_DEFAULT, 0, NULL);
    addr_add_group(cur, ADDR_REALM_LOCAL_ALL_NODES);
    addr_add_group(cur, ADDR_REALM_LOCAL_ALL_ROUTERS);

    return 0;

    //Error handling and free memory
init_fail:
    lowpan_adaptation_interface_mpx_register(interface_id, NULL, 0);
    ws_eapol_pdu_mpx_register(cur, NULL, 0);
    ws_neigh_table_free(&neigh_info);
    ws_llc_delete(cur);
    ws_eapol_pdu_delete(cur);
    ws_pae_controller_delete(cur);
    return ret_val;
}

static int ws_bootstrap_set_rf_config(struct net_if *cur, phy_rf_channel_configuration_t rf_configs)
{
    rcp_set_radio(cur->rcp, &rf_configs);
    if (version_older_than(cur->rcp->version_api, 2, 0, 0)) {
        rcp_legacy_set_802154_mode(IEEE_802_15_4G_2012);
        rcp_legacy_set_cca_threshold(cur->ws_info.hopping_schedule.number_of_channels,
                                     CCA_DEFAULT_DBM, CCA_HIGH_LIMIT, CCA_LOW_LIMIT);
        rcp_legacy_get_rx_sensitivity();
    }
    return 0;
}

int ws_bootstrap_set_domain_rf_config(struct net_if *cur)
{
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    ws_hopping_schedule_t *hopping_schedule = &cur->ws_info.hopping_schedule;
    phy_rf_channel_configuration_t rf_config = { };

    phy_params = ws_regdb_phy_params(hopping_schedule->phy_mode_id, hopping_schedule->operating_mode);
    chan_params = ws_regdb_chan_params(hopping_schedule->regulatory_domain, hopping_schedule->channel_plan_id,
                                       hopping_schedule->operating_class);

    rf_config.rcp_config_index = hopping_schedule->rcp_rail_config_index;
    if (hopping_schedule->phy_op_modes[0])
        rf_config.use_phy_op_modes = true;
    // We don't worry of the case where phy_params == NULL, the RCP will return
    // an error anyway.
    if (phy_params) {
        rf_config.datarate = phy_params->datarate;
        rf_config.modulation = phy_params->modulation;
        rf_config.modulation_index = phy_params->fsk_modulation_index;
        rf_config.fec = phy_params->fec;
        rf_config.ofdm_option = phy_params->ofdm_option;
        rf_config.ofdm_mcs = phy_params->ofdm_mcs;
    }

    if (!chan_params) {
        rf_config.channel_0_center_frequency = hopping_schedule->ch0_freq;
        rf_config.channel_spacing = hopping_schedule->channel_spacing;
        rf_config.number_of_channels = hopping_schedule->number_of_channels;
    } else {
        WARN_ON(!ws_regdb_check_phy_chan_compat(phy_params, chan_params),
                "non standard RF configuration in use");
        rf_config.channel_0_center_frequency = chan_params->chan0_freq;
        rf_config.channel_spacing = chan_params->chan_spacing;
        rf_config.number_of_channels = chan_params->chan_count;
    }

    hopping_schedule->phy_mode_id_ms_base = phy_params ? phy_params->phy_mode_id : 0;
    ws_bootstrap_set_rf_config(cur, rf_config);
    return 0;
}

void ws_bootstrap_fhss_activate(struct net_if *cur)
{
    ws_bootstrap_fhss_enable(cur);
    // Only supporting fixed channel

    cur->lowpan_info &=  ~INTERFACE_NWK_CONF_MAC_RX_OFF_IDLE;
    if (version_older_than(cur->rcp->version_api, 2, 0, 0))
        rcp_legacy_set_security(true);
    cur->mac_parameters.pan_id = cur->ws_info.network_pan_id;
    rcp_req_radio_enable(cur->rcp, cur->mac_parameters.pan_id);
    return;
}

void ws_bootstrap_ip_stack_reset(struct net_if *cur)
{
    // Delete all temporary cached information
    ipv6_neighbour_cache_flush(&cur->ipv6_neighbour_cache);
    lowpan_context_list_free(&cur->lowpan_contexts);
}

void ws_bootstrap_ip_stack_activate(struct net_if *cur)
{
    cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ACTIVE;
    ws_bootstrap_ip_stack_reset(cur);
}

void ws_bootstrap_seconds_timer(struct net_if *cur, uint32_t seconds)
{
    cur->ws_info.uptime++;

    ws_llc_timer_seconds(cur, seconds);
}

//Calculate max_packet queue size
static uint16_t ws_bootstrap_define_congestin_max_threshold(uint32_t heap_total_size, uint16_t packet_size, uint16_t packet_per_seconds, uint32_t max_delay, uint16_t min_packet_queue_size, uint16_t max_packet_queue_size)
{
    uint32_t max_packet_count = 0;
    if (heap_total_size) {
        //Claculate how many packet can be max queue to half of heap
        max_packet_count = (heap_total_size / 2) / packet_size;
    }

    //Calculate how many packet is possible to queue for guarantee given max delay
    uint32_t max_delayded_queue_size = max_delay * packet_per_seconds;

    if (max_packet_count > max_delayded_queue_size) {
        //Limit queue size by MAX delay
        max_packet_count = max_delayded_queue_size;
    }

    if (max_packet_count > max_packet_queue_size) {
        //Limit queue size by Max
        max_packet_count = max_packet_queue_size;
    } else if (max_packet_count < min_packet_queue_size) {
        //Limit queue size by Min
        max_packet_count = min_packet_queue_size;
    }
    return (uint16_t)max_packet_count;
}

static uint16_t ws_bootstrap_packet_per_seconds(struct net_if *cur, uint16_t packet_size)
{
    uint32_t data_rate = ws_common_datarate_get(cur);

    //calculate how many packet is possible send in paper
    data_rate /= 8 * packet_size;

    //Divide optimal  by / 5 because we split TX / RX slots and BC schedule
    //With Packet size 500 it should return
    //Return 15 for 300kBits
    //Return 7 for 150kBits
    //Return 2 for 50kBits
    return data_rate / 5;
}

void ws_bootstrap_packet_congestion_init(struct net_if *cur)
{
    random_early_detection_free(cur->random_early_detection);
    cur->random_early_detection = NULL;

    uint32_t heap_size = UINT32_MAX;

    uint16_t packet_per_seconds = ws_bootstrap_packet_per_seconds(cur, WS_CONGESTION_PACKET_SIZE);

    uint16_t min_th, max_th;

    max_th = ws_bootstrap_define_congestin_max_threshold(heap_size,
                                                         WS_CONGESTION_PACKET_SIZE,
                                                         packet_per_seconds,
                                                         WS_CONGESTION_QUEUE_DELAY,
                                                         WS_CONGESTION_BR_MIN_QUEUE_SIZE,
                                                         WS_CONGESTION_BR_MAX_QUEUE_SIZE);
    min_th = max_th / 2;
    tr_info("Wi-SUN packet congestion minTh %u, maxTh %u, drop probability %u weight %u, Packet/Seconds %u", min_th, max_th, WS_CONGESTION_RED_DROP_PROBABILITY, RED_AVERAGE_WEIGHT_EIGHTH, packet_per_seconds);
    cur->random_early_detection = random_early_detection_create(min_th, max_th, WS_CONGESTION_RED_DROP_PROBABILITY, RED_AVERAGE_WEIGHT_EIGHTH);

}
