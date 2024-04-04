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
#include "common/random_early_detection.h"

#include "app/dbus.h"
#include "app/wsbr.h"
#include "app/wsbr_mac.h"
#include "app/rcp_api_legacy.h"
#include "net/ns_address_internal.h"
#include "net/timers.h"
#include "net/protocol.h"
#include "ipv6/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "ipv6/icmpv6.h"
#include "common/specs/ipv6.h"
#include "common/specs/ip.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "ipv6/nd_router_object.h"

#include "ws/ws_bootstrap_6lbr.h"
#include "ws/ws_common.h"
#include "ws/ws_config.h"
#include "ws/ws_eapol_auth_relay.h"
#include "ws/ws_eapol_pdu.h"
#include "ws/ws_eapol_relay.h"
#include "ws/ws_ie_lib.h"
#include "ws/ws_llc.h"
#include "ws/ws_neigh.h"
#include "ws/ws_pae_controller.h"

#include "ws/ws_bootstrap.h"

#define TRACE_GROUP "wsbs"

static void ws_bootstrap_neighbor_delete(struct net_if *interface, struct ws_neigh *neighbor)
{
    ws_neigh_del(&interface->ws_info.neighbor_storage, neighbor->mac64);
    if (!ws_neigh_lfn_count(&interface->ws_info.neighbor_storage))
        ws_timer_stop(WS_TIMER_LTS);
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

void ws_bootstrap_up(struct net_if *cur, const uint8_t *ipv6_address)
{
    BUG_ON(!ipv6_address);
    BUG_ON(!cur);

    addr_interface_set_ll64(cur);
    // Trigger discovery for bootstrap
    protocol_6lowpan_up(cur);

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
}

void ws_bootstrap_configuration_reset(struct net_if *cur)
{
    ws_mngt_async_trickle_stop(cur);
}

/**
 * Neighbor management logic:
 * - 15.4 neigh and IPv6 neigh have independant lifetimes
 * - There is 1 ARO route per IPv6 neigh except for multicast ipv6 neigh
 * - when an IPv6 neigh is restored, its ARO route is not created
 * - when a 15.4 neigh is added and one or several corresponding IPv6 neigh(s)
 *   with GUA already exists, all associated ARO routes are restored and the
 *   lifetime of the 15.4 neighbor is set to the lifetime of the first
 *   associated IPv6 neigh with GUA found in cache.
 * - when a 15.4 neigh expires/is deleted, all ARO routes of corresponding IPv6
 *   neighs are deleted. All corresponding IPv6 neighs remain in the cache
 *   until expiration.
 * - when an IPv6 neigh expires/is deleted, the ARO route associated to the
 *   IPv6 neigh is deleted. The corresponding 15.4 neigh remains in cache until
 *   expiration.
 */
struct ws_neigh *ws_bootstrap_neighbor_add(struct net_if *net_if, const uint8_t eui64[8], uint8_t role)
{
    struct ws_neigh *ws_neigh;
    struct ipv6_neighbour *ipv6_neighbor;

    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, eui64);
    if (!ws_neigh)
        ws_neigh = ws_neigh_add(&net_if->ws_info.neighbor_storage,
                                eui64, role, net_if->ws_info.tx_power_dbm,
                                net_if->ws_info.key_index_mask);

    BUG_ON(!ws_neigh);
    if (role == WS_NR_ROLE_LFN && !g_timers[WS_TIMER_LTS].timeout)
        ws_timer_start(WS_TIMER_LTS);

    ipv6_neighbor = ipv6_neighbour_lookup_gua_by_eui64(&net_if->ipv6_neighbour_cache, eui64);
    if (ipv6_neighbor) {
        ws_neigh_trust(ws_neigh);
        ws_neigh_refresh(ws_neigh, ipv6_neighbor->lifetime_s);
        nd_restore_aro_routes_by_eui64(net_if, eui64);
    }
    return ws_neigh;
}

void ws_bootstrap_neighbor_del(const uint8_t *mac64)
{
    struct net_if *cur = protocol_stack_interface_info_get();
    struct ws_neigh *ws_neigh = ws_neigh_get(&cur->ws_info.neighbor_storage, mac64);

    BUG_ON(!ws_neigh);

    lowpan_adaptation_free_messages_from_queues_by_address(cur, mac64, ADDR_802_15_4_LONG);
    nd_remove_aro_routes_by_eui64(cur, mac64);
    ws_bootstrap_neighbor_delete(cur, ws_neigh);
}

static void ws_bootstrap_nw_key_set(struct net_if *cur,
                                    uint8_t key_index,
                                    const uint8_t key[16],
                                    uint32_t frame_counter)
{
    struct ws_neigh *neigh;

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
    SLIST_FOREACH(neigh, & cur->ws_info.neighbor_storage.neigh_list, link)
        neigh->frame_counter_min[key_index - 1] = key ? 0 : UINT32_MAX;
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

static bool ws_bootstrap_eapol_congestion_get(struct net_if *cur)
{
    if (cur == NULL) {
        return false;
    }

    bool return_value = false;
    uint16_t adaptation_average = 0;
    uint16_t llc_average = 0;
    uint16_t llc_eapol_average = 0;
    uint16_t average_sum = 0;

    // Read the values for adaptation and LLC queues
    adaptation_average = red_aq_get(&cur->random_early_detection);
    llc_average = red_aq_get(&cur->llc_random_early_detection);
    llc_eapol_average  = red_aq_get(&cur->llc_eapol_random_early_detection);
    // Calculate combined average
    average_sum = adaptation_average + llc_average + llc_eapol_average;
    // Check drop probability
    average_sum = red_aq_calc(&cur->pae_random_early_detection, average_sum);
    return_value = red_congestion_check(&cur->pae_random_early_detection);

    tr_info("Congestion check, summed averageQ: %i adapt averageQ: %i LLC averageQ: %i LLC EAPOL averageQ: %i drop: %s", average_sum, adaptation_average, llc_average, llc_eapol_average, return_value ? "T" : "F");

    return return_value;
}

int ws_bootstrap_init(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    int ret_val = 0;

    if (!cur)
        return -1;

    //Disable always by default
    lowpan_adaptation_interface_mpx_register(interface_id, NULL, 0);

    ws_llc_create(cur, &ws_mngt_ind, &ws_mngt_cnf);

    mpx_api_t *mpx_api = ws_llc_mpx_api_get(cur);
    if (!mpx_api) {
        ret_val =  -4;
        goto init_fail;
    }

    //Register MPXUser to adapatation layer
    if (lowpan_adaptation_interface_mpx_register(interface_id, mpx_api, MPX_ID_6LOWPAN) != 0) {
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
                                      ws_mngt_pan_version_increase,
                                      ws_mngt_lfn_version_increase,
                                      ws_bootstrap_eapol_congestion_get) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Init EAPOL PDU handler and register it to MPX
    if (ws_eapol_pdu_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_eapol_pdu_mpx_register(cur, mpx_api, MPX_ID_KMP) != 0) {
        ret_val =  -4;
        // add deallocs
        goto init_fail;
    }

    ws_bootstrap_configuration_reset(cur);

    addr_add_group(cur, ADDR_REALM_LOCAL_ALL_NODES);
    addr_add_group(cur, ADDR_REALM_LOCAL_ALL_ROUTERS);

    return 0;

    //Error handling and free memory
init_fail:
    lowpan_adaptation_interface_mpx_register(interface_id, NULL, 0);
    ws_eapol_pdu_mpx_register(cur, NULL, 0);
    ws_llc_delete(cur);
    ws_eapol_pdu_delete(cur);
    ws_pae_controller_delete(cur);
    return ret_val;
}

int ws_bootstrap_set_domain_rf_config(struct net_if *cur)
{
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    struct ws_phy_config *phy_config = &cur->ws_info.phy_config;
    struct ws_fhss_config *fhss_config = &cur->ws_info.fhss_config;
    phy_rf_channel_configuration_t rf_config = { };

    phy_params = ws_regdb_phy_params(phy_config->phy_mode_id, phy_config->op_mode);
    chan_params = ws_regdb_chan_params(fhss_config->regulatory_domain, fhss_config->chan_plan_id, fhss_config->op_class);

    rf_config.rcp_config_index = phy_config->rcp_rail_config_index;
    if (phy_config->phy_op_modes[0])
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
        rf_config.channel_0_center_frequency = fhss_config->chan0_freq;
        rf_config.channel_spacing = fhss_config->chan_spacing;
        rf_config.number_of_channels = fhss_config->chan_count;
    } else {
        WARN_ON(!ws_regdb_check_phy_chan_compat(phy_params, chan_params),
                "non standard RF configuration in use");
        rf_config.channel_0_center_frequency = chan_params->chan0_freq;
        rf_config.channel_spacing = chan_params->chan_spacing;
        rf_config.number_of_channels = chan_params->chan_count;
    }

    phy_config->phy_mode_id_ms_base = phy_params ? phy_params->phy_mode_id : 0;
    rcp_set_radio(cur->rcp,
                  rf_config.rcp_config_index,
                  rf_config.ofdm_mcs,
                  rf_config.use_phy_op_modes);
    return 0;
}

void ws_bootstrap_fhss_activate(struct net_if *cur)
{
    rcp_set_filter_pan_id(cur->rcp, cur->ws_info.pan_information.pan_id);
    rcp_req_radio_enable(cur->rcp);
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
    ws_bootstrap_ip_stack_reset(cur);
}

void ws_bootstrap_seconds_timer(struct net_if *cur, uint32_t seconds)
{
    ws_llc_timer_seconds(cur, seconds);
}

//Calculate max_packet queue size
static uint16_t ws_bootstrap_define_congestion_max_threshold(uint32_t heap_total_size, uint16_t packet_size, uint16_t packet_per_seconds, uint32_t max_delay, uint16_t min_packet_queue_size, uint16_t max_packet_queue_size)
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
    uint16_t packet_per_seconds = ws_bootstrap_packet_per_seconds(cur, WS_CONGESTION_PACKET_SIZE);
    uint16_t max_th = ws_bootstrap_define_congestion_max_threshold(UINT32_MAX,
                                                                  WS_CONGESTION_PACKET_SIZE,
                                                                  packet_per_seconds,
                                                                  WS_CONGESTION_QUEUE_DELAY,
                                                                  WS_CONGESTION_BR_MIN_QUEUE_SIZE,
                                                                  WS_CONGESTION_BR_MAX_QUEUE_SIZE);

    cur->random_early_detection.weight = RED_AVERAGE_WEIGHT_EIGHTH,
    cur->random_early_detection.threshold_min = max_th / 2,
    cur->random_early_detection.threshold_max = max_th,
    cur->random_early_detection.drop_max_probability = WS_CONGESTION_RED_DROP_PROBABILITY,
    red_init(&cur->random_early_detection);
    tr_info("Wi-SUN packet congestion minTh %u, maxTh %u, drop probability %u weight %u, Packet/Seconds %u",
            cur->random_early_detection.threshold_min,
            cur->random_early_detection.threshold_max,
            cur->random_early_detection.drop_max_probability,
            cur->random_early_detection.weight, packet_per_seconds);
}
