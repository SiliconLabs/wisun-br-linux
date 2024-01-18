/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#include "common/rand.h"
#include "common/bits.h"
#include "common/events_scheduler.h"
#include "common/endian.h"
#include "common/string_extra.h"
#include "common/specs/ipv6.h"

#include "app_wsbrd/rcp_api_legacy.h"
#include "app_wsbrd/wsbr_mac.h"
#include "core/timers.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_llc.h"
#include "common_protocols/ipv6.h"
#include "mpl/mpl.h"

#include "nwk_interface/protocol_stats.h"
#include "nwk_interface/protocol.h"

// RFC 4861 says we only have to reroll ReachableTime every couple of hours, but
// to make sure the code is regularly exercised, let's make it 10 minutes.
#define REACHABLE_TIME_UPDATE_SECONDS       600

protocol_interface_list_t NS_LIST_NAME_INIT(protocol_interface_info_list);

// maximum value of nwk_interface_id_e is 1
struct net_if protocol_interface_info;

static int8_t net_interface_get_free_id(void);

void icmp_fast_timer(int ticks)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    /* This gives us the RFC 4443 default (10 tokens/s, bucket size 10) */
    cur->icmp_tokens += ticks;
    if (cur->icmp_tokens > 10) {
        cur->icmp_tokens = 10;
    }
}

static uint32_t protocol_stack_interface_set_reachable_time(struct net_if *cur, uint32_t base_reachable_time)
{
    cur->base_reachable_time = base_reachable_time;
    cur->reachable_time_ttl = REACHABLE_TIME_UPDATE_SECONDS;

    return cur->ipv6_neighbour_cache.reachable_time = rand_randomise_base(base_reachable_time, 0x4000, 0xBFFF);
}

void update_reachable_time(int seconds)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (cur->reachable_time_ttl > seconds) {
        cur->reachable_time_ttl -= seconds;
    } else {
        protocol_stack_interface_set_reachable_time(cur, cur->base_reachable_time);
    }
}

void protocol_core_init(void)
{
    ws_timer_start(WS_TIMER_MONOTONIC_TIME);
    ws_timer_start(WS_TIMER_MPL_SLOW);
    ws_timer_start(WS_TIMER_PAE_FAST);
    ws_timer_start(WS_TIMER_PAE_SLOW);
    ws_timer_start(WS_TIMER_IPV6_DESTINATION);
    ws_timer_start(WS_TIMER_IPV6_ROUTE);
    ws_timer_start(WS_TIMER_CIPV6_FRAG);
    ws_timer_start(WS_TIMER_ICMP_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_MLD_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_MLD_SLOW);
    ws_timer_start(WS_TIMER_6LOWPAN_ND);
    ws_timer_start(WS_TIMER_6LOWPAN_ADAPTATION);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR_SLOW);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_CONTEXT);
    ws_timer_start(WS_TIMER_6LOWPAN_REACHABLE_TIME);
    ws_timer_start(WS_TIMER_WS_COMMON_FAST);
    ws_timer_start(WS_TIMER_WS_COMMON_SLOW);
}

static void protocol_core_base_init(struct net_if *entry)
{
    entry->if_ns_transmit = NULL;
    entry->if_common_forwarding_out_cb = NULL;
    entry->if_special_forwarding = NULL;
    entry->if_snoop = NULL;
    entry->if_map_ip_to_link_addr = NULL;
    entry->lowpan_info = 0;
}

static void protocol_core_base_finish_init(struct net_if *entry)
{
    entry->configure_flags = 0;
    entry->reallocate_short_address_if_duplicate = true;
    entry->icmp_tokens = 10;
    entry->ip_forwarding = true; /* Default to on for now... */
    entry->ip_multicast_forwarding = true; /* Default to on for now... */
    entry->recv_ra_routes = true;
    entry->recv_ra_prefixes = true;
    entry->send_mld = true;
    entry->mpl_seed = false;
    entry->mpl_data_trickle_params = rfc7731_default_data_message_trickle_params;
    entry->mpl_seed_set_entry_lifetime = RFC7731_DEFAULT_SEED_SET_ENTRY_LIFETIME;
    entry->mpl_seed_id_mode = MULTICAST_MPL_SEED_ID_IPV6_SRC_FOR_DOMAIN;
    entry->cur_hop_limit = UNICAST_HOP_LIMIT_DEFAULT;
    protocol_stack_interface_set_reachable_time(entry, 30000);
    entry->dup_addr_detect_transmits = 1;
    entry->ipv6_neighbour_cache.link_mtu = IPV6_MIN_LINK_MTU;
    entry->max_link_mtu = IPV6_MIN_LINK_MTU;
    entry->pmtu_lifetime = 10 * 60; // RFC 1981 default - 10 minutes
    ns_list_link_init(entry, link);
    entry->if_stack_buffer_handler = NULL;
    ns_list_init(&entry->lowpan_contexts);
    ns_list_init(&entry->ip_addresses);
    ns_list_init(&entry->ip_groups);
    ns_list_init(&entry->ipv6_neighbour_cache.list);
}

static struct net_if *protocol_interface_class_allocate()
{
    struct net_if *entry = &protocol_interface_info;
    int id = net_interface_get_free_id();

    memset(entry, 0, sizeof(struct net_if));
    /* We assume for now zone indexes for interface, link and realm all equal interface id */
    entry->id = id;
    entry->zone_index[IPV6_SCOPE_INTERFACE_LOCAL] = id;
    entry->zone_index[IPV6_SCOPE_LINK_LOCAL] = id;
    entry->zone_index[IPV6_SCOPE_REALM_LOCAL] = id;
    protocol_core_base_init(entry);
    return entry;
}

static struct net_if *protocol_core_interface_6lowpan_entry_get_with_mac(struct rcp *rcp, int mtu)
{
    struct net_if *entry = protocol_interface_class_allocate();

    BUG_ON(!entry);
    lowpan_adaptation_interface_init(entry->id);
    reassembly_interface_init(entry->id, 8, 5);
    memset(&entry->mac_parameters, 0, sizeof(arm_15_4_mac_parameters_t));
    entry->mac_parameters.pan_id = 0xffff;

    entry->mac_parameters.mac_default_ffn_key_index = 0;
    entry->mac_parameters.mtu = mtu;

    entry->rcp = rcp;

    protocol_core_base_finish_init(entry);
    return entry;
}

void nwk_interface_print_neigh_cache()
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
        ipv6_neighbour_cache_print(&cur->ipv6_neighbour_cache);
    }
}

struct net_if *protocol_stack_interface_info_get()
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list)
        return cur;

    return NULL;
}

static int8_t net_interface_get_free_id(void)
{
    uint_fast8_t id; // Must be unsigned for loop test to work...

    for (id = 1; id <= INT8_MAX; id++) {
        bool in_use = false;
        /* interface index == default zone index for link, interface and realm, so
         * ensure selected ID is not in use for any of those scopes */
        ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
            if (cur->id == (int8_t) id ||
                    cur->zone_index[IPV6_SCOPE_INTERFACE_LOCAL] == id ||
                    cur->zone_index[IPV6_SCOPE_LINK_LOCAL] == id ||
                    cur->zone_index[IPV6_SCOPE_REALM_LOCAL] == id) {
                in_use = true;
                break;
            }
        }
        if (!in_use) {
            return id;
        }
    }

    return -1;
}

struct net_if *protocol_stack_interface_generate_lowpan(struct rcp *rcp, int mtu)
{
    struct net_if *new_entry = protocol_core_interface_6lowpan_entry_get_with_mac(rcp, mtu);

    if (new_entry) {
        ipv6_neighbour_cache_init(&new_entry->ipv6_neighbour_cache, new_entry->id);
        memcpy(new_entry->iid_eui64, rcp->eui64, 8);
        memcpy(new_entry->iid_slaac, rcp->eui64, 8);
        /* RFC4291 2.5.1: invert the "u" bit */
        new_entry->iid_eui64[0] ^= 2;
        new_entry->iid_slaac[0] ^= 2;
        ns_list_add_to_start(&protocol_interface_info_list, new_entry);
        return new_entry;
    }
    return NULL;
}

void protocol_push(buffer_t *b)
{
    if (!b)
        return;

    struct net_if *cur = b->interface;
    if (cur && cur->if_stack_buffer_handler) {
        cur->if_stack_buffer_handler(b);
        return;
    }
    buffer_free(b);
}

/* XXX note that this does not perform any scope checks, so will for example match
 * link local addresses on any interface - you may want addr_interface_address_compare */
int8_t protocol_interface_address_compare(const uint8_t *addr)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
        if (addr_is_assigned_to_interface(cur, addr)) {
            return 0;
        }
    }

    return -1;
}
