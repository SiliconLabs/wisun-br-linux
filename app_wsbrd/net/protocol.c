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
#include "common/log.h"
#include "common/rand.h"
#include "common/bits.h"
#include "common/events_scheduler.h"
#include "common/endian.h"
#include "common/string_extra.h"
#include "common/specs/ipv6.h"

#include "app/wsbr_mac.h"
#include "net/timers.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "ws/ws_bootstrap_6lbr.h"
#include "ws/ws_common.h"
#include "ws/ws_llc.h"
#include "ipv6/ipv6.h"
#include "mpl/mpl.h"

#include "net/protocol.h"

// RFC 4861 says we only have to reroll ReachableTime every couple of hours, but
// to make sure the code is regularly exercised, let's make it 10 minutes.
#define REACHABLE_TIME_UPDATE_SECONDS       600

protocol_interface_list_t NS_LIST_NAME_INIT(protocol_interface_info_list);

void icmp_fast_timer(int ticks)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (!cur)
        return;

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

    if (!cur)
        return;
    if (cur->reachable_time_ttl > seconds) {
        cur->reachable_time_ttl -= seconds;
    } else {
        protocol_stack_interface_set_reachable_time(cur, cur->base_reachable_time);
    }
}

void protocol_core_init(void)
{
    ws_timer_start(WS_TIMER_MONOTONIC_TIME);
    ws_timer_start(WS_TIMER_MPL);
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
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR_SLOW);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_CONTEXT);
    ws_timer_start(WS_TIMER_6LOWPAN_REACHABLE_TIME);
    ws_timer_start(WS_TIMER_WS_COMMON_FAST);
    ws_timer_start(WS_TIMER_ASYNC);
}

static void protocol_set_eui64(struct net_if *cur, uint8_t eui64[8])
{
    BUG_ON(!memzcmp(eui64, 8));
    memcpy(cur->mac, eui64, 8);
    memcpy(cur->iid_eui64, eui64, 8);
    memcpy(cur->iid_slaac, eui64, 8);
    /* RFC4291 2.5.1: invert the "u" bit */
    cur->iid_eui64[0] ^= 2;
    cur->iid_slaac[0] ^= 2;
}

void protocol_init(struct net_if *entry, struct rcp *rcp, int mtu)
{
    /* We assume for now zone indexes for interface, link and realm all equal interface id */
    entry->id = 1;
    entry->zone_index[IPV6_SCOPE_INTERFACE_LOCAL] = entry->id;
    entry->zone_index[IPV6_SCOPE_LINK_LOCAL] = entry->id;
    entry->zone_index[IPV6_SCOPE_REALM_LOCAL] = entry->id;

    lowpan_adaptation_interface_init(entry->id);
    reassembly_interface_init(entry->id, 8, 5);
    memset(&entry->mac_parameters, 0, sizeof(arm_15_4_mac_parameters_t));
    entry->ws_info.ffn_gtk_index = 0;
    entry->mac_parameters.mtu = mtu;
    entry->rcp = rcp;
    entry->icmp_tokens = 10;
    entry->cur_hop_limit = UNICAST_HOP_LIMIT_DEFAULT;
    protocol_stack_interface_set_reachable_time(entry, 30000);
    ns_list_link_init(entry, link);
    ns_list_init(&entry->lowpan_contexts);
    ns_list_init(&entry->ip_addresses);
    ns_list_init(&entry->ip_groups);
    ns_list_init(&entry->ipv6_neighbour_cache.list);
    ipv6_neighbour_cache_init(&entry->ipv6_neighbour_cache, entry->id);
    protocol_set_eui64(entry, rcp->eui64.u8);
    ns_list_add_to_start(&protocol_interface_info_list, entry);
}

struct net_if *protocol_stack_interface_info_get()
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list)
        return cur;

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
