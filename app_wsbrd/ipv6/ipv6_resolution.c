/*
 * Copyright (c) 2015-2019, Pelion and affiliates.
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
#include "common/endian.h"
#include "common/memutils.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/specs/icmpv6.h"

#include "net/netaddr_types.h"
#include "net/ns_address_internal.h"
#include "net/protocol.h"
#include "ipv6/nd_router_object.h" // for gp_address_ functions - better place?
#include "ipv6/ipv6_routing_table.h"

#include "ipv6/ipv6.h"
#include "ipv6/icmpv6.h"

#include "ipv6/ipv6_resolution.h"

#define TRACE_GROUP "ip6r"

#ifndef RESOLUTION_QUEUE_LIMIT
#define RESOLUTION_QUEUE_LIMIT 2
#endif

void ipv6_interface_resolve_send_ns(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry, bool unicast, uint8_t seq)
{
    struct net_if *cur_interface = container_of(cache, struct net_if, ipv6_neighbour_cache);
    buffer_t *buf;

    if (cur_interface->if_ns_transmit) {
        /* Thread uses DHCP Leasequery (!) instead of NS for address resolution */
        /* We still allow unicast NUD probes using NS, although I expect them to be disabled */
        if (cur_interface->if_ns_transmit(cur_interface, entry, unicast, seq)) {
            return;
        }
    }

    tr_debug("Sending %s NS for: %s",
             (unicast ? "unicast" : "multicast"), tr_ipv6(entry->ip_address));

    buf = icmpv6_build_ns(cur_interface, entry->ip_address, unicast);
    protocol_push(buf);
}

/* Silly bit of interface glue - ipv6_routing_table.c doesn't know about interface structures,
 * but it needs to be able to get from the interface id in the Routing Table and/or
 * Destination Cache to the relevant Neighbour Cache
 */
ipv6_neighbour_cache_t *ipv6_neighbour_cache_by_interface_id(int8_t interface_id)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);

    return interface ? &interface->ipv6_neighbour_cache : NULL;
}

/* Given a buffer with IP next-hop address and outgoing interface, find the
 * neighbour entry, and if complete, write the link-layer address into the buffer
 * destination, and return the Neighbour Cache entry.
 * If we have an incomplete Neighbour Cache entry, start address resolution
 * and queue the buffer, returning NULL.
 */
ipv6_neighbour_t *ipv6_interface_resolve_new(struct net_if *cur, buffer_t *buf)
{
    addrtype_e ll_type;
    const uint8_t *ll_addr;
    ipv6_neighbour_t *n;
    buffer_routing_info_t *route = ipv6_buffer_route(buf);

    if (!route) {
        tr_warn("XXX ipv6_interface_resolve no route!");
        // Can this happen? How did it get to this interface in the first place?
        // If it can happen, send ICMP Destination Unreachable
        buffer_free(buf);
        return NULL;
    }

    if (!ipv6_map_ip_to_ll(cur, NULL, route->route_info.next_hop_addr, &ll_type, &ll_addr) ||
        ll_type != ADDR_802_15_4_LONG) {
        TRACE(TR_TX_ABORT, "tx-abort: unable to map ip to link layer address");
        buffer_free(buf);
        return NULL;
    }

    n = ipv6_neighbour_lookup(&cur->ipv6_neighbour_cache, route->route_info.next_hop_addr);
    if (!n)
        n = ipv6_neighbour_create(&cur->ipv6_neighbour_cache,
                                  route->route_info.next_hop_addr, ll_addr + PAN_ID_LEN);
    if (!n) {
        buffer_free(buf);
        return NULL;
    }

    if (n->state == IP_NEIGHBOUR_NEW || n->state == IP_NEIGHBOUR_INCOMPLETE)
        ipv6_neighbour_entry_update_unsolicited(&cur->ipv6_neighbour_cache, n, ll_type, ll_addr);

    buf->dst_sa.addr_type = n->ll_type;
    memcpy(buf->dst_sa.address, n->ll_address, addr_len_from_type(n->ll_type));

    n = ipv6_neighbour_used(&cur->ipv6_neighbour_cache, n);
    return n;
}

/* Attempt a mapping from current information (neighbour cache, hard mappings) */
bool ipv6_map_ip_to_ll(struct net_if *cur, ipv6_neighbour_t *n, const uint8_t ip_addr[16], addrtype_e *ll_type, const uint8_t **ll_addr_out)
{
    if (!n) {
        n = ipv6_neighbour_lookup(&cur->ipv6_neighbour_cache, ip_addr);
    }
    if (n && !(n->state == IP_NEIGHBOUR_NEW || n->state == IP_NEIGHBOUR_INCOMPLETE)) {
        *ll_type = n->ll_type;
        *ll_addr_out = n->ll_address;
        return true;
    }

    if (cur->if_map_ip_to_link_addr &&
            cur->if_map_ip_to_link_addr(cur, ip_addr, ll_type, ll_addr_out)) {
        return true;
    }

    return false;
}
