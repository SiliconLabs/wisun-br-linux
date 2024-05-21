/*
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSRD_NDP_H
#define WSRD_NDP_H

struct in6_addr;
struct ipv6_ctx;

#include <netinet/in.h>
#include <sys/queue.h>
#include <stdbool.h>

#include "common/timer.h"

struct ipv6_ctx;

/*
 * Neighbor Discovery Protocol (NDP) is defined in:
 *   - RFC 4861: Neighbor Discovery for IP version 6 (IPv6)
 *   - RFC 6775: Neighbor Discovery Optimization for IPv6 over Low-Power
 *     Wireless Personal Area Networks (6LoWPANs)
 *   - RFC 8505: Registration Extensions for IPv6 over Low-Power Wireless
 *     Personal Area Network (6LoWPAN) Neighbor Discovery
 *   - draft-ietf-6lo-multicast-registration-18: IPv6 Neighbor Discovery
 *     Multicast and Anycast Address Listener Subscription
 */

// RFC 4861 7.3.2. Neighbor Cache Entry States
enum {
    IPV6_NUD_UNDEF,
    IPV6_NUD_INCOMPLETE, // Unused (no multicast NS as per RFC 6775)
    IPV6_NUD_REACHABLE,
    IPV6_NUD_STALE,
    IPV6_NUD_DELAY,
    IPV6_NUD_PROBE,
};

/*
 *   RFC 4861 5.1 Conceptual Data Structures
 * Neighbor Cache: A set of entries about individual neighbors to which traffic
 * has been sent recently. Entries are keyed on the neighbor's on-link unicast
 * IP address and contain such information as its link-layer address, a flag
 * indicating whether the neighbor is a router or a host, a pointer to any
 * queued packets waiting for address resolution to complete, etc. A Neighbor
 * Cache entry also contains information used by the Neighbor Unreachability
 * Detection algorithm, including the reachability state, the number of
 * unanswered probes, and the time the next Neighbor Unreachability Detection
 * event is scheduled to take place.
 */
struct ipv6_neigh {
    uint8_t eui64[8];
    struct in6_addr ipv6_addr;

    int  nud_state;
    int  nud_probe_count;
    struct timer_entry nud_timer;

    struct rpl_neigh *rpl_neigh;

    SLIST_ENTRY(ipv6_neigh) link;
};

// Declare struct ipv6_neigh_cache
SLIST_HEAD(ipv6_neigh_cache, ipv6_neigh);

struct ipv6_neigh *ipv6_neigh_get(struct ipv6_ctx *ipv6,
                                  const struct in6_addr *ipv6_addr);
struct ipv6_neigh *ipv6_neigh_add(struct ipv6_ctx *ipv6,
                                  const struct in6_addr *ipv6_addr,
                                  const uint8_t eui64[64]);
void ipv6_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh);

void ipv6_nud_set_state(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh, int state);

void ipv6_send_ns_aro(struct ipv6_ctx *ipv6, struct in6_addr *dst);

#endif