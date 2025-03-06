/*
 * Copyright (c) 2012, 2014-2019, 2021, Pelion and affiliates.
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
/*
 * ipv6_routing_table.h
 *
 * Implements Neighbour Cache
 */

#ifndef IPV6_ROUTING_TABLE_H_
#define IPV6_ROUTING_TABLE_H_
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "common/ns_list.h"

#include "net/netaddr_types.h"

/* Address Resolution and Neighbour Unreachablity Detection constants from
 * RFC 4861, updated by RFC 7048.
 */
#define MAX_MULTICAST_SOLICIT               3
#define MAX_UNICAST_SOLICIT                 5
#define MARK_UNREACHABLE                    3
#define MAX_RETRANS_TIMER                   60000   /* ms */
#define DELAY_FIRST_PROBE_TIME              5000    /* ms */
#define BACKOFF_MULTIPLE                    3

/* RFC 6775 parameters */
#define TENTATIVE_NCE_LIFETIME              20      /* s */

#define IPV6_ROUTE_DEFAULT_METRIC           128

#define DCACHE_GC_PERIOD    20  /* seconds */

/* XXX in the process of renaming this - it's really specifically the
 * IP Neighbour Cache  but was initially called a routing table */

typedef enum ip_neighbour_cache_state {
    IP_NEIGHBOUR_NEW,               /* Not yet used; no LL addr, no NS sent */
    IP_NEIGHBOUR_INCOMPLETE,
    IP_NEIGHBOUR_REACHABLE,
    IP_NEIGHBOUR_STALE,
    IP_NEIGHBOUR_DELAY,
    IP_NEIGHBOUR_PROBE,
    IP_NEIGHBOUR_UNREACHABLE
} ip_neighbour_cache_state_e;

/* RFC 6775 types */
typedef enum ip_neighbour_cache_type {
    IP_NEIGHBOUR_GARBAGE_COLLECTIBLE,
    IP_NEIGHBOUR_REGISTERED,
    IP_NEIGHBOUR_TENTATIVE
} ip_neighbour_cache_type_e;

typedef enum ipv6_route_src {
    ROUTE_ANY,          /* Unspecified - use in lookups */
    ROUTE_NONE,         /* Only occurs in incomplete destination cache entries */
    ROUTE_STATIC,
    ROUTE_LOOPBACK,
    ROUTE_USER,
    ROUTE_ARO,
    ROUTE_RADV,
    ROUTE_RPL_DAO_SR,   /* Explicitly advertised in DAO, Root Source Routes in Non-Storing mode */
    ROUTE_MULTICAST,    /* Not in routing table - used to represent multicast interface selection */
    ROUTE_MPL,
    ROUTE_RIP,
    ROUTE_THREAD,
    ROUTE_THREAD_BORDER_ROUTER,
    ROUTE_THREAD_PROXIED_HOST,
    ROUTE_THREAD_PROXIED_DUA_HOST,
    ROUTE_THREAD_BBR,
    ROUTE_REDIRECT,     /* Only occurs in destination cache */
    ROUTE_MAX,
} ipv6_route_src_t;

struct buffer;

typedef struct ipv6_neighbour {
    uint8_t                         ip_address[16];             /*!< neighbour IP address */
    uint8_t                         retrans_count;
    ip_neighbour_cache_state_e      state;
    ip_neighbour_cache_type_e       type;
    addrtype_e                      ll_type;
    uint32_t                        timer;                      /* 100ms ticks */
    uint32_t                        lifetime_s;
    time_t                          expiration_s;
    ns_list_link_t                  link;                       /*!< List link */
    uint8_t                         ll_address[];
} ipv6_neighbour_t;

/* Neighbour Cache entries also store EUI-64 after ll_address if "recv_addr_reg"
 * is set for the cache. This is ADDR_EUI64_ZERO if unknown.
 */
#define ipv6_neighbour_eui64(ncache, entry) ((entry)->ll_address + (ncache)->max_ll_len)

typedef struct ipv6_route_info_cache {
    uint16_t                                metric; // interface metric
    uint8_t                                 sources[ROUTE_MAX];
} ipv6_route_interface_info_t;

typedef struct ipv6_neighbour_cache {
    bool                                    send_addr_reg : 1;
    bool                                    recv_addr_reg : 1;
    bool                                    send_nud_probes : 1;
    bool                                    recv_ns_aro : 1;
    bool                                    omit_na_aro_success : 1;
    bool                                    omit_na : 1; // except for ARO successes which have a separate flag
    int8_t                                  interface_id;
    uint8_t                                 max_ll_len;
    uint8_t                                 gc_timer;
    uint32_t                                retrans_timer;
    uint32_t                                reachable_time;
    // Interface specific information for route
    ipv6_route_interface_info_t             route_if_info;
    //uint8_t                                   num_entries;
    NS_LIST_HEAD(ipv6_neighbour_t, link)    list;
} ipv6_neighbour_cache_t;

void ipv6_neighbour_cache_init(ipv6_neighbour_cache_t *cache, int8_t interface_id);
void ipv6_neighbour_cache_flush(ipv6_neighbour_cache_t *cache);
ipv6_neighbour_t *ipv6_neighbour_update(ipv6_neighbour_cache_t *cache, const uint8_t *address, bool solicited);
void ipv6_neighbour_set_state(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry, ip_neighbour_cache_state_e state);
ipv6_neighbour_t *ipv6_neighbour_used(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry);
ipv6_neighbour_t *ipv6_neighbour_lookup(ipv6_neighbour_cache_t *cache, const uint8_t *address);
ipv6_neighbour_t *ipv6_neighbour_lookup_mc(ipv6_neighbour_cache_t *cache, const uint8_t *address, const uint8_t *eui64);
ipv6_neighbour_t *ipv6_neighbour_create(ipv6_neighbour_cache_t *cache, const uint8_t *address, const uint8_t *eui64);
void ipv6_neighbour_entry_remove(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry);
ipv6_neighbour_t *ipv6_neighbour_lookup_gua_by_eui64(ipv6_neighbour_cache_t *cache, const uint8_t *eui64);
void ipv6_neighbour_entry_update_unsolicited(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry, addrtype_e type, const uint8_t *ll_address/*, bool tentative*/);
ipv6_neighbour_t *ipv6_neighbour_update_unsolicited(ipv6_neighbour_cache_t *cache, const uint8_t *ip_address, addrtype_e ll_type, const uint8_t *ll_address);
void ipv6_neighbour_cache_fast_timer(int ticks);
void ipv6_neighbour_cache_slow_timer(int seconds);

typedef struct ipv6_route_info {
    ipv6_route_src_t                source;
    uint8_t                         source_id;
    int8_t                          interface_id;
    uint16_t                        pmtu;
    void                            *info;              // pointer to route provider's info
    uint8_t                         next_hop_addr[16];
} ipv6_route_info_t;

typedef struct ipv6_destination {
    /* Destination/path information */
    uint8_t                         destination[16];
    int8_t                          interface_id;       // fixed if link-local destination, else variable and gets set from redirect interface and/or last_neighbour interface
    uint16_t                        refcount;
    uint16_t                        lifetime;           // Life in GC calls, so 20s units
    ipv6_neighbour_t                *last_neighbour;    // last neighbour used (only for reachability confirmation)
    ns_list_link_t                  link;
} ipv6_destination_t;

ipv6_destination_t *ipv6_destination_lookup_or_create(const uint8_t *address, int8_t interface_id);
ipv6_destination_t *ipv6_destination_lookup_or_create_with_route(const uint8_t *address, int8_t interface_id, ipv6_route_info_t *route_out);
void ipv6_destination_cache_timer(int ticks);
void ipv6_destination_cache_clean(int8_t interface_id);

/* Combined Routing Table (RFC 4191) and Prefix List (RFC 4861) */
/* On-link prefixes have the on_link flag set and next_hop is unset */
typedef struct ipv6_route {
    uint8_t             prefix_len;
    bool                on_link: 1;
    bool                search_skip: 1;
    bool                info_autofree: 1;
    uint8_t             metric;             // 0x40 = RFC 4191 pref high, 0x80 = default, 0xC0 = RFC 4191 pref low
    ipv6_route_info_t   info;
    uint32_t            lifetime;           // (seconds); 0xFFFFFFFF means permanent
    ns_list_link_t      link;
    uint8_t             prefix[];           // variable length
} ipv6_route_t;

/* Callbacks for route providers that dynamically compute next hop */
typedef bool ipv6_route_next_hop_fn_t(const uint8_t *dest, ipv6_route_info_t *route_info);

ipv6_route_t *ipv6_route_add(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, uint32_t lifetime, int_fast8_t pref);
ipv6_route_t *ipv6_route_add_with_info(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, uint8_t source_id, uint32_t lifetime, int_fast8_t pref);
ipv6_route_t *ipv6_route_add_metric(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, uint8_t source_id, uint32_t lifetime, uint8_t metric);
ipv6_route_t *ipv6_route_lookup_with_info(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, int_fast16_t source_id);
int_fast8_t ipv6_route_delete(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source);
int_fast8_t ipv6_route_delete_with_info(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, int_fast16_t source_id);
ipv6_route_t *ipv6_route_choose_next_hop(const uint8_t *dest, int8_t interface_id);

void ipv6_route_table_set_next_hop_fn(ipv6_route_src_t src, ipv6_route_next_hop_fn_t *fn);
void ipv6_route_table_ttl_update(int seconds);
bool ipv6_route_table_source_was_invalidated(ipv6_route_src_t src);
void ipv6_route_table_source_invalidated_reset(void);

#endif /* IPV6_ROUTING_TABLE_H_ */
