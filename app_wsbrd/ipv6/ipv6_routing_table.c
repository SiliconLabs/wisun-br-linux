/*
 * Copyright (c) 2012-2019, 2021, Pelion and affiliates.
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
 * ipv6_routing_table.c
 *
 *  Implements IPv6 Neighbour Cache (RFC 4861), Destination Cache (RFC 4861),
 *  and Routing Table (RFC 4191, incorporating the RFC 4861 Prefix List)
 *
 * Note that RFC 4861 dictates that the Prefix List is checked first,
 * followed by the Default Router List. In simple host scenarios, the
 * longest-match routing table look-up achieves that, because on-link entries
 * from the Prefix List are longer than the ::/0 default routes.
 *
 * In more complex scenarios, we can have more-specific routes preferred over
 * more general on-link prefixes, eg the border router preferring a /128 RPL
 * DAO-SR route instead of the /64 on-link prefix for the Ethernet backbone.
 *
 */
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "common/rand.h"
#include "common/bits.h"
#include "common/memutils.h"
#include "common/log_legacy.h"
#include "common/string_extra.h"

#include "common/specs/ipv6.h"
#include "ipv6/icmpv6.h"
#include "ipv6/ipv6_resolution.h"
#include "net/protocol.h"
#include "common/time_extra.h"

#include "ipv6/ipv6_neigh_storage.h"
#include "ipv6/ipv6_routing_table.h"
#include "net/protocol_abstract.h"

#define TRACE_GROUP "rout"

#define NCACHE_GC_PERIOD    20  /* seconds */

/* Neighbour Cache garbage collection parameters (per interface) */
/* Parameters only for garbage-collectible entries; registered entries counted separately */
#define NCACHE_MAX_LONG_TERM    8   /* Target for basic GC - expire old entries if more than this */
#define NCACHE_MAX_SHORT_TERM   32  /* Expire stale entries if more than this */
#define NCACHE_MAX_ABSOLUTE     64  /* Never have more than this */
#define NCACHE_GC_AGE           600 /* 10 minutes (1s units - decremented every slow timer call) */

/* Destination Cache garbage collection parameters (system-wide) */
#define DCACHE_MAX_LONG_TERM    16
#define DCACHE_MAX_SHORT_TERM   40
#define DCACHE_MAX_ABSOLUTE     64 /* Never have more than this */
#define DCACHE_GC_AGE           (30 * DCACHE_GC_PERIOD)    /* 10 minutes */

/* We track "lifetime" of garbage-collectible entries, resetting
 * when used. Entries with lifetime 0 are favoured
 * for garbage-collection. */
#define DCACHE_GC_AGE_LL (120 / DCACHE_GC_PERIOD)  /* 2 minutes for link-local destinations, in DCACHE_GC_PERIOD intervals */

static NS_LIST_DEFINE(ipv6_destination_cache, ipv6_destination_t, link);
static NS_LIST_DEFINE(ipv6_routing_table, ipv6_route_t, link);

static void ipv6_destination_cache_forget_neighbour(const ipv6_neighbour_t *neighbour);
static bool ipv6_destination_release(ipv6_destination_t *dest);
static uint16_t total_metric(const ipv6_route_t *route);
static uint8_t ipv6_route_table_count_source(int8_t interface_id, ipv6_route_src_t source);
static void ipv6_route_table_remove_last_one_from_source(int8_t interface_id, ipv6_route_src_t source);
static uint8_t ipv6_route_table_get_max_entries(int8_t interface_id, ipv6_route_src_t source);

static uint32_t next_probe_time(ipv6_neighbour_cache_t *cache, uint8_t retrans_num)
{
    uint32_t t = cache->retrans_timer;

    while (retrans_num--) {
        t *= BACKOFF_MULTIPLE;
        if (t > MAX_RETRANS_TIMER) {
            t = MAX_RETRANS_TIMER;
            break;
        }
    }

    return rand_randomise_base(t, 0x4000, 0xBFFF);
}

void ipv6_neighbour_cache_init(ipv6_neighbour_cache_t *cache, int8_t interface_id)
{
    /* Init Double linked Routing Table */
    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cache->list) {
        ipv6_neighbour_entry_remove(cache, cur);
    }
    cache->gc_timer = NCACHE_GC_PERIOD;
    cache->retrans_timer = 1000;
    cache->max_ll_len = 2 + 8;
    cache->interface_id = interface_id;
    cache->recv_addr_reg = false;
    cache->send_addr_reg = false;
    cache->send_nud_probes = true;
    cache->recv_ns_aro = false;
    cache->route_if_info.metric = 0;
    memset(cache->route_if_info.sources, 0, sizeof(cache->route_if_info.sources));
}

void ipv6_neighbour_cache_flush(ipv6_neighbour_cache_t *cache)
{
    /* Flush non-registered entries only */
    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cache->list) {
        if (cur->type == IP_NEIGHBOUR_GARBAGE_COLLECTIBLE) {
            ipv6_neighbour_entry_remove(cache, cur);
        }
    }
}


ipv6_neighbour_t *ipv6_neighbour_lookup(ipv6_neighbour_cache_t *cache, const uint8_t *address)
{
    ns_list_foreach(ipv6_neighbour_t, cur, &cache->list)
        if (addr_ipv6_equal(cur->ip_address, address))
            return cur;

    return NULL;
}

void ipv6_neighbour_entry_remove(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry)
{
    struct net_if *net_if = container_of(cache, struct net_if, ipv6_neighbour_cache);

    /* Remove entry from cache first - avoids weird garbage collection issues, like
     * it being pushed out while generating ICMP errors, or ICMP errors actually using
     * the entry.
     */
    ns_list_remove(&cache->list, entry);
    switch (entry->state) {
        case IP_NEIGHBOUR_NEW:
        case IP_NEIGHBOUR_INCOMPLETE:
            break;
        case IP_NEIGHBOUR_STALE:
        case IP_NEIGHBOUR_REACHABLE:
        case IP_NEIGHBOUR_DELAY:
        case IP_NEIGHBOUR_PROBE:
        case IP_NEIGHBOUR_UNREACHABLE:
            break;
    }
    ipv6_destination_cache_forget_neighbour(entry);
    if (!IN6_IS_ADDR_MULTICAST(entry->ip_address))
        ipv6_route_delete(entry->ip_address, 128, net_if->id, entry->ip_address, ROUTE_ARO);
    TRACE(TR_NEIGH_IPV6, "IPv6 neighbor del %s / %s",
        tr_eui64(ipv6_neighbour_eui64(cache, entry)), tr_ipv6(entry->ip_address));
    ipv6_neigh_storage_save(cache, ipv6_neighbour_eui64(cache, entry));
    free(entry);
}

ipv6_neighbour_t *ipv6_neighbour_lookup_mc(ipv6_neighbour_cache_t *cache, const uint8_t *address, const uint8_t *eui64)
{
    if (!IN6_IS_ADDR_MULTICAST(address))
        return NULL;

    ns_list_foreach(ipv6_neighbour_t, cur, &cache->list)
        if (addr_ipv6_equal(cur->ip_address, address)) {
            if (memcmp(ipv6_neighbour_eui64(cache, cur), eui64, 8))
                continue;
            return cur;
        }

    return NULL;
}

ipv6_neighbour_t *ipv6_neighbour_create(ipv6_neighbour_cache_t *cache, const uint8_t *address, const uint8_t *eui64)
{
    uint16_t count = 0;
    ipv6_neighbour_t *entry = NULL;
    ipv6_neighbour_t *garbage_possible_entry = NULL;

    ns_list_foreach(ipv6_neighbour_t, cur, &cache->list) {
        if (cur->type == IP_NEIGHBOUR_GARBAGE_COLLECTIBLE) {
            garbage_possible_entry = cur;
            count++;
        }
    }

    if (count >= NCACHE_MAX_ABSOLUTE && garbage_possible_entry) {
        //Remove Last storaged IP_NEIGHBOUR_GARBAGE_COLLECTIBLE type entry
        ipv6_neighbour_entry_remove(cache, garbage_possible_entry);
    }

    // Allocate new - note we have a basic size, plus enough for the LL address,
    // plus another 8 for the EUI-64 of registration (RFC 6775). Note that in
    // the protocols, the link-layer address and EUI-64 are distinct. The
    // neighbour may be using a short link-layer address, not its EUI-64.
    entry = zalloc(sizeof(ipv6_neighbour_t) + cache->max_ll_len + (cache->recv_addr_reg ? 8 : 0));
    memcpy(entry->ip_address, address, 16);
    if (cache->recv_addr_reg)
        memcpy(ipv6_neighbour_eui64(cache, entry), eui64, 8);
    ns_list_add_to_start(&cache->list, entry);
    TRACE(TR_NEIGH_IPV6, "IPv6 neighbor add %s / %s",
          tr_eui64(ipv6_neighbour_eui64(cache, entry)), tr_ipv6(entry->ip_address));

    return entry;
}

ipv6_neighbour_t *ipv6_neighbour_used(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry)
{
    /* Reset the GC life, if it's a GC entry */
    if (entry->type == IP_NEIGHBOUR_GARBAGE_COLLECTIBLE) {
        entry->lifetime_s = NCACHE_GC_AGE;
        entry->expiration_s = time_now_s(CLOCK_MONOTONIC) + NCACHE_GC_AGE;
    }

    /* Move it to the front of the list */
    if (entry != ns_list_get_first(&cache->list)) {
        ns_list_remove(&cache->list, entry);
        ns_list_add_to_start(&cache->list, entry);
    }

    /* If the entry is stale, prepare delay timer for active NUD probe */
    if (entry->state == IP_NEIGHBOUR_STALE && cache->send_nud_probes) {
        ipv6_neighbour_set_state(cache, entry, IP_NEIGHBOUR_DELAY);
    }

    /* Special case for Registered Unreachable entries - restart the probe timer if stopped */
    else if (entry->state == IP_NEIGHBOUR_UNREACHABLE && entry->timer == 0) {
        entry->timer = next_probe_time(cache, entry->retrans_count);
    }

    return entry;
}

static bool ipv6_neighbour_update_ll(ipv6_neighbour_t *entry, addrtype_e ll_type, const uint8_t *ll_address)
{
    uint8_t ll_len = addr_len_from_type(ll_type);

    if (ll_type != entry->ll_type || memcmp(entry->ll_address, ll_address, ll_len)) {
        entry->ll_type = ll_type;
        memcpy(entry->ll_address, ll_address, ll_len);
        return true;
    }
    return false;
}

bool ipv6_neighbour_has_registered_by_eui64(ipv6_neighbour_cache_t *cache, const uint8_t *eui64)
{
    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cache->list)
        if (cur->type != IP_NEIGHBOUR_GARBAGE_COLLECTIBLE &&
            !memcmp(ipv6_neighbour_eui64(cache, cur), eui64, 8) &&
            !IN6_IS_ADDR_MULTICAST(cur->ip_address))
            return true;
    return false;
}

ipv6_neighbour_t *ipv6_neighbour_lookup_gua_by_eui64(ipv6_neighbour_cache_t *cache, const uint8_t *eui64)
{
    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cache->list)
        if (cur->type != IP_NEIGHBOUR_GARBAGE_COLLECTIBLE &&
            !memcmp(ipv6_neighbour_eui64(cache, cur), eui64, 8) &&
            !IN6_IS_ADDR_MULTICAST(cur->ip_address) &&
            !IN6_IS_ADDR_LINKLOCAL(cur->ip_address))
            return cur;
    return NULL;
}

void ipv6_neighbour_set_state(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry, ip_neighbour_cache_state_e state)
{
    switch (state) {
        case IP_NEIGHBOUR_INCOMPLETE:
            entry->retrans_count = 0;
            entry->timer = cache->retrans_timer;
            break;
        case IP_NEIGHBOUR_STALE:
            entry->timer = 0;
            break;
        case IP_NEIGHBOUR_DELAY:
            entry->timer = DELAY_FIRST_PROBE_TIME;
            break;
        case IP_NEIGHBOUR_PROBE:
            entry->retrans_count = 0;
            entry->timer = next_probe_time(cache, 0);
            break;
        case IP_NEIGHBOUR_REACHABLE:
            entry->timer = cache->reachable_time;
            break;
        case IP_NEIGHBOUR_UNREACHABLE:
            /* Progress to this from PROBE - timers continue */
            ipv6_destination_cache_forget_neighbour(entry);
            break;
        default:
            entry->timer = 0;
            break;
    }
    entry->state = state;
}

/* Called when LL address information is received other than in an NA (NS source, RS source, RA source, Redirect target) */
void ipv6_neighbour_entry_update_unsolicited(ipv6_neighbour_cache_t *cache, ipv6_neighbour_t *entry, addrtype_e type, const uint8_t *ll_address/*, bool tentative*/)
{
    bool modified_ll = ipv6_neighbour_update_ll(entry, type, ll_address);

    switch (entry->state) {
        case IP_NEIGHBOUR_NEW:
        case IP_NEIGHBOUR_INCOMPLETE:
            ipv6_neighbour_set_state(cache, entry, IP_NEIGHBOUR_STALE);
            break;
        default:
            if (modified_ll) {
                ipv6_neighbour_set_state(cache, entry, IP_NEIGHBOUR_STALE);
            }
            break;
    }
}

ipv6_neighbour_t *ipv6_neighbour_update_unsolicited(ipv6_neighbour_cache_t *cache, const uint8_t *ip_address, addrtype_e type, const uint8_t *ll_address/*, bool tentative*/)
{
    ipv6_neighbour_t *entry = ipv6_neighbour_lookup(cache, ip_address);
    if (!entry)
        entry = ipv6_neighbour_create(cache, ip_address, ll_address + PAN_ID_LEN);
    if (!entry)
        return NULL;

    ipv6_neighbour_entry_update_unsolicited(cache, entry, type, ll_address/*, tentative*/);

    return entry;
}

static void ipv6_neighbour_cache_gc_periodic(ipv6_neighbour_cache_t *cache)
{
    ns_list_foreach_reverse_safe(ipv6_neighbour_t, entry, &cache->list) {
        if (entry->type != IP_NEIGHBOUR_GARBAGE_COLLECTIBLE)
            continue;

        if (time_now_s(CLOCK_MONOTONIC) >= entry->expiration_s)
            ipv6_neighbour_entry_remove(cache, entry);
    }
}

void ipv6_neighbour_cache_slow_timer(int seconds)
{
    ipv6_neighbour_cache_t *cache = &protocol_stack_interface_info_get()->ipv6_neighbour_cache;

    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cache->list) {
        if (cur->lifetime_s && cur->expiration_s &&
            time_now_s(CLOCK_MONOTONIC) < cur->expiration_s)
            continue;

        /* Lifetime expired */
        switch (cur->type) {
            case IP_NEIGHBOUR_GARBAGE_COLLECTIBLE:
                /* No immediate action, but 0 lifetime is an input to the GC */
                break;

            case IP_NEIGHBOUR_TENTATIVE:
            case IP_NEIGHBOUR_REGISTERED:
                /* These are deleted as soon as lifetime expires */
                ipv6_destination_cache_forget_neighbour(cur);
                ipv6_neighbour_entry_remove(cache, cur);
                break;
        }
    }

    if (cache->gc_timer > seconds) {
        cache->gc_timer -= seconds;
        return;
    }

    cache->gc_timer = NCACHE_GC_PERIOD;
    ipv6_neighbour_cache_gc_periodic(cache);
}

void ipv6_neighbour_cache_fast_timer(int ticks)
{
    ipv6_neighbour_cache_t *cache = &protocol_stack_interface_info_get()->ipv6_neighbour_cache;
    uint32_t ms = (uint32_t) ticks * 100;

    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cache->list) {
        if (cur->timer == 0) {
            continue;
        }

        if (cur->timer > ms) {
            cur->timer -= ms;
            continue;
        }

        cur->timer = 0;

        /* Timer expired */
        switch (cur->state) {
            case IP_NEIGHBOUR_NEW:
                /* Shouldn't happen */
                break;
            case IP_NEIGHBOUR_INCOMPLETE:
                if (++cur->retrans_count >= MAX_MULTICAST_SOLICIT) {
                    /* Should be safe for registration - Tentative/Registered entries can't be INCOMPLETE */
                    ipv6_destination_cache_forget_neighbour(cur);
                    ipv6_neighbour_entry_remove(cache, cur);
                } else {
                    ipv6_interface_resolve_send_ns(cache, cur, false, cur->retrans_count);
                    cur->timer = cache->retrans_timer;
                }
                break;
            case IP_NEIGHBOUR_STALE:
                /* Shouldn't happen */
                break;
            case IP_NEIGHBOUR_REACHABLE:
                ipv6_neighbour_set_state(cache, cur, IP_NEIGHBOUR_STALE);
                break;
            case IP_NEIGHBOUR_DELAY:
                ipv6_neighbour_set_state(cache, cur, IP_NEIGHBOUR_PROBE);
                ipv6_interface_resolve_send_ns(cache, cur, true, 0);
                break;
            case IP_NEIGHBOUR_PROBE:
                if (cur->retrans_count >= MARK_UNREACHABLE - 1)
                    ipv6_neighbour_set_state(cache, cur, IP_NEIGHBOUR_UNREACHABLE);
            /* fall through */
            case IP_NEIGHBOUR_UNREACHABLE:
                if (cur->retrans_count < 0xFF) {
                    cur->retrans_count++;
                }

                if (cur->retrans_count >= MAX_UNICAST_SOLICIT && cur->type == IP_NEIGHBOUR_GARBAGE_COLLECTIBLE) {
                    ipv6_neighbour_entry_remove(cache, cur);
                } else {
                    ipv6_interface_resolve_send_ns(cache, cur, true, cur->retrans_count);
                    if (cur->retrans_count >= MAX_UNICAST_SOLICIT - 1) {
                        /* "Final" unicast probe */
                        if (cur->type == IP_NEIGHBOUR_GARBAGE_COLLECTIBLE) {
                            /* Only wait 1 initial retrans time for response to final probe - don't want backoff in this case */
                            cur->timer = cache->retrans_timer;
                        } else {
                            /* We're not going to remove this. Let's stop the timer. We'll restart to probe once more if it's used */
                            cur->timer = 0;
                        }
                    } else {
                        /* Backoff for the next probe */
                        cur->timer = next_probe_time(cache, cur->retrans_count);
                    }
                }
                break;
        }
    }
}

/* Unlike original version, this does NOT perform routing check - it's pure destination cache look-up
 *
 * We no longer attempt to cache route lookups in the destination cache, as
 * assumption that routing look-ups are keyed purely by destination is no longer
 * true. If necessary, a caching layer could be placed into
 * ipv6_route_choose_next_hop.
 *
 * Interface IDs are a little tricky here. Current situation is that we
 * require an interface ID for <=realm-local addresses, and it's ignored for
 * other addresses. That prevents us having multiple Destination Cache entries
 * for one global address.
 */
ipv6_destination_t *ipv6_destination_lookup_or_create(const uint8_t *address, int8_t interface_id)
{
    uint16_t count = 0;
    ipv6_destination_t *entry = NULL;
    bool interface_specific = addr_ipv6_scope(address) <= IPV6_SCOPE_REALM_LOCAL;

    if (interface_specific && interface_id == -1) {
        return NULL;
    }

    /* Find any existing entry */
    ns_list_foreach(ipv6_destination_t, cur, &ipv6_destination_cache) {
        count++;
        if (!addr_ipv6_equal(cur->destination, address)) {
            continue;
        }
        /* For LL addresses, interface ID must also be compared */
        if (interface_specific && cur->interface_id != interface_id) {
            continue;
        }

        entry = cur;
        break;
    }


    if (!entry) {
        if (count > DCACHE_MAX_ABSOLUTE) {
            entry = ns_list_get_last(&ipv6_destination_cache);
            ipv6_destination_release(entry);
        }

        /* If no entry, make one */
        entry = malloc(sizeof(ipv6_destination_t));
        if (!entry) {
            return NULL;
        }
        memcpy(entry->destination, address, 16);
        entry->refcount = 1;
        entry->last_neighbour = NULL;
        if (interface_specific) {
            entry->interface_id = interface_id;
        } else {
            entry->interface_id = -1;
        }
        ns_list_add_to_start(&ipv6_destination_cache, entry);
    } else if (entry != ns_list_get_first(&ipv6_destination_cache)) {
        /* If there was an entry, and it wasn't at the start, move it */
        ns_list_remove(&ipv6_destination_cache, entry);
        ns_list_add_to_start(&ipv6_destination_cache, entry);
    }

    if (addr_ipv6_scope(address) <= IPV6_SCOPE_LINK_LOCAL) {
        entry->lifetime = DCACHE_GC_AGE_LL;
    } else {
        entry->lifetime = DCACHE_GC_AGE / DCACHE_GC_PERIOD;
    }

    return entry;
}

static void ipv6_destination_cache_forget_neighbour(const ipv6_neighbour_t *neighbour)
{
    ns_list_foreach(ipv6_destination_t, entry, &ipv6_destination_cache) {
        if (entry->last_neighbour == neighbour) {
            entry->last_neighbour = NULL;
        }
    }
}

void ipv6_destination_cache_clean(int8_t interface_id)
{
    ns_list_foreach_reverse_safe(ipv6_destination_t, entry, &ipv6_destination_cache) {
        if (entry->interface_id == interface_id) {
            ipv6_destination_release(entry);
        }
    }
}

static bool ipv6_destination_release(ipv6_destination_t *dest)
{
    if (--dest->refcount == 0) {
        ns_list_remove(&ipv6_destination_cache, dest);
        tr_debug("Destination cache remove: %s", tr_ipv6(dest->destination));
        free(dest);
        return true;
    }
    return false;
}

static void ipv6_destination_cache_gc_periodic(void)
{
    uint16_t gc_count = 0;
    ns_list_foreach_safe(ipv6_destination_t, entry, &ipv6_destination_cache) {
        if (entry->lifetime) {
            entry->lifetime--;
        }
        gc_count++;
    }

    if (gc_count <= DCACHE_MAX_LONG_TERM) {
        return;
    }

    /* Cache is in most-recently-used-first order. GC strategy is to start from
     * the back, and reduce the size to "MAX_SHORT_TERM" every GC period,
     * deleting any entry. Timed-out entries will be deleted to keep it to
     * MAX_LONG_TERM.
     */
    ns_list_foreach_reverse_safe(ipv6_destination_t, entry, &ipv6_destination_cache) {
        if (entry->lifetime == 0 || gc_count > DCACHE_MAX_SHORT_TERM) {
            if (ipv6_destination_release(entry)) {
                gc_count--;
            }

            if (gc_count <= DCACHE_MAX_LONG_TERM) {
                break;
            }
        }
    }

}

void ipv6_destination_cache_timer(int ticks)
{
    for (int i = 0; i < ticks; i++)
        ipv6_destination_cache_gc_periodic();
}

static const char *route_src_names[] = {
    [ROUTE_ANY]     = "?",
    [ROUTE_STATIC]  = "Static",
    [ROUTE_USER]    = "User",
    [ROUTE_LOOPBACK] = "Loopback",
    [ROUTE_RADV]    = "RAdv",
    [ROUTE_ARO]     = "ARO",
    [ROUTE_RPL_DAO_SR] = "RPL DAO SR",
    [ROUTE_MULTICAST] = "Multicast",
    [ROUTE_MPL]     = "MPL",
    [ROUTE_RIP]     = "RIP",
    [ROUTE_THREAD]  = "Thread",
    [ROUTE_THREAD_BORDER_ROUTER] = "Thread Network data",
    [ROUTE_THREAD_PROXIED_HOST] = "Thread Proxy",
    [ROUTE_THREAD_BBR] = "Thread BBR",
    [ROUTE_THREAD_PROXIED_DUA_HOST] = "Thread DUA Proxy",
    [ROUTE_REDIRECT] = "Redirect",
};

static ipv6_route_next_hop_fn_t *ipv6_route_next_hop_computation[ROUTE_MAX];

void ipv6_route_table_set_next_hop_fn(ipv6_route_src_t src, ipv6_route_next_hop_fn_t fn)
{
    ipv6_route_next_hop_computation[src] = fn;
}

static void ipv6_route_print(const ipv6_route_t *route)
{
    // Route prefix is variable-length, so need to zero pad for str_ipv6
    uint8_t addr[16] = { 0 };
    bitcpy(addr, route->prefix, route->prefix_len);
    if (route->lifetime != 0xFFFFFFFF) {
        tr_debug(" %24s if:%u src:'%s' id:%d lifetime:%"PRIu32,
                 tr_ipv6_prefix(addr, route->prefix_len), route->info.interface_id,
                 route_src_names[route->info.source], route->info.source_id, route->lifetime
                );
    } else {
        tr_debug(" %24s if:%u src:'%s' id:%d lifetime:infinite",
                 tr_ipv6_prefix(addr, route->prefix_len), route->info.interface_id,
                 route_src_names[route->info.source], route->info.source_id
                );
    }
    if (route->on_link) {
        tr_debug("     On-link (met %d)", total_metric(route));
    } else {
        tr_debug("     next-hop %s (met %d)", tr_ipv6(route->info.next_hop_addr), total_metric(route));
    }
}

/*
 * This function returns total effective metric, which is a combination
 * of 1) route metric, and 2) interface metric. Can be extended to include
 * protocol metric as well in the future.
 */
static uint16_t total_metric(const ipv6_route_t *route)
{
    ipv6_neighbour_cache_t *cache;
    uint16_t metric;

    metric = route->metric;
    cache = ipv6_neighbour_cache_by_interface_id(route->info.interface_id);

    if (cache) {
        metric += cache->route_if_info.metric;
    }

    return metric;
}

static void ipv6_route_entry_remove(ipv6_route_t *route)
{
    tr_info("Deleted route:");
    ipv6_route_print(route);
    if (route->info_autofree) {
        free(route->info.info);
    }
    ns_list_remove(&ipv6_routing_table, route);
    free(route);
}

/* Return true is a is better than b */
static bool ipv6_route_is_better(const ipv6_route_t *a, const ipv6_route_t *b)
{
    /* Prefer longer prefix */
    if (a->prefix_len < b->prefix_len) {
        return false;
    }

    if (a->prefix_len > b->prefix_len) {
        return true;
    }

    /* Prefer on-link */
    if (b->on_link && !a->on_link) {
        return false;
    }

    if (a->on_link && !b->on_link) {
        return true;
    }

    /* If prefixes exactly equal, tiebreak by metric */
    return total_metric(a) < total_metric(b);
}

/* Find the "best" route regardless of reachability, but respecting the skip flag and predicates */
static ipv6_route_t *ipv6_route_find_best(const uint8_t *addr, int8_t interface_id)
{
    ipv6_route_t *best = NULL;
    ns_list_foreach(ipv6_route_t, route, &ipv6_routing_table) {
        /* We mustn't be skipping this route */
        if (route->search_skip) {
            continue;
        }

        /* Interface must match, if caller specified */
        if (interface_id != -1 && interface_id != route->info.interface_id) {
            continue;
        }

        /* Prefix must match */
        if (bitcmp(addr, route->prefix, route->prefix_len)) {
            continue;
        }

        if (!best || ipv6_route_is_better(route, best)) {
            best = route;
        }
    }
    return best;
}

ipv6_route_t *ipv6_route_choose_next_hop(const uint8_t *dest, int8_t interface_id)
{
    ipv6_route_t *best = NULL;

    ns_list_foreach(ipv6_route_t, route, &ipv6_routing_table) {
        route->search_skip = false;
    }

    /* Search algorithm from RFC 4191, S3.2:
     *
     * When a type C host does next-hop determination and consults its
     * Routing Table for an off-link destination, it searches its routing
     * table to find the route with the longest prefix that matches the
     * destination, using route preference values as a tie-breaker if
     * multiple matching routes have the same prefix length.  If the best
     * route points to a non-reachable router, this router is remembered for
     * the algorithm described in Section 3.5 below, and the next best route
     * is consulted.  This check is repeated until a matching route is found
     * that points to a reachable router, or no matching routes remain.
     *
     * Note that rather than having a separate on-link Prefix List, we have
     * on-link entries. These take precedence over default routes (by their
     * non-0 length), but not necessarily over more-specific routes. Therefore
     * it is possible that we consider a few non-reachable routers first, then
     * fall back to on-link. This behaviour may or may not be desired, depending
     * on the scenario. If not desired, the router entries should have their
     * "probing" flag set to false, so they always take precedence over
     * the on-link entry.
     *
     * There is currently no mechanism for an on-link entry to always take
     * precedence over a more-specific route, which is what would happen if
     * we really did have a separate Prefix List and Routing Table. One
     * possibility would be a special precedence flag.
     */
    for (;;) {
        ipv6_route_t *route = ipv6_route_find_best(dest, interface_id);
        if (!route) {
            break;
        }

        if (!route->on_link) {
            /* Some routes (eg RPL SR) compute next hop on demand */
            if (ipv6_route_next_hop_computation[route->info.source]) {
                if (!ipv6_route_next_hop_computation[route->info.source](dest, &route->info)) {
                    route->search_skip = true;
                    continue;
                }
            }

            ipv6_neighbour_cache_t *ncache = ipv6_neighbour_cache_by_interface_id(route->info.interface_id);
            if (!ncache) {
                tr_warn("Invalid interface ID in routing table!");
                route->search_skip = true;
                continue;
            }
        }

        /* If router is reachable, we'll take it now */
        best = route;
        break;
    }

    return best;
}

ipv6_route_t *ipv6_route_lookup_with_info(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, int_fast16_t src_id)
{
    ns_list_foreach(ipv6_route_t, r, &ipv6_routing_table) {
        if (interface_id == r->info.interface_id && prefix_len == r->prefix_len && !bitcmp(prefix, r->prefix, prefix_len)) {
            if (source != ROUTE_ANY) {
                if (source != r->info.source) {
                    continue;
                }
                if (info && info != r->info.info) {
                    continue;
                }
                if (src_id != -1 && src_id != r->info.source_id) {
                    continue;
                }
                if (info && ipv6_route_next_hop_computation[source]) {
                    /* No need to match the actual next hop - we assume info distinguishes */
                    return r;
                }
            }

            /* "next_hop" being NULL means on-link; this is a flag in the route entry, and r->next_hop can't be NULL */
            if ((next_hop && r->on_link) || (!next_hop && !r->on_link)) {
                continue;
            }

            if (next_hop && !r->on_link && !addr_ipv6_equal(next_hop, r->info.next_hop_addr)) {
                continue;
            }

            return r;
        }
    }

    return NULL;
}

#define PREF_TO_METRIC(pref) (128 - 64 * (pref))

uint8_t ipv6_route_pref_to_metric(int_fast8_t pref)
{
    if (pref < -1 || pref > +1) {
        pref = 0;
    }
    return PREF_TO_METRIC(pref);
}

ipv6_route_t *ipv6_route_add(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, uint32_t lifetime, int_fast8_t pref)
{
    return ipv6_route_add_with_info(prefix, prefix_len, interface_id, next_hop, source, NULL, 0, lifetime, pref);
}

ipv6_route_t *ipv6_route_add_with_info(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, uint8_t source_id, uint32_t lifetime, int_fast8_t pref)
{
    /* Only support -1, 0 and +1 prefs, as per RFC 4191 */
    if (pref < -1 || pref > +1) {
        return NULL;
    }

    return ipv6_route_add_metric(prefix, prefix_len, interface_id, next_hop, source, info,  source_id, lifetime, PREF_TO_METRIC(pref));
}

ipv6_route_t *ipv6_route_add_metric(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, uint8_t source_id, uint32_t lifetime, uint8_t metric)
{
    ipv6_route_t *route = NULL;
    enum { UNCHANGED, UPDATED, NEW } changed_info = UNCHANGED;

    // Maybe don't need this after all? We'll just assume that the next_hop is on-link
    // Thread certainly wants to use ULAs...
#if 0
    if (next_hop) {
        /* Currently we require that all routes must be to link-local addresses. */
        /* This simplifies all sorts of things - particularly that we can assume link-local addresses to be on-link. */
        /* It is needed to make Redirects and probes work too. */
        if (!addr_is_ipv6_link_local(next_hop)) {
            return NULL;
        }
    }
#endif


    /* Check for matching info, in which case it's an update */
    route = ipv6_route_lookup_with_info(prefix, prefix_len, interface_id, next_hop, source, info, source_id);

    /* 0 lifetime is a deletion request (common to all protocols) */
    if (lifetime == 0) {
        if (route) {
            tr_debug("Zero route lifetime");
            ipv6_route_entry_remove(route);
        }
        return NULL;
    }

    uint8_t max_entries = ipv6_route_table_get_max_entries(interface_id, source);
    if (max_entries > 0) {
        uint8_t entries = ipv6_route_table_count_source(interface_id, source);
        if (entries > max_entries) {
            ipv6_route_table_remove_last_one_from_source(interface_id, source);
        }
    }

    if (!route) { /* new route */
        uint8_t prefix_bytes = (prefix_len + 7u) / 8u;
        route = malloc(sizeof(ipv6_route_t) + prefix_bytes);
        if (!route) {
            return NULL;
        }
        memset(route->prefix, 0, prefix_bytes);
        bitcpy(route->prefix, prefix, prefix_len);
        route->prefix_len = prefix_len;
        route->search_skip = false;
        route->lifetime = lifetime;
        route->metric = metric;
        route->info.source = source;
        route->info_autofree = false;
        route->info.info = info;
        route->info.source_id = source_id;
        route->info.interface_id = interface_id;
        route->info.pmtu = 0xFFFF;
        if (next_hop) {
            route->on_link = false;
            memcpy(route->info.next_hop_addr, next_hop, 16);
        } else {
            route->on_link = true;
            memset(route->info.next_hop_addr, 0, 16);
        }

        /* Routing table will be resorted during use, thanks to probing. */
        /* Doesn't matter much where they start off, but put them at the */
        /* beginning so new routes tend to get tried first. */
        ns_list_add_to_start(&ipv6_routing_table, route);
        changed_info = NEW;
    } else { /* updating a route - only lifetime and metric can be changing */
        route->lifetime = lifetime;
        if (metric != route->metric) {
            route->metric = metric;
            changed_info = UPDATED;
        }

    }

    if (changed_info != UNCHANGED) {
        tr_info("%s route:", changed_info == NEW ? "Added" : "Updated");
        ipv6_route_print(route);
    }

    return route;
}

int_fast8_t ipv6_route_delete(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source)
{
    return ipv6_route_delete_with_info(prefix, prefix_len, interface_id, next_hop, source, NULL, 0);
}

int_fast8_t ipv6_route_delete_with_info(const uint8_t *prefix, uint8_t prefix_len, int8_t interface_id, const uint8_t *next_hop, ipv6_route_src_t source, void *info, int_fast16_t source_id)
{
    ipv6_route_t *route = ipv6_route_lookup_with_info(prefix, prefix_len, interface_id, next_hop, source, info, source_id);
    if (!route) {
        return -1;
    }

    ipv6_route_entry_remove(route);
    return 0;
}

void ipv6_route_table_remove_interface(int8_t interface_id)
{
    ns_list_foreach_safe(ipv6_route_t, r, &ipv6_routing_table) {
        if (interface_id == r->info.interface_id) {
            ipv6_route_entry_remove(r);
        }
    }
}

static uint8_t ipv6_route_table_count_source(int8_t interface_id, ipv6_route_src_t source)
{
    uint8_t count = 0;
    ns_list_foreach(ipv6_route_t, r, &ipv6_routing_table) {
        if (interface_id == r->info.interface_id && r->info.source == source) {
            count++;
            if (count == 0xff) {
                break;
            }
        }
    }
    return count;
}

static void ipv6_route_table_remove_last_one_from_source(int8_t interface_id, ipv6_route_src_t source)
{
    // Removes last i.e. oldest entry */
    ns_list_foreach_reverse(ipv6_route_t, r, &ipv6_routing_table) {
        if (interface_id == r->info.interface_id && r->info.source == source) {
            ipv6_route_entry_remove(r);
            break;
        }
    }
}


void ipv6_route_table_ttl_update(int seconds)
{
    ns_list_foreach_safe(ipv6_route_t, r, &ipv6_routing_table) {
        if (r->lifetime == 0xFFFFFFFF) {
            continue;
        }

        if (r->lifetime > seconds) {
            r->lifetime -= seconds;
            continue;
        }

        tr_debug("Route expired");
        ipv6_route_entry_remove(r);
    }
}

static uint8_t ipv6_route_table_get_max_entries(int8_t interface_id, ipv6_route_src_t source)
{
    ipv6_neighbour_cache_t *ncache = ipv6_neighbour_cache_by_interface_id(interface_id);

    if (ncache) {
        return ncache->route_if_info.sources[source];
    }

    return 0;
}
