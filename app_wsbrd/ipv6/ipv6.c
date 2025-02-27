/*
 * Copyright (c) 2013-2021, Pelion and affiliates.
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "common/ipv6/ipv6_flow_label.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/specs/ipv6.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ndp.h"
#include "common/specs/rpl.h"
#include "common/specs/ip.h"

#include "ipv6/nd_router_object.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_llc.h"
#include "net/protocol.h"
#include "ipv6/ipv6_routing_table.h"
#include "net/ns_address_internal.h"
#include "rpl/rpl_glue.h"
#include "mpl/mpl.h"

#include "ipv6/icmpv6.h"
#include "ipv6/ipv6_resolution.h"

#include "ipv6/ipv6.h"
#include "app/tun.h"

#define TRACE_GROUP "ipv6"

static buffer_t *ipv6_consider_forwarding_multicast_packet(buffer_t *buf, struct net_if *cur, bool for_us);
static void ipv6_consider_forwarding_multicast_packet_to_lfn(buffer_t *buf, bool for_us);

static bool ipv6_packet_is_for_us(buffer_t *buf)
{
    struct net_if *cur = buf->interface;
    if (buf->dst_sa.addr_type != ADDR_IPV6) {
        return false;
    }

    if (addr_is_ipv6_multicast(buf->dst_sa.address)) {
        return addr_am_group_member_on_interface(cur, buf->dst_sa.address);
    } else if (addr_is_ipv6_loopback(buf->dst_sa.address)) {
        // We should have already dropped it if received externally
        return true;
    } else {
        return addr_interface_address_compare(cur, buf->dst_sa.address) == 0;
    }
}

static ipv6_exthdr_provider_fn_t *ipv6_exthdr_provider[ROUTE_MAX];

/* On entry:
 *     buf->route filled in with data from routing lookup, including source info
 *     buf->dst = final destination
 *     buf->src = source
 *     Other metadata available (eg rpl info from parsing in up)
 * On exit:
 *     buf->dst modified to next hop if source routing
 *     Also possible to modify buf->route->next_hop_addr (eg RPL return to sender,
 *     for forwarding-error, except where would you get the parent addr?)
 *
 * Return negative if failed (will usually end up treated as "no route" error).
 */
static buffer_t *ipv6_get_exthdrs(buffer_t *buf, ipv6_exthdr_stage_e stage, int16_t *result)
{
    if (ipv6_exthdr_provider[buf->route->route_info.source]) {
        return ipv6_exthdr_provider[buf->route->route_info.source](buf, stage, result);
    }
    *result = 0;
    return buf;
}

void ipv6_set_exthdr_provider(ipv6_route_src_t src, ipv6_exthdr_provider_fn_t *fn)
{
    ipv6_exthdr_provider[src] = fn;
}


/* If next_if != NULL, this sends to next_hop on that interface */
buffer_routing_info_t *ipv6_buffer_route_to(buffer_t *buf, const uint8_t *next_hop, struct net_if *next_if)
{
    addrtype_e ll_type;
    const uint8_t *ll_addr;
    buffer_routing_info_t *route;

    if (buf->route) {
        return buf->route;
    }

    buf->route = route = malloc(sizeof(buffer_routing_info_t));
    if (!route) {
        return NULL;
    }

    route->ip_dest = NULL;
    route->ref_count = 1;

    /* Realm-or-lower scope addresses must have interface specified */
    bool interface_specific = addr_ipv6_scope(buf->dst_sa.address) <= IPV6_SCOPE_REALM_LOCAL;
    struct net_if *cur = buf->interface;
    if (cur == NULL && interface_specific) {
        goto no_route;
    }

    ipv6_destination_t *dest_entry = ipv6_destination_lookup_or_create(buf->dst_sa.address, cur ? cur->id : -1);
    if (!dest_entry) {
        tr_error("ipv6_buffer_route no destination entry %s", tr_ipv6(buf->dst_sa.address));
        goto no_route;
    }

    if (next_hop && next_if) {
        if (interface_specific && next_if != buf->interface) {
            tr_error("Next hop interface mismatch %s%%%d vs %s%%%d", tr_ipv6(buf->dst_sa.address), buf->interface->id,
                   tr_ipv6(next_hop), next_if->id);
        }
        memcpy(route->route_info.next_hop_addr, next_hop, 16);
        route->route_info.interface_id = next_if->id;
        route->route_info.pmtu = 0xFFFF;
        route->route_info.source = ROUTE_REDIRECT;
    } else if (addr_is_ipv6_multicast(buf->dst_sa.address)) {
        /*
         * Multicast is handled specially - we always treat as on-link, so the
         * only thing used from the routing table is the interface selection. This
         * is what most network stacks do - basically means we direct on the
         * interface leading to the default router in most cases. We don't support
         * directing to a unicast next-hop, unless this was manually requested.
         */
        if (!cur) {
            /* Choose interface (only) from routing table */
            ipv6_route_t *ip_route = ipv6_route_choose_next_hop(buf->dst_sa.address, -1);
            if (!ip_route) {
                tr_debug("No route for multicast %s", tr_ipv6(buf->dst_sa.address));
                goto no_route;
            }
            route->route_info.interface_id = ip_route->info.interface_id;
        } else {
            route->route_info.interface_id = cur->id;
        }
        memcpy(route->route_info.next_hop_addr, next_hop ? next_hop : buf->dst_sa.address, 16);
        route->route_info.pmtu = 0xFFFF;
        route->route_info.source = ROUTE_MULTICAST;
    } else { /* unicast, normal */
        ipv6_route_t *ip_route = ipv6_route_choose_next_hop(buf->dst_sa.address, interface_specific ? cur->id : -1);
        if (!ip_route) {
            goto no_route;
        }

        route->route_info = ip_route->info;
        /* Above line copies all the main route info, but for on-link routes, we
         * need to fill in next hop from the destination address.
         */
        if (ip_route->on_link) {
            memcpy(route->route_info.next_hop_addr, buf->dst_sa.address, 16);
        }
    }

    struct net_if *outgoing_if = protocol_stack_interface_info_get_by_id(route->route_info.interface_id);
    if (!outgoing_if) {
        goto no_route;      // Shouldn't happen - internal error
    }

    if (buf->options.mpl_permitted &&
        addr_is_ipv6_multicast(buf->dst_sa.address) &&
        addr_ipv6_multicast_scope(buf->dst_sa.address) >= IPV6_SCOPE_REALM_LOCAL) {
        /* Special handling for MPL. Once we have decided we're sending to a
         * multicast next hop for a greater-than-realm-local destination,
         * if we're functioning as an MPL seed on that interface, we turn this
         * into an MPL route. If the destination matches a domain, MPL extension
         * header processing will add the necessary headers, else it will get
         * tunnelled to All-MPL-Forwarders (ff03::fc).
         */
        route->route_info.source = ROUTE_MPL;
    }

    dest_entry->interface_id = route->route_info.interface_id;
    if (!addr_is_ipv6_multicast(dest_entry->destination)) {
        dest_entry->last_neighbour = ipv6_neighbour_lookup(&outgoing_if->ipv6_neighbour_cache, route->route_info.next_hop_addr);

        if (!dest_entry->last_neighbour) {
            if (!ipv6_map_ip_to_ll(outgoing_if, NULL, route->route_info.next_hop_addr, &ll_type, &ll_addr) ||
                ll_type != ADDR_802_15_4_LONG)
                goto no_route;
            dest_entry->last_neighbour = ipv6_neighbour_create(&outgoing_if->ipv6_neighbour_cache,
                                                               route->route_info.next_hop_addr,
                                                               ll_addr + PAN_ID_LEN);
        }
        if (!dest_entry->last_neighbour)
            goto no_route;
    }
    //tr_debug("%s->last_neighbour := %s", tr_ipv6(dest_entry->destination), tr_ipv6(route->route_info.next_hop_addr));

    if (!cur || route->route_info.interface_id != cur->id) {
        struct net_if *new_if = protocol_stack_interface_info_get_by_id(route->route_info.interface_id);
        if (!new_if) {
            goto no_route;
        }
        buf->interface = new_if;
        cur = new_if;
    }

    if (buf->src_sa.addr_type == ADDR_NONE) {
        const uint8_t *src = addr_select_source(cur, buf->dst_sa.address, 0);
        if (!src) {
            tr_debug("No source address");
            goto no_route;
        }
        memcpy(buf->src_sa.address, src, 16);
        buf->src_sa.addr_type = ADDR_IPV6;
    }

    return route;

no_route:
    free(buf->route);
    return buf->route = NULL;
}

buffer_routing_info_t *ipv6_buffer_route(buffer_t *buf)
{
    return ipv6_buffer_route_to(buf, NULL, NULL);
}

/* Compute total IP header size requirements, before its construction
 * src and dst must be originator and final destination, and ipv6_buffer_route()
 * must have been called. This only counts the FIRST IP header and its extension headers -
 * RPL tunnelling takes more thought.
 * Doesn't account for fragmentation header.
 */
uint16_t ipv6_header_size_required(buffer_t *buf)
{
    uint8_t hbh_options = 2; // dummy 2 for initial alignment
    uint16_t ip_size = IPV6_HDRLEN;

    if (buf->options.ip_extflags & IPEXT_HBH_ROUTER_ALERT) {
        hbh_options += 4;
    }

#if 0
    /* If RPL source routing */
    {
        ip_size += srh_size;
    }
    /* else If RPL up/down and NOT tunnelling, ie dest is RPL */
    {
        hbh_options += 6;
    }

    /* If MPL */
    {
        hbh_options += mpl_option_size; // 4 or 6
    }
#endif

    if (hbh_options != 2) {
        ip_size += (hbh_options + 7) & ~ 7;
    }

    return ip_size;
}

uint16_t ipv6_max_unfragmented_payload(buffer_t *buf, uint16_t mtu_limit)
{
    uint16_t ip_size = ipv6_header_size_required(buf);
    uint16_t pmtu = ipv6_mtu(buf);
    uint16_t frag_size;

    if (pmtu < IPV6_MIN_LINK_MTU) {
        /* Small "PMTU" doesn't actually reduce our fragment size */
        frag_size = IPV6_MIN_LINK_MTU;
    } else {
        frag_size = pmtu;
    }

    if (mtu_limit && frag_size > mtu_limit) {
        frag_size = mtu_limit;
    }

    /* If this is true, then we're exceeding a sub-minimum PMTU, so need to
     * include a fragment header, despite not actually fragmenting (RFC 2460, RFC 6415)*/
    if (frag_size > pmtu) {
        ip_size += 8;
    }

    return frag_size - ip_size;
}

#define ipv6_use_min_mtu(buf) buf->options.ipv6_use_min_mtu

/* Return the IPV6 MTU to use for a buffer to a specified final destination.
 * Gives result of Path MTU discovery, unless this is deactivated by
 * a socket option.
 * Note that the MTU returned may be less than the IPv6 minimum if there has
 * been such a "Packet Too Big" response (possibly due to IPv4<->IPv6
 * translation). In this case, it's up to the caller whether they want to
 * obey that MTU (presumably avoiding sub-IPv6 fragmentation at that link),
 * or use the IPv6 minimum (reducing work on other links, but presumably
 * necessitating sub-IPv6 fragmentation there).
 */
uint16_t ipv6_mtu(buffer_t *buf)
{
    int8_t use_min_mtu = ipv6_use_min_mtu(buf);

    if (use_min_mtu == -1) {
        use_min_mtu = addr_is_ipv6_multicast(buf->dst_sa.address);
    }

    if (use_min_mtu) {
        return IPV6_MIN_LINK_MTU;
    }

    return buf->route->route_info.pmtu;
}

/* Input: IP payload. dst/src as source and final destination, type=NH, tclass set.
 * Output: IP header added. With RPL HbH/SRH if necessary.
 *         Buffer source/destination = IP source/destination (matching contents)
 */
buffer_t *ipv6_down(buffer_t *buf)
{
    uint8_t *ptr;
    struct net_if *cur = 0;

    buffer_routing_info_t *route = ipv6_buffer_route(buf);
    /* Note ipv6_buffer_route can change interface */
    if (!route) {
        tr_warn("ipv6_down route fail");
        goto drop;
    }

    cur = buf->interface;
    if (cur == NULL) {
        tr_debug("ipv6_down Drop by Interface_PTR");
        goto drop;
    }

    if (buf->dst_sa.addr_type != ADDR_IPV6) {
        tr_debug("IP:Dest Not IPV6");
        goto drop;
    }
    if (buf->src_sa.addr_type != ADDR_IPV6) {
        tr_debug("IP:SRC Not IPV6");
        goto drop;
    }

    /* Allow this to be decided at the last moment */
    if (buf->options.hop_limit == 0) {
        buf->options.hop_limit = cur->cur_hop_limit;
    }

    /* Choose a flow label if required (RFC 6437) */
    if (buf->options.flow_label == IPV6_FLOW_UNSPECIFIED) {
        buf->options.flow_label = IPV6_FLOW_AUTOGENERATE;
    }
    if (buf->options.flow_label < 0)
        buf->options.flow_label = ipv6_flow_label(buf->src_sa.address,
                                                  buf->dst_sa.address,
                                                  buf->src_sa.port,
                                                  buf->dst_sa.port,
                                                  buf->options.type);

    /* Routing system can insert extension headers now */
    /* If they want IP destination address changed (eg if inserting a routing
     * header), they can set buf->route.ip_dest.
     */
    int16_t exthdr_result;
    buf = ipv6_get_exthdrs(buf, IPV6_EXTHDR_INSERT, &exthdr_result);
    if (!buf) {
        return NULL;
    }
    if (exthdr_result < 0) {
        goto drop;
    }

    uint16_t payload_len = buffer_data_length(buf);

    //tr_debug("IP Header Len: %02x", ip_header_len);
    uint16_t ip_hdr_len = ipv6_header_size_required(buf);

    if ((buf = buffer_headroom(buf, ip_hdr_len)) == NULL) {
        return (buf);
    }
    ptr = buffer_data_reserve_header(buf, ip_hdr_len);
    ptr = write_be32(ptr, (UINT32_C(6) << 28)
                        | ((uint32_t)buf->options.traffic_class << 20)
                        | (buf->options.flow_label & 0xfffff));
    ptr = write_be16(ptr, (ip_hdr_len - IPV6_HDRLEN) + payload_len);
    /* Remember position of Next Header octet - we'll fill it later */
    uint8_t *nh_ptr = ptr++;
    *ptr++ = buf->options.hop_limit;

    if (addr_is_ipv6_multicast(buf->src_sa.address)) {
        tr_error("Illegal source %s", tr_ipv6(ptr));
        goto drop;
    }
    // Copy the source address (IPv6)
    memcpy(ptr, buf->src_sa.address, 16);
    ptr += 16;

    // Copy the destination address (IPv6), either modified by routing, or
    // the original final destination.
    memcpy(ptr, buf->route->ip_dest ? buf->route->ip_dest : buf->dst_sa.address, 16);

    // Last-minute enforcement of a couple of rules on destination from RFC 4291
    if (addr_is_ipv6_unspecified(ptr) ||
            (addr_is_ipv6_multicast(ptr) && addr_ipv6_multicast_scope(ptr) == 0)) {
        tr_error("Illegal destination %s", tr_ipv6(ptr));
        goto drop;
    }
    ptr += 16;

    bool add_hbh = false;
    if (buf->options.ip_extflags & IPEXT_HBH_ROUTER_ALERT) {
        add_hbh = true;
    }

    /* This HbH insertion would conflict with insertion from ipv6_get_exthdrs. */
    /* Fortunately cases never overlap. */
    if (add_hbh) {
        *nh_ptr = IPV6_NH_HOP_BY_HOP;
        nh_ptr = ptr;
        // Come back to fill these in later
        *ptr++ = IPV6_NH_NONE;
        *ptr++ = 0;

        if (buf->options.ip_extflags & IPEXT_HBH_ROUTER_ALERT) {
            *ptr++ = IPV6_OPTION_ROUTER_ALERT;
            *ptr++ = 2; // Length
            ptr = write_be16(ptr, IPV6_ROUTER_ALERT_MLD);
        }
#if 0
        if (multicast) {
            //tr_debug("TRIG Len; %02x", buf->trickle_data_len);
            *ptr++ = IPV6_OPTION_MPL;
            *ptr++ = buf->trickle_data_len;
            memcpy(ptr, buf->trickle_data_field, buf->trickle_data_len);
            ptr += buf->trickle_data_len;
            if (buf->trickle_data_len == 2) {
                *ptr++ = IPV6_OPTION_PADN;
                *ptr++ = 0;
            }
        }
#endif
        uint8_t alignment = (ptr - nh_ptr) & 7;
        if (alignment) {
            uint8_t pad = 8 - alignment;
            if (pad == 1) {
                *ptr++ = IPV6_OPTION_PAD1;
            } else {
                *ptr++ = IPV6_OPTION_PADN;
                *ptr++ = (pad -= 2);
                while (pad) {
                    *ptr = 0, pad--;
                }
            }
        }
        /* Go back and fill in the length byte */
        nh_ptr[1] = ((ptr - nh_ptr) >> 3) - 1;
    }

#if 0
    if (src_route_len) {
        *nh_ptr = IPV6_NH_ROUTING;
        nh_ptr = ptr++;
        *ptr++ = src_route_len;
        ptr = gen_source_route_set(ptr);
    }
#endif

    // Fill in the previous Next Header field
    *nh_ptr = buf->options.type;
    buf->options.type = 0;
    buf->options.code = 0;

    buf->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6 | B_TO_IPV6_FWD);

    return buf;

drop:
    buffer_free(buf);
    return NULL;
}

/* Input: IP packet, either locally-generated, or received and okay to forward
 *        (XXX can currently distinguish with buf->ip_routed_up)
 *        Buffer source/destination = IP source/destination (matching contents)
 * Output: Either go back for another IP header (tunnel entry)
 *         or determine routing information, and pass to transmission.
 *         Next hop IP address will be in buf->route->route_info.next_hop_addr.
 *         (Or loop back up if it's for us).
 */
buffer_t *ipv6_forwarding_down(buffer_t *buf)
{
    /* If it's for us, loop it back up. It goes back into forwarding up, as
     * we should process Destination headers etc...
     * (Note that we could theoretically go forwarding up/down a few times in
     * the event of a weird Routing Header)
     */
    if (ipv6_packet_is_for_us(buf) && !IN6_IS_ADDR_MULTICAST(buf->dst_sa.address)) {
        buf->info = (buffer_info_t)(B_DIR_UP | B_FROM_IPV6_FWD | B_TO_IPV6_FWD);
        return buf;
    }

    ipv6_consider_forwarding_multicast_packet_to_lfn(buf, false);

    /* Note ipv6_buffer_route can change interface */
    if (!ipv6_buffer_route(buf)) {
        tr_info("ipv6_forwarding route fail");
        return icmpv6_error(buf, NULL, ICMPV6_TYPE_ERROR_DESTINATION_UNREACH, ICMPV6_CODE_DST_UNREACH_NO_ROUTE, 0);
    }

    /* Consider multicast forwarding /before/ calling routing code to modify
     * extension headers - if that actually decides to tunnel it will
     * overwrite the buffer's src_sa and dst_sa, when we want to consider
     * forwarding the inner packet. This ordering works out for our only
     * header-modifying multicast case of MPL:
     * 1) We never want to forward packets with MPL headers, which means the
     *    outer packet in a tunnel gets ignored anyway.
     * 2) This also means we don't have to worry that we're forwarding packets
     *    with the extension header not filled in yet.
     * If we ever do have a multicast system where we are working with
     * extension headers and forwarding those across interfaces, ipv6_get_exthdrs
     * system will need a rework - probably split the "try MODIFY" call from the
     * subsequent "give me tunnel parameters" part.
     */
    if (!buf->ip_routed_up && addr_is_ipv6_multicast(buf->dst_sa.address)) {
        buf = ipv6_consider_forwarding_multicast_packet(buf, buf->interface, true);
    }

    /* Allow routing code to update extension headers */
    int16_t exthdr_result;
    buf = ipv6_get_exthdrs(buf, IPV6_EXTHDR_MODIFY, &exthdr_result);
    if (!buf) {
        return NULL;
    }
    if (exthdr_result < 0) {
        goto drop;
    }

    /* Routing code may say it needs to tunnel to add headers - loop back to IP layer if requested */
    if (exthdr_result == IPV6_EXTHDR_MODIFY_TUNNEL) {

        if (buffer_data_length(buf) > IPV6_MIN_LINK_MTU) {
            /* recover IP addresses that icmpv6_error needs, which routing code will have overwritten */
            buf->src_sa.addr_type = ADDR_IPV6;
            memcpy(buf->src_sa.address, buffer_data_pointer(buf) + IPV6_HDROFF_SRC_ADDR, 16);
            buf->dst_sa.addr_type = ADDR_IPV6;
            memcpy(buf->dst_sa.address, buffer_data_pointer(buf) + IPV6_HDROFF_DST_ADDR, 16);
            return icmpv6_error(buf, NULL, ICMPV6_TYPE_ERROR_PACKET_TOO_BIG, 0, IPV6_MIN_LINK_MTU);
        }

        /* Avoid an infinite loop in the event of routing code failure - never
         * let them ask for tunnelling more than once.
         */
        if (buf->options.tunnelled) {
            tr_error("Tunnel recursion");
            goto drop;
        }
        buf->options.tunnelled = true;

        buf->options.ip_extflags = 0;
        buf->options.ipv6_use_min_mtu = -1;

        /* Provide tunnel source, unless already set */
        if (buf->src_sa.addr_type == ADDR_NONE) {
            struct net_if *cur = buf->interface;
            if (!cur) {
                goto drop;
            }
            if (addr_interface_select_source(cur, buf->src_sa.address, buf->dst_sa.address, 0) < 0) {
                tr_error("No tunnel source address");
                goto drop;
            }
            buf->src_sa.addr_type = ADDR_IPV6;
        }
        /* DSCP copied from inner packet */
        buf->options.type = IPV6_NH_IPV6;
        /* Compute new flow label from inner src, dst, flow (RFC 6438) */
        const uint8_t *iphdr = buffer_data_pointer(buf);
        uint24_t flow = read_be24(iphdr + IPV6_HDROFF_FLOW_LABEL) & 0xFFFFF;
        buf->options.flow_label = ipv6_flow_label_tunnel(iphdr + IPV6_HDROFF_SRC_ADDR,
                                                         iphdr + IPV6_HDROFF_DST_ADDR,
                                                         flow);
        buf->options.hop_limit = buf->interface->cur_hop_limit;
        buf->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6);
        return buf;
    }

    buf->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6 | B_TO_IPV6_TXRX);
    return buf;
drop:
    buffer_free(buf);
    return NULL;
}

/* Tunnel exit is only needed (and allowed!) for RPL and MPL */
#define IP_ECN__DROP -1

/*
 * 4x4 array implementing the ECN combination rules from RFC 6040.
 *
 * Summary visualisation:      Outer
 *                             N01C
 *                            +----
 *                           N|NNN-
 *                    Inner  0|001C
 *                           1|111C
 *                           C|CCCC
 *
 * Each of the 16 entries [outer][inner], with justification:
 */
static const int8_t exit_ecn_combination[4][4] = {
    // If the inner is Not-ECT, we mustn't propagate ECN markings onwards
    // So we strip off any capability flags
    [IP_ECN_NOT_ECT][IP_ECN_NOT_ECT] = IP_ECN_NOT_ECT,
    [IP_ECN_ECT_0  ][IP_ECN_NOT_ECT] = IP_ECN_NOT_ECT,
    [IP_ECN_ECT_1  ][IP_ECN_NOT_ECT] = IP_ECN_NOT_ECT,

    // And if we see congestion experienced, we drop to indicate congestion
    [IP_ECN_CE     ][IP_ECN_NOT_ECT] = IP_ECN__DROP,

    // If inner supports ECN, we set outgoing to most severe (C>1>0>N)
    [IP_ECN_NOT_ECT][IP_ECN_ECT_0  ] = IP_ECN_ECT_0,
    [IP_ECN_ECT_0  ][IP_ECN_ECT_0  ] = IP_ECN_ECT_0,
    [IP_ECN_ECT_1  ][IP_ECN_ECT_0  ] = IP_ECN_ECT_1,
    [IP_ECN_CE     ][IP_ECN_ECT_0  ] = IP_ECN_CE,

    [IP_ECN_NOT_ECT][IP_ECN_ECT_1  ] = IP_ECN_ECT_1,
    [IP_ECN_ECT_0  ][IP_ECN_ECT_1  ] = IP_ECN_ECT_1,
    [IP_ECN_ECT_1  ][IP_ECN_ECT_1  ] = IP_ECN_ECT_1,
    [IP_ECN_CE     ][IP_ECN_ECT_1  ] = IP_ECN_CE,

    [IP_ECN_NOT_ECT][IP_ECN_CE     ] = IP_ECN_CE,
    [IP_ECN_ECT_0  ][IP_ECN_CE     ] = IP_ECN_CE,
    [IP_ECN_ECT_1  ][IP_ECN_CE     ] = IP_ECN_CE,
    [IP_ECN_CE     ][IP_ECN_CE     ] = IP_ECN_CE,
};

/* On entry, buf is original IPv6 packet, payload points to outer packet's
 * protocol payload (ie the start of the inner IPv6 header.)
 */
static buffer_t *ipv6_tunnel_exit(buffer_t *buf, uint8_t *payload)
{
    buf->options.ip_extflags = 0;

    buffer_data_pointer_set(buf, payload);

    /*
     * First 8 bytes of the IP header that we need to patch:
     * .               .               .               .               .
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Version|   DSCP    |ECN|           Flow Label                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Payload Length        |  Next Header  |   Hop Limit   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    if (buffer_data_length(buf) >= IPV6_HDRLEN) {
        /* RFC 6040 - combine ECN */
        uint8_t inner_tclass = (payload[0] << 4) | (payload[1] >> 4);
        uint8_t outer_ecn = buf->options.traffic_class & IP_TCLASS_ECN_MASK;
        uint8_t inner_ecn = inner_tclass & IP_TCLASS_ECN_MASK;
        uint8_t inner_dscp = inner_tclass & IP_TCLASS_DSCP_MASK;
        int8_t outgoing_ecn = exit_ecn_combination[outer_ecn][inner_ecn];
        if (outgoing_ecn == IP_ECN__DROP) {
            goto drop;
        }

        /* RFC 2983 uniform model - copy DSCP from inner packet */
        uint8_t outgoing_tclass = inner_dscp | outgoing_ecn;

        /* Write the outgoing traffic-class field */
        payload[0] = (payload[0] & 0xf0) | (outgoing_tclass >> 4);
        payload[1] = (outgoing_tclass << 4) | (payload[1] & 0x0f);

        /* We would like RFC 3443-style "uniform model" Hop Limit handling. As
         * tunnel entry, we transfer the Hop Limit from the inner to the outer
         * packet. On exit we transfer from outer back to inner (and outer must
         * be lower than inner). Just in case another entry implementation didn't do
         * this and set a big outer, we take the minimum of inner and outer.
         */
        if (payload[IPV6_HDROFF_HOP_LIMIT] > buf->options.hop_limit) {
            payload[IPV6_HDROFF_HOP_LIMIT] = buf->options.hop_limit;
        }
    }


    buf->info = (buffer_info_t)(B_DIR_UP | B_TO_IPV6_FWD | B_FROM_IPV6_FWD);
    return buf;

drop:
    return buffer_free(buf);
}

static buffer_t *ipv6_handle_options(buffer_t *buf, struct net_if *cur,
                                     uint8_t *ptr, uint16_t payload_length,
                                     uint16_t *hdrlen_out, bool pre_fragment)
{
    uint8_t *opt_type_ptr;

    if (payload_length < 2) {
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, 4);
    }

    uint16_t hlen = (ptr[1] + 1) * 8;
    if (payload_length < hlen) {
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, (ptr + 1) - buffer_data_pointer(buf));
    }

    if (pre_fragment) {
        *hdrlen_out = hlen;
        return buf;
    }

    uint8_t *opt = ptr + 2;
    const uint8_t *const end = ptr + hlen;
    while (opt < end) {
        if (opt[0] == IPV6_OPTION_PAD1) {
            opt++;
            continue;
        }
        opt_type_ptr = opt++;
        if (opt >= end) {
            goto len_err;
        }
        uint8_t optlen = *opt++;
        if (opt + optlen > end) {
            goto len_err;
        }
        switch (*opt_type_ptr) {
            case IPV6_OPTION_RPI:
            case IPV6_OPTION_RPI_DEPRECATED:
                if (!rpl_glue_process_rpi(&cur->rpl_root, buf, opt, optlen))
                    goto drop;
                // FIXME: hack to allow ignoring RPI from the kernel.
                *opt_type_ptr = IPV6_OPTION_RPI;
                break;
            case IPV6_OPTION_MPL:
                if (!mpl_hbh_len_check(opt, optlen)) {
                    goto len_err;
                }
                if (!mpl_process_hbh(buf, cur, opt)) {
                    goto drop;
                }
                break;
            default:
                *opt_type_ptr &= IPV6_OPTION_ACTION_MASK;
                if (*opt_type_ptr == IPV6_OPTION_ACTION_SKIP) {
                    break;
                }
                if (*opt_type_ptr == IPV6_OPTION_ACTION_ERROR ||
                        (*opt_type_ptr == IPV6_OPTION_ACTION_ERROR_UNICAST && !addr_is_ipv6_multicast(buf->dst_sa.address))) {
                    return icmpv6_error(buf, NULL, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_UNREC_IPV6_OPT, (opt - 2) - buffer_data_pointer(buf));
                }
                /* falling to */
drop:
                return buffer_free(buf);

len_err:
                return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, (opt - 1) - buffer_data_pointer(buf));
        }
        opt += optlen;
    }

    *hdrlen_out = hlen;

    return buf;
}

static buffer_t *ipv6_handle_routing_header(buffer_t *buf, struct net_if *cur, uint8_t *ptr, uint16_t payload_length, uint16_t *hdrlen_out, bool *forward_out, bool pre_fragment)
{
    if (buf->options.ll_security_bypass_rx) {
        tr_warn("Routing header: Security check fail");
        return buffer_free(buf);
    }

    if (payload_length < 4) {
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, 4);
    }

    uint16_t hlen = (ptr[1] + 1) * 8;
    if (payload_length < hlen) {
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, (ptr + 1) - buffer_data_pointer(buf));
    }

    if (pre_fragment) {
        *hdrlen_out = hlen;
        return buf;
    }

    uint8_t type = ptr[2];
    uint8_t segs_left = ptr[3];
    switch (type) {
        default:
            /* Unknown type: if segments left is 0, we ignore the header, else return an error */
            if (segs_left == 0) {
                *hdrlen_out = hlen;
            } else {
                return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, (ptr + 2) - buffer_data_pointer(buf));
            }
            break;
    }

    return buf;
}

static buffer_t *ipv6_tun_up(buffer_t *b)
{
    ssize_t status;

    // FIXME: do not call app_wsbrd directly. Use a callback instead.
    status = wsbr_tun_write(buffer_data_pointer(b), buffer_data_length(b));
    if (status <= 0)
        tr_warn("packet not sent to tun interface: %m");
    return buffer_free(b);
}

static buffer_t *ipv6_consider_forwarding_unicast_packet(buffer_t *buf, struct net_if *cur)
{
    /* Security checks needed here before forwarding */
    if (buf->options.ll_security_bypass_rx) {
        tr_warn("IP Forward: Security check fail dst %s", tr_ipv6(buf->dst_sa.address));
        return buffer_free(buf);
    }

    if (addr_is_ipv6_loopback(buf->dst_sa.address) ||
        addr_is_ipv6_unspecified(buf->src_sa.address)) {
        return buffer_free(buf);
    }

    /* Hop limit check and decrement */
    if (buf->options.hop_limit <= 1) {
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_TIME_EXCEEDED, ICMPV6_CODE_TME_EXCD_HOP_LIM_EXCD, 0);
    }

    buf->ip_routed_up = true;
    buffer_data_pointer(buf)[IPV6_HDROFF_HOP_LIMIT] = --buf->options.hop_limit;

    /* Not for us, let's think about forwarding */
    /* Note ipv6_buffer_route can change interface  */
    buffer_routing_info_t *routing = ipv6_buffer_route(buf);

    // If we can't route inside the network, let's try outside !
    if (!routing)
        return ipv6_tun_up(buf);

    struct net_if *out_interface;
    out_interface = buf->interface;

    /* If heading out a different interface, some extra scope checks for
     * crossing a zone boundary (see RFC 4007).
     */
    if (out_interface->id != cur->id) {
        uint8_t src_scope = addr_ipv6_scope(buf->src_sa.address);
        /* Check source scope (standard RFC 4007 test) */
        if (out_interface->zone_index[src_scope] != cur->zone_index[src_scope]) {
            buf->interface = cur;
            return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_DESTINATION_UNREACH, ICMPV6_CODE_DST_UNREACH_BEYOND_SCOPE, 0);
        }
//#ifdef THREAD_SUPPORT
        /* Handle a Thread-specific wrinkle - Thread's "Realm-local" address
         * is really a ULA, so is global on other interfaces, and is treated
         * as such for routing purposes. There's nothing in the routing system
         * stopping a packet going into or out of Thread with a Realm-local
         * address. The generic code above has handled the case:
         *
         *    Thread->External src=RL ("Beyond scope of source address")
         *
         * Here we block the other cases:
         *
         *    External->Thread src=RL ("Source address failed ingress/egress policy")
         *    Thread<->External dst=RL ("Communication with destination administratively prohibited")
         *
         * (NB if a real Realm-local address was defined, then we'd make routing
         * treat it like link-local, and we'd never find ourselves routing
         * to another interface, catching the first two cases, and the last
         * would have been caught by "Beyond scope of source address").
         */
        if (addr_ipv6_scope(buf->src_sa.address) <= IPV6_SCOPE_REALM_LOCAL) {
            buf->interface = cur;
            return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_DESTINATION_UNREACH, ICMPV6_CODE_DST_UNREACH_SRC_FAILED_POLICY, 0);
        }
        if (addr_ipv6_scope(buf->dst_sa.address) <= IPV6_SCOPE_REALM_LOCAL) {
            buf->interface = cur;
            return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_DESTINATION_UNREACH, ICMPV6_CODE_DST_UNREACH_ADM_PROHIB, 0);
        }
//#endif
    }

    /* route_info.pmtu will cover limits from both the interface and the
     * route. As a bonus, it will also cover any PMTUD we happen to have done
     * to that destination ourselves. Extra limits due to tunnelling are checked on tunnel entry in ipv6_down.
     */
    if (routing->route_info.pmtu < buffer_data_length(buf)) {
        buf->interface = cur;
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PACKET_TOO_BIG, 0, routing->route_info.pmtu);
    }

    /* Pass to "forwarding down" */
    buf->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6_FWD);
    return buf;
}

void ipv6_transmit_multicast_on_interface(buffer_t *buf, struct net_if *cur)
{
    /* Mess with routing to get this to go out the correct interface */
    buf->interface = cur;
    if (!ipv6_buffer_route_to(buf, buf->dst_sa.address, cur)) {
        buffer_free(buf);
        return;
    }

    /* Send straight to IP transmission? Or to forwarding down? */
    buf->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6_FWD);
    protocol_push(buf);
}

/* Traditional multicast forwarding - from one interface to other(s).
 * Used for example for ff05::1 across the border router. This is limited to
 * scop values 4 and up, as we assume realms don't cross interfaces.
 *
 * This is distinct from MPL, which runs its own forwarding strategy. That is
 * used for scop 3 (realm). [It could run at higher scopes, except the MPL
 * code currently only transmits on 1 interface - rather than repeating on
 * multiple].
 *
 * The two can be mixed, eg by encapsulating an ff05::1 packet in an MPL
 * packet to ff03::fc. That would be spread by the MPL forwarding logic, and
 * the border router would de-encapsulate and forward to Ethernet via this.
 */

/* "For us" tells us that we need to return the buffer (or a copy) - if false, we don't */
/* This controls copying logic. */
static buffer_t *ipv6_consider_forwarding_multicast_packet(buffer_t *buf, struct net_if *cur, bool for_us)
{
    /* Security checks needed here before forwarding */
    if (buf->options.ll_security_bypass_rx) {
        goto no_forward;
    }

    /* Hop limit check */
    if (buf->options.hop_limit <= 1) {
        goto no_forward;
    }

    if (addr_is_ipv6_unspecified(buf->src_sa.address))
        goto no_forward;

    /* MPL does its own thing - we do not perform any "native" forwarding */
    if (buf->options.ip_extflags & IPEXT_HBH_MPL) {
        goto no_forward;
    }

no_forward:
    /* Base functionality - if it's for us, return it, else bin it */
    if (for_us) {
        return buf;
    } else {
        return buffer_free(buf);
    }
}

static void ipv6_consider_forwarding_multicast_packet_to_lfn(buffer_t *buf, bool for_us)
{
    buffer_t *clone;

    if (!IN6_IS_ADDR_MULTICAST(buf->dst_sa.address) || buf->options.lfn_multicast)
        return;

    // In Wi-SUN FAN 1.1v07 - 6.2.3.1.2.2 Multicast Addresses,
    // All FAN nodes MUST recognize the link-local-scope all-nodes group
    // (ff02::1) [RFC4291] as identifying itself.
    // [...]
    // With the exception of the link-local-scope all-nodes group (ff02::1),
    // to participate in any other multicast group an LFN MUST use the LFN
    // Multicast Group Enrollment mechanism described in section 6.2.3.1.4.3.
    if (addr_ipv6_multicast_scope(buf->dst_sa.address) < IPV6_SCOPE_REALM_LOCAL && for_us)
        return;
    if (!ipv6_neighbour_lookup(&buf->interface->ipv6_neighbour_cache, buf->dst_sa.address) &&
        memcmp(buf->dst_sa.address, ADDR_LINK_LOCAL_ALL_NODES, 16))
        return;
    if (!ws_neigh_lfn_count(&buf->interface->ws_info.neighbor_storage))
        return;

    clone = buffer_clone(buf);
    if (!clone)
        return;

    clone->route = ipv6_buffer_route(clone);
    clone->options.lfn_multicast = true;
    clone->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6 | B_TO_IPV6_TXRX);
    protocol_push(clone);
    buf->options.lfn_multicast = false;
}

static bool is_for_linux(uint8_t next_header, const uint8_t *data_ptr)
{
    switch (next_header) {
    case IPV6_NH_IPV6:
        return false;
    case IPV6_NH_ICMPV6:
        if (data_ptr[0] == ICMPV6_TYPE_NS)
            return false;
        if (data_ptr[0] == ICMPV6_TYPE_NA)
            return false;
    default:
        return true;
    }
}

static void ipv6_refresh_neighbor_lifetime(buffer_t *buf, const sockaddr_t *ll_src)
{
    ipv6_neighbour_t *ipv6_neighbour = ipv6_neighbour_lookup(&buf->interface->ipv6_neighbour_cache, buf->src_sa.address);
    struct ws_neigh *ws_neigh;
    struct ipv6_nd_opt_earo aro;
    uint8_t eui64[8];

    if (ll_src->addr_type == ADDR_802_15_4_LONG)
        memcpy(eui64, ll_src->address + PAN_ID_LEN, 8);
    else
        return;

    if (!ipv6_neighbour || ipv6_neighbour->type != IP_NEIGHBOUR_REGISTERED)
        return;

    if (memcmp(ipv6_neighbour_eui64(&buf->interface->ipv6_neighbour_cache, ipv6_neighbour), eui64, 8))
        return;

    ws_neigh = ws_neigh_get(&buf->interface->ws_info.neighbor_storage, eui64);
    if (!ws_neigh)
        return;

    aro.status = NDP_ARO_STATUS_SUCCESS;
    aro.lifetime = ws_neigh->lifetime_s / 60;

    nd_update_registration(buf->interface, ipv6_neighbour, &aro, ws_neigh);
}

buffer_t *ipv6_forwarding_up(buffer_t *buf)
{
    uint8_t *ptr = buffer_data_pointer(buf);
    uint16_t len = buffer_data_length(buf);
    uint8_t *nh_ptr;
    struct net_if *cur;
    bool intercept = false;

    /* When processing a reassembled packet, we don't reprocess headers from before the fragment header */
    uint16_t frag_offset;

    cur = buf->interface;

    // Make sure that this is a v6 header (just in case...)
    if (!cur || len < IPV6_HDRLEN || (*ptr >> 4) != 6) {
        goto drop;
    }

    if (buf->options.ip_extflags & IPEXT_FRAGMENT) {
        // Remember the flags for headers we parsed before the fragment header;
        // we won't re-parse them, and expect the metadata (from the first fragment)
        // to survive reassembly.
        frag_offset = buf->offset;
        buf->options.ip_extflags &= ~ IPEXT_FRAGMENT;
        tr_debug("Processing fragment from %d", frag_offset);
    } else {
        // Clear all info - extension header parsers will set
        frag_offset = 0;
        buf->options.ip_extflags = 0;
    }

    buf->options.traffic_class = (ptr[0] << 4) | (ptr[1] >> 4);
    // Just skip Flow Label for now
    ptr += 4;

    uint16_t payload_length = read_be16(ptr);
    ptr += 2;

    // "Parameter problem" needs this pointer to Next Header field
    nh_ptr = ptr++;

    // May as well note the outermost NH field now; will update later
    // if we go to an upper layer.
    buf->options.type = *nh_ptr;
    buf->options.code = 0;

    // Read the Hop Limit
    buf->options.hop_limit = *ptr++;

    // Remember the link-layer address for "special forwarding" check
    sockaddr_t ll_src = buf->src_sa;

    // Get the Source Address
    memcpy(buf->src_sa.address, ptr, 16);
    buf->src_sa.addr_type = ADDR_IPV6;
    ptr += 16;

    // Get the Destination Address
    memcpy(buf->dst_sa.address, ptr, 16);
    buf->dst_sa.addr_type = ADDR_IPV6;
    ptr += 16;

    /* XXX I'm using ip_routed_up as a "received from outside this node" check
     * Not sure if that was original intent... We do want to accept it if it came
     * from inside this node.
     */
    if (addr_is_ipv6_multicast(buf->src_sa.address) ||
            (buf->ip_routed_up && (addr_is_ipv6_loopback(buf->dst_sa.address) ||
                                   addr_is_ipv6_loopback(buf->src_sa.address)))
       ) {
        goto drop;
    }

    if (addr_is_ipv6_multicast(buf->dst_sa.address)) {
        /* RFC 4291 says we must drop multicast packets with scope 0 */
        if (addr_ipv6_multicast_scope(buf->dst_sa.address) == 0) {
            goto drop;
        }
    } else {
        /* RFC 1122 and 1812 say we SHOULD silently discard packets with unicast IP
         * address but link-layer multicast or broadcast. And we MUST NOT forward
         * them. So catch them here.
         */
        if (buf->options.ll_broadcast_rx) {
            goto drop;
        }
    }

    /* If security bypass is set, we only allow link-local traffic (unicast
     * or multicast with link-local scope), as per ZigBee IP
     */
    if (buf->options.ll_security_bypass_rx) {
        if (addr_ipv6_scope(buf->dst_sa.address) != IPV6_SCOPE_LINK_LOCAL) {
            goto drop;
        }
    }

    if (IPV6_HDRLEN + payload_length > buffer_data_length(buf)) {
        // Return "Parameter problem", pointing at Payload Length
        return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, 4);
    }

    /* Trim buffer if it's longer than payload length stated in IP header */
    if (IPV6_HDRLEN + payload_length < buffer_data_length(buf)) {
        buffer_data_length_set(buf, IPV6_HDRLEN + payload_length);
    }

    /* Handle any hop-by-hop options first, before checking destination */
    if (*nh_ptr == IPV6_NH_HOP_BY_HOP) {
        uint16_t hdrlen = 0;
        if (payload_length == 0) {
            // RFC 2675 - return "Parameter problem", pointing at Payload Length
            return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, 4);
        }
        buf = ipv6_handle_options(buf, cur, ptr, payload_length, &hdrlen,
                                  ptr - buffer_data_pointer(buf) < frag_offset);
        if (hdrlen == 0) {
            /* Something went wrong - it will have freed buf or turned it into an ICMP error */
            return buf;
        }
        nh_ptr = ptr;
        ptr += hdrlen;
        payload_length -= hdrlen;
    }

    if (*nh_ptr == IPV6_NH_ICMPV6 && payload_length >= 4 && ptr[0] == ICMPV6_TYPE_NS) {
        /* Treat as ours, let NS reply */
        intercept = true;
    }

    /* We don't reprocess if this is a reassembly - each fragment is its own MPL
     * Data Message, and we already processed them.
     */
    if ((buf->options.ip_extflags & IPEXT_HBH_MPL) && !frag_offset) {
        if (!mpl_forwarder_process_message(buf, NULL, false)) {
            /* False return means "duplicate" or other reason not to process */
            return buffer_free(buf);
        }
    }

    bool for_us = intercept || ipv6_packet_is_for_us(buf);

    if (addr_is_ipv6_multicast(buf->dst_sa.address)) {
        /* Multicast forwarding is told whether we're interested. It may
         * clone or take ownership of the buffer, depending on for_us. If not
         * forwarding or for us, it will bin.
         */
        ipv6_consider_forwarding_multicast_packet_to_lfn(buf, for_us);
        buf = ipv6_consider_forwarding_multicast_packet(buf, cur, for_us);
        if (!buf) {
            return NULL;
        }
        if (is_for_linux(*nh_ptr, ptr))
            return ipv6_tun_up(buf);
    } else { /* unicast */
        if (buf->link_specific.ieee802_15_4.requestAck)
            ipv6_refresh_neighbor_lifetime(buf, &ll_src);

        if (!for_us)
            return ipv6_consider_forwarding_unicast_packet(buf, cur);
        if (is_for_linux(*nh_ptr, ptr))
            return ipv6_tun_up(buf);
    }

    /* Its destination is us (or we're intercepting) - start munching headers */
    /* Guess this should ultimately be the "CIPV6" up layer */
    for (;;) {
        uint16_t hdrlen = 0;
        if (payload_length == 0 && *nh_ptr != IPV6_NH_NONE) {
            // RFC 2675 - return "Parameter problem", pointing at Payload Length
            return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_HDR_ERR, 4);
        }
        switch (*nh_ptr) {
            case IPV6_NH_NONE:
                return buffer_free(buf);
            case IPV6_NH_DEST_OPT:
                buf = ipv6_handle_options(buf, cur, ptr, payload_length, &hdrlen,
                                          ptr - buffer_data_pointer(buf) < frag_offset);
                nh_ptr = ptr;
                break;
            case IPV6_NH_ROUTING: {
                bool forward = false;
                buf = ipv6_handle_routing_header(buf, cur, ptr, payload_length, &hdrlen, &forward, ptr - buffer_data_pointer(buf) < frag_offset);
                if (forward) {
                    /* Note that forwarding will cope with looping back if next address is
                     * actually ours. We do want to always treat it as forwarding, as we do
                     * want hop counts decremented, etc.
                     */
                    return ipv6_consider_forwarding_unicast_packet(buf, cur);
                }
                nh_ptr = ptr;
                break;
            }
            case IPV6_NH_UDP:
                buf->info = (buffer_info_t)(B_DIR_UP | B_TO_UDP | B_FROM_IPV6_FWD);
                /* UDP may want to generate ICMP "port unreachable", so we leave the
                 * IP headers unconsumed, setting offset to point to the UDP header
                 */
                buf->options.type = IPV6_NH_UDP;
                buf->offset = ptr - buffer_data_pointer(buf);
                return buf;
            case IPV6_NH_ICMPV6:
                buf->info = (buffer_info_t)(B_DIR_UP | B_TO_ICMP | B_FROM_IPV6_FWD);
                goto upper_layer;
            case IPV6_NH_IPV6:
                /* Tunnel support is only used for RPL or MPL. Only permit tunnel exit if there was
                  * a RPL or MPL HbH option header, or RPL SRH header. Gives security, as
                  * long as border router doesn't forward such packets into rpl/MPL domain.
                  */
                if (!(buf->options.ip_extflags & (IPEXT_HBH_RPL | IPEXT_SRH_RPL | IPEXT_HBH_MPL))) {
                    goto bad_nh;
                }
                buf->options.type = *nh_ptr;
                return ipv6_tunnel_exit(buf, ptr);
            default: {
                goto bad_nh;
            }
bad_nh:
            return icmpv6_error(buf, cur, ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM, ICMPV6_CODE_PARAM_PRB_UNREC_NEXT_HDR, nh_ptr - buffer_data_pointer(buf));
        }
        if (hdrlen == 0) {
            /* Something went wrong in an extension header - it will have freed buf or turned it into an ICMP error */
            return buf;
        }
        ptr += hdrlen;
        payload_length -= hdrlen;
    }
upper_layer:
    buf->options.type = *nh_ptr;
    buffer_data_pointer_set(buf, ptr);
    return buf;

drop:
    return buffer_free(buf);
}
