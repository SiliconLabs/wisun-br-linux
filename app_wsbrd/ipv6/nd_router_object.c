/*
 * Copyright (c) 2013-2020, Pelion and affiliates.
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
#include "common/ws/ws_neigh.h"
#include "common/string_extra.h"
#include "common/time_extra.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/bits.h"
#include "common/specs/ndp.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ipv6.h"

#include "app/tun.h" // FIXME
#include "net/protocol.h"
#include "ipv6/icmpv6.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "ipv6/ipv6_neigh_storage.h"
#include "ipv6/ipv6_routing_table.h"

#include "ipv6/nd_router_object.h"

static void nd_add_ipv6_neigh_route(struct net_if *net_if, struct ipv6_neighbour *neigh)
{
    ipv6_route_add_metric(neigh->ip_address, 128, net_if->id, neigh->ip_address,
                          ROUTE_ARO, NULL, 0, neigh->lifetime_s - 2, 32);
    tun_add_node_to_proxy_neightbl(net_if, neigh->ip_address);
    tun_add_ipv6_direct_route(net_if, neigh->ip_address);
}

void nd_update_registration(struct net_if *cur_interface, ipv6_neighbour_t *neigh, const struct ipv6_nd_opt_earo *aro,
                            struct ws_neigh *ws_neigh)
{
    struct rpl_target *target;

    TRACE(TR_NEIGH_IPV6, "IPv6 neighbor refresh %s / %s / %ds",
          tr_eui64(ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh)),
          tr_ipv6(neigh->ip_address), aro->lifetime * UINT32_C(60));

    /* We are about to send an ARO response - update our Neighbour Cache accordingly */
    if (aro->status == NDP_ARO_STATUS_SUCCESS && aro->lifetime != 0) {
        neigh->type = IP_NEIGHBOUR_REGISTERED;
        neigh->lifetime_s = aro->lifetime * UINT32_C(60);
        neigh->expiration_s = time_now_s(CLOCK_MONOTONIC) + neigh->lifetime_s;
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        /* Register with 2 seconds off the lifetime - don't want the NCE to expire before the route */
        if (!IN6_IS_ADDR_MULTICAST(neigh->ip_address)) {
            nd_add_ipv6_neigh_route(cur_interface, neigh);
            BUG_ON(!ws_neigh);
            ws_neigh_refresh(&cur_interface->ws_info.neighbor_storage, ws_neigh, aro->lifetime * UINT32_C(60));
        }
    } else {
        // ipv6_neighbor entry will be released by garbage collector
        neigh->lifetime_s = 0;
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        if (!IN6_IS_ADDR_MULTICAST(neigh->ip_address)) {
            target = rpl_target_get(&cur_interface->rpl_root, neigh->ip_address);
            if (target)
                rpl_target_del(&cur_interface->rpl_root, target);
        }
    }
    ipv6_neigh_storage_save(&cur_interface->ipv6_neighbour_cache, ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh));
}

void nd_remove_aro_routes_by_eui64(struct net_if *net_if, const uint8_t *eui64)
{
    ns_list_foreach_safe(ipv6_neighbour_t, neigh, &net_if->ipv6_neighbour_cache.list)
        if ((neigh->type == IP_NEIGHBOUR_REGISTERED || neigh->type == IP_NEIGHBOUR_TENTATIVE) &&
            !memcmp(ipv6_neighbour_eui64(&net_if->ipv6_neighbour_cache, neigh), eui64, 8) &&
            !IN6_IS_ADDR_MULTICAST(neigh->ip_address))
            ipv6_route_delete(neigh->ip_address, 128, net_if->id, neigh->ip_address, ROUTE_ARO);
}

void nd_restore_aro_routes_by_eui64(struct net_if *net_if, const uint8_t *eui64)
{
    ns_list_foreach_safe(ipv6_neighbour_t, neigh, &net_if->ipv6_neighbour_cache.list)
        if ((neigh->type == IP_NEIGHBOUR_REGISTERED || neigh->type == IP_NEIGHBOUR_TENTATIVE) &&
            !memcmp(ipv6_neighbour_eui64(&net_if->ipv6_neighbour_cache, neigh), eui64, 8) &&
            !IN6_IS_ADDR_MULTICAST(neigh->ip_address))
            nd_add_ipv6_neigh_route(net_if, neigh);
}

/* Process ICMP Neighbor Solicitation (RFC 4861 + RFC 6775 + RFC 8505 + draft-ietf-6lo-multicast-registration-15) EARO. */
bool nd_ns_earo_handler(struct net_if *cur_interface, const uint8_t *earo_ptr, size_t earo_len,
                        const uint8_t *slla_ptr, const uint8_t src_addr[16], const uint8_t target[16],
                        struct ipv6_nd_opt_earo *na_earo)
{
    const uint8_t *registered_addr = src_addr;
    struct iobuf_read earo = {
        .data_size = earo_len,
        .data = earo_ptr,
    };
    struct ws_neigh *ws_neigh;
    ipv6_neighbour_t *neigh;
    sockaddr_t ll_addr;
    uint8_t flags;
    uint8_t tid;

    //   RFC 6775 Section 6.5 - Processing a Neighbor Solicitation
    // If the source address of the NS is the unspecified address, or if no
    // SLLAO is included, then any included ARO is ignored, that is, the NS
    // is processed as if it did not contain an ARO.
    if (addr_is_ipv6_unspecified(src_addr) || !slla_ptr)
        return true;

    // Ignore ARO if SLLAO is incorrect
    if (!cur_interface->if_llao_parse(cur_interface, slla_ptr, &ll_addr))
        return true;

    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Type = 33   |   Length = 2  |    Status     |    Opaque     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Rsv| P | I |R|T|      TID      |     Registration Lifetime     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                            EUI-64                             |
     * +                              or                               +
     * |             Registration Ownership Verifier (ROVR)            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    BUG_ON(iobuf_pop_u8(&earo) != NDP_OPT_ARO);
    //   RFC 6775 Section 6.5 - Processing a Neighbor Solicitation
    // In addition to the normal validation of an NS and its options, the ARO
    // is verified as follows (if present).  If the Length field is not two, or
    // if the Status field is not zero, then the NS is silently ignored.
    if (iobuf_pop_u8(&earo) != 2) // Length
        return false;
    if (iobuf_pop_u8(&earo) != NDP_ARO_STATUS_SUCCESS)
        return false;
    iobuf_pop_u8(&earo); // Opaque
    flags = iobuf_pop_u8(&earo);
    tid   = iobuf_pop_u8(&earo);
    na_earo->lifetime = iobuf_pop_be16(&earo);
    iobuf_pop_data(&earo, na_earo->eui64, 8);

    na_earo->t = FIELD_GET(NDP_MASK_ARO_T, flags);
    na_earo->r = FIELD_GET(NDP_MASK_ARO_R, flags);
    na_earo->p = FIELD_GET(NDP_MASK_ARO_P, flags);

    if (na_earo->p != NDP_ADDR_TYPE_UNICAST && na_earo->p != NDP_ADDR_TYPE_MULTICAST) {
        TRACE(TR_DROP, "drop %-9s: invalid P flag value in EARO: %d", "ns", na_earo->p);
        return false;
    }

    // FIXME: It is not clear how ARO and EARO are differentiated.
    // This hack is based on the Wi-SUN specification.
    if (na_earo->t && (na_earo->r || na_earo->p == NDP_ADDR_TYPE_MULTICAST)) {
        //   RFC 8505 Section 5.6 - Link-Local Addresses and Registration
        // When sending an NS(EARO) to a 6LR, a 6LN MUST use a Link-Local
        // Address as the Source Address of the registration, whatever the type
        // of IPv6 Address that is being registered.  That Link-Local Address
        // MUST be either an address that is already registered to the 6LR or
        // the address that is being registered.
        if (!addr_is_ipv6_link_local(src_addr)) {
            na_earo->present = true;
            na_earo->status = NDP_ARO_STATUS_INVALSRC;
            return true;
        }
        //   RFC 8505 Section 5.1 - Extending the Address Registration Option
        // The Target Address field in the NS containing the EARO is now the
        // field that indicates the address that is being registered, as
        // opposed to the Source Address field in the NS as specified in
        // [RFC6775] (see Section 5.5).
        registered_addr = target;
        // Normally in Wi-SUN the border router receives a DAO from the FFN
        // parenting the LFN, and responds with a DAO-ACK triggering the
        // sending of a NA(EARO) by the FFN to its LFN child. The case where
        // the border router is a direct parent isn't fully described, but it
        // makes sense to register the address and respond with a NA(EARO).
        na_earo->present = true;
        na_earo->status = NDP_ARO_STATUS_SUCCESS;
        na_earo->tid = tid;
        if (na_earo->p == NDP_ADDR_TYPE_MULTICAST)
            if (addr_ipv6_equal(ADDR_ALL_MPL_FORWARDERS, registered_addr) ||
                !IN6_IS_ADDR_MULTICAST(registered_addr) ||
                addr_ipv6_multicast_scope(registered_addr) < IPV6_SCOPE_LINK_LOCAL) {
                TRACE(TR_IGNORE, "invalid multicast address in earo: %s", tr_ipv6(registered_addr));
                na_earo->status = NDP_ARO_STATUS_INVALTOPO;
                return true;
            }
    }

    if (na_earo->p == NDP_ADDR_TYPE_MULTICAST) {
        ws_neigh = NULL;
    } else {
        /* Check if we are already using this address ourself */
        if (addr_interface_address_compare(cur_interface, registered_addr) == 0) {
            na_earo->present = true;
            na_earo->status = NDP_ARO_STATUS_DUP;
            return true;
        }

        ws_neigh = ws_neigh_get(&cur_interface->ws_info.neighbor_storage,
                                &EUI64_FROM_BUF(na_earo->eui64));
        if (!ws_neigh) {
            na_earo->status = NDP_ARO_STATUS_INVALTOPO;
            na_earo->present = true;
            return true;
        }
    }

    if (na_earo->p == NDP_ADDR_TYPE_MULTICAST)
        neigh = ipv6_neighbour_lookup_mc(&cur_interface->ipv6_neighbour_cache, registered_addr, na_earo->eui64);
    else
        neigh = ipv6_neighbour_lookup(&cur_interface->ipv6_neighbour_cache, registered_addr);

    if (!neigh)
        neigh = ipv6_neighbour_create(&cur_interface->ipv6_neighbour_cache, registered_addr, na_earo->eui64);
    if (!neigh) {
        na_earo->present = true;
        na_earo->status = NDP_ARO_STATUS_NOMEM;
        return true;
    }

    uint8_t *nce_eui64 = ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh);
    if (neigh->state != IP_NEIGHBOUR_NEW) {
        switch (neigh->type) {
            case IP_NEIGHBOUR_TENTATIVE:
                /* Is zero EUI-64 still possible? */
                if (memcmp(nce_eui64, na_earo->eui64, 8) && memzcmp(nce_eui64, 8)) {
                    /* Have a Tentative NCE with different EUI-64 - ignore NS; two
                     * people trying to register at once. One should retry.
                     */
                    return false;
                }
                break;
            case IP_NEIGHBOUR_REGISTERED:
                if (memcmp(nce_eui64, na_earo->eui64, 8)) {
                    /* Already registered with different EUI-64 - duplicate */
                    na_earo->present = true;
                    na_earo->status = NDP_ARO_STATUS_DUP;
                    return true;
                }
                break;
            case IP_NEIGHBOUR_GARBAGE_COLLECTIBLE:
                break;
        }
    }

    if (neigh->type != IP_NEIGHBOUR_REGISTERED) {
        neigh->type = IP_NEIGHBOUR_TENTATIVE;
        neigh->lifetime_s = TENTATIVE_NCE_LIFETIME;
    }

    /* Set the LL address, ensure it's marked STALE */
    ipv6_neighbour_entry_update_unsolicited(&cur_interface->ipv6_neighbour_cache, neigh, ll_addr.addr_type, ll_addr.address);
    ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
    na_earo->status = NDP_ARO_STATUS_SUCCESS;
    na_earo->present = true;
    // Todo: this might not be needed...
    nd_update_registration(cur_interface, neigh, na_earo, ws_neigh);
    return true;
}
