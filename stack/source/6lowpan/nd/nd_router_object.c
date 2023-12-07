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
#include "common/iobuf.h"
#include "common/log.h"
#include "common/specs/icmpv6.h"

#include "app_wsbrd/tun.h" // FIXME
#include "app_wsbrd/wsbr.h"
#include "nwk_interface/protocol.h"
#include "common_protocols/icmpv6.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_llc.h"
#include "ipv6_stack/ipv6_routing_table.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"

#include "6lowpan/nd/nd_router_object.h"

void nd_update_registration(struct net_if *cur_interface, ipv6_neighbour_t *neigh, const struct ipv6_nd_opt_earo *aro)
{
    const uint8_t *eui64 = ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh);
    struct ws_neighbor_class_entry *ws_neigh = ws_neighbor_class_entry_get(&cur_interface->ws_info.neighbor_storage, eui64);
    struct rpl_root *root = &g_ctxt.rpl_root;
    struct rpl_target *target;

    BUG_ON(!ws_neigh);

    TRACE(TR_NEIGH_IPV6, "IPv6 neighbor refresh %s / %s / %ds",
          tr_eui64(ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh)),
          tr_ipv6(neigh->ip_address), aro->lifetime * UINT32_C(60));

    /* We are about to send an ARO response - update our Neighbour Cache accordingly */
    if (aro->status == ARO_SUCCESS && aro->lifetime != 0) {
        neigh->type = IP_NEIGHBOUR_REGISTERED;
        neigh->lifetime = aro->lifetime * UINT32_C(60);
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        /* Register with 2 seconds off the lifetime - don't want the NCE to expire before the route */
        if (!IN6_IS_ADDR_MULTICAST(neigh->ip_address)) {
            ipv6_route_add_metric(neigh->ip_address, 128, cur_interface->id, neigh->ip_address, ROUTE_ARO, NULL, 0, neigh->lifetime - 2, 32);
            tun_add_node_to_proxy_neightbl(cur_interface, neigh->ip_address);
            tun_add_ipv6_direct_route(cur_interface, neigh->ip_address);
        }
    } else {
        /* Um, no - can't transmit response if we remove NCE now! */
        //ipv6_neighbour_entry_remove(&cur_interface->ipv6_neighbour_cache, neigh);
        neigh->type = IP_NEIGHBOUR_TENTATIVE;
        neigh->lifetime = 2;
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        if (!IN6_IS_ADDR_MULTICAST(neigh->ip_address)) {
            ipv6_route_add_metric(neigh->ip_address, 128, cur_interface->id, neigh->ip_address, ROUTE_ARO, NULL, 0, 4, 32);
            target = rpl_target_get(root, neigh->ip_address);
            if (target)
                rpl_target_del(root, target);
            mac_neighbor_table_refresh_neighbor(&ws_neigh->mac_data, aro->lifetime);
        }
    }
}

void nd_remove_registration(struct net_if *cur_interface, addrtype_e ll_type, const uint8_t *ll_address)
{
    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cur_interface->ipv6_neighbour_cache.list) {
        if ((cur->type == IP_NEIGHBOUR_REGISTERED
                || cur->type == IP_NEIGHBOUR_TENTATIVE)
                && ipv6_neighbour_ll_addr_match(cur, ll_type, ll_address)) {
            if (!IN6_IS_ADDR_MULTICAST(cur->ip_address))
                ipv6_route_delete(cur->ip_address, 128, cur_interface->id,
                                  cur->ip_address, ROUTE_ARO);
            ipv6_neighbour_entry_remove(&cur_interface->ipv6_neighbour_cache,
                                        cur);
        }
    }
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
    BUG_ON(iobuf_pop_u8(&earo) != ICMPV6_OPT_ADDR_REGISTRATION);
    //   RFC 6775 Section 6.5 - Processing a Neighbor Solicitation
    // In addition to the normal validation of an NS and its options, the ARO
    // is verified as follows (if present).  If the Length field is not two, or
    // if the Status field is not zero, then the NS is silently ignored.
    if (iobuf_pop_u8(&earo) != 2) // Length
        return false;
    if (iobuf_pop_u8(&earo) != ARO_SUCCESS) // Status
        return false;
    iobuf_pop_u8(&earo); // Opaque
    flags = iobuf_pop_u8(&earo);
    tid   = iobuf_pop_u8(&earo);
    na_earo->lifetime = iobuf_pop_be16(&earo);
    iobuf_pop_data(&earo, na_earo->eui64, 8);

    na_earo->t = FIELD_GET(IPV6_ND_OPT_EARO_FLAGS_T_MASK, flags);
    na_earo->r = FIELD_GET(IPV6_ND_OPT_EARO_FLAGS_R_MASK, flags);
    na_earo->p = FIELD_GET(IPV6_ND_OPT_EARO_FLAGS_P_MASK, flags);

    if (na_earo->p > IPV6_ND_OPT_EARO_FLAGS_P_MC) {
        TRACE(TR_DROP, "drop %-9s: invalid P flag value in EARO: %d", "ns", na_earo->p);
        return false;
    }

    // FIXME: It is not clear how ARO and EARO are differentiated.
    // This hack is based on the Wi-SUN specification.
    if (na_earo->t && (na_earo->r || na_earo->p == IPV6_ND_OPT_EARO_FLAGS_P_MC)) {
        //   RFC 8505 Section 5.6 - Link-Local Addresses and Registration
        // When sending an NS(EARO) to a 6LR, a 6LN MUST use a Link-Local
        // Address as the Source Address of the registration, whatever the type
        // of IPv6 Address that is being registered.  That Link-Local Address
        // MUST be either an address that is already registered to the 6LR or
        // the address that is being registered.
        if (!addr_is_ipv6_link_local(src_addr))
            return true;
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
        na_earo->status = ARO_SUCCESS;
        na_earo->tid = tid;
        if (na_earo->p == IPV6_ND_OPT_EARO_FLAGS_P_MC)
            if (addr_ipv6_equal(ADDR_ALL_MPL_FORWARDERS, registered_addr) ||
                !IN6_IS_ADDR_MULTICAST(registered_addr)) {
                TRACE(TR_IGNORE, "invalid multicast address in earo: %s", tr_ipv6(registered_addr));
                na_earo->status = ARO_TOPOLOGICALLY_INCORRECT;
                return true;
            }
    }

    if (na_earo->p != IPV6_ND_OPT_EARO_FLAGS_P_MC) {
        /* Check if we are already using this address ourself */
        if (addr_interface_address_compare(cur_interface, registered_addr) == 0) {
            na_earo->present = true;
            na_earo->status = ARO_DUPLICATE;
            return true;
        }

        /* TODO - check hard upper limit on registrations? */
        na_earo->status = ws_common_allow_child_registration(cur_interface, na_earo->eui64, na_earo->lifetime);
        if (na_earo->status != ARO_SUCCESS) {
            na_earo->present = true;
            return true;
        }
    }

    if (na_earo->p == IPV6_ND_OPT_EARO_FLAGS_P_MC)
        neigh = ipv6_neighbour_lookup_mc(&cur_interface->ipv6_neighbour_cache, registered_addr, na_earo->eui64);
    else
        neigh = ipv6_neighbour_lookup(&cur_interface->ipv6_neighbour_cache, registered_addr);

    if (!neigh)
        neigh = ipv6_neighbour_create(&cur_interface->ipv6_neighbour_cache, registered_addr, na_earo->eui64);
    if (!neigh) {
        na_earo->present = true;
        na_earo->status = ARO_FULL;
        return true;
    }

    uint8_t *nce_eui64 = ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh);
    if (neigh->state != IP_NEIGHBOUR_NEW) {
        switch (neigh->type) {
            case IP_NEIGHBOUR_TENTATIVE:
                /* Is zero EUI-64 still possible? */
                if (memcmp(nce_eui64, na_earo->eui64, 8) && memcmp(nce_eui64, ADDR_EUI64_ZERO, 8)) {
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
                    na_earo->status = ARO_DUPLICATE;
                    return true;
                }
                break;
            case IP_NEIGHBOUR_GARBAGE_COLLECTIBLE:
                break;
        }
    }

    if (neigh->type != IP_NEIGHBOUR_REGISTERED) {
        neigh->type = IP_NEIGHBOUR_TENTATIVE;
        neigh->lifetime = TENTATIVE_NCE_LIFETIME;
    }

    /* Set the LL address, ensure it's marked STALE */
    ipv6_neighbour_entry_update_unsolicited(&cur_interface->ipv6_neighbour_cache, neigh, ll_addr.addr_type, ll_addr.address);
    ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
    na_earo->status = ARO_SUCCESS;
    na_earo->present = true;
    // Todo: this might not be needed...
    nd_update_registration(cur_interface, neigh, na_earo);
    return true;
}
