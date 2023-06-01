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
#include "app_wsbrd/tun.h" // FIXME
#include "common/rand.h"
#include "common/iobuf.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/serial_number_arithmetic.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "stack/net_6lowpan_parameter.h"
#include "stack/timers.h"

#include "stack/source/rpl/rpl_downward.h"
#include "nwk_interface/protocol.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/icmpv6_prefix.h"
#include "core/ns_address_internal.h"
#include "rpl/rpl_control.h"
#include "rpl/rpl_data.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_common.h"

#include "6lowpan/nd/nd_router_object.h"

#define TRACE_GROUP "loND"

static void lowpan_nd_address_cb(struct net_if *interface, if_address_entry_t *addr, if_address_callback_e reason);

nd_parameters_s nd_params = {
    .rs_retry_max = 3,
    .rs_retry_interval_min = 15,
    .ns_retry_interval_min = 100,
    .ns_retry_linear_backoff = 100,
    .timer_random_max = 31,
    .ns_retry_max = 5,
    .multihop_dad = true,
    .send_nud_probes = true,
    .ns_forward_timeout = 300,
};

static int icmp_nd_slaac_prefix_address_gen(struct net_if *cur_interface, uint8_t *prefix, uint8_t prefix_len, uint32_t lifetime, uint32_t preftime, bool borRouterDevice, slaac_src_e slaac_src)
{
    if_address_entry_t *address_entry = NULL;
    address_entry = icmpv6_slaac_address_add(cur_interface, prefix, prefix_len, lifetime, preftime, true, slaac_src);
    if (address_entry) {
        //Set Callback
        address_entry->cb = lowpan_nd_address_cb;
        if (borRouterDevice) {
            address_entry->state_timer = 0;
        } else {
            address_entry->state_timer = 45 + rand_get_random_in_range(1, nd_params.timer_random_max);
            //Allocate Addres registration state
            if (cur_interface->if_6lowpan_dad_process.active == false) {
                cur_interface->if_6lowpan_dad_process.count = nd_params.ns_retry_max;
                cur_interface->if_6lowpan_dad_process.active = true;
                memcpy(cur_interface->if_6lowpan_dad_process.address, address_entry->address, 16);
            }

            if ((cur_interface->lowpan_info & INTERFACE_NWK_BOOTSTRAP_ACTIVE) && cur_interface->nwk_bootstrap_state == ER_SCAN) {
                cur_interface->nwk_bootstrap_state = ER_ADDRESS_REQ;
                cur_interface->bootstrap_state_machine_cnt = 0;
            }
        }
        return 0;
    }
    return -1;
}


static void lowpan_nd_address_cb(struct net_if *interface, if_address_entry_t *addr, if_address_callback_e reason)
{
    bool g16_address;
    tr_debug("Interface ID: %i, ipv6: %s", interface->id, tr_ipv6(addr->address));

    if (memcmp(&addr->address[8], ADDR_SHORT_ADR_SUFFIC, 6) == 0) {
        g16_address = true;
    } else {
        g16_address = false;
    }

    switch (reason) {
        case ADDR_CALLBACK_DAD_COMPLETE:
            if (addr_ipv6_equal(interface->if_6lowpan_dad_process.address, addr->address)) {
                tr_info("Address REG OK: %s", tr_ipv6(interface->if_6lowpan_dad_process.address));
                interface->if_6lowpan_dad_process.active = false;
                interface->global_address_available = true;
                if (interface->lowpan_info & INTERFACE_NWK_BOOTSTRAP_ACTIVE)
                    protocol_6lowpan_bootstrap_nd_ready(interface);
            }
            break;

        case ADDR_CALLBACK_TIMER:
            tr_debug("State Timer CB");
            if (interface->if_6lowpan_dad_process.active) {
                if (memcmp(addr->address, interface->if_6lowpan_dad_process.address, 16))
                    addr->state_timer = 5;
            } else {
                tr_debug("No ND Object for Address");
            }

            break;

        case ADDR_CALLBACK_PARENT_FULL:
            interface->if_6lowpan_dad_process.count = 0;
            tr_error("ND cache full--> Black list by given lifetime");
            break;

        case ADDR_CALLBACK_DAD_FAILED:
            if (g16_address) {
                tr_warn("ARO Failure:Duplicate address");
                uint16_t shortAddress = read_be16(&addr->address[14]);
                tr_warn("Del old ll16");
                protocol_6lowpan_del_ll16(interface, shortAddress);
                //Check if Application not freeze new address allocartion
                if (interface->reallocate_short_address_if_duplicate) {

                    protocol_6lowpan_allocate_mac16(interface);
                    interface->if_6lowpan_dad_process.active = false;
                    if (icmp_nd_slaac_prefix_address_gen(interface, addr->address, addr->prefix_len,
                                                         addr->valid_lifetime, addr->preferred_lifetime, false, SLAAC_IID_6LOWPAN_SHORT) == 0) {
                        addr->state_timer = 1;
                        return;
                    }
                }
            }
            bootstrap_next_state_kick(ER_BOOTSTRAP_DAD_FAIL, interface);

            break;

        default:
            break;
    }
}

static void nd_update_registration(struct net_if *cur_interface, ipv6_neighbour_t *neigh, const struct ipv6_nd_opt_earo *aro)
{
    /* We are about to send an ARO response - update our Neighbour Cache accordingly */
    if (aro->status == ARO_SUCCESS && aro->lifetime != 0) {
        neigh->type = IP_NEIGHBOUR_REGISTERED;
        neigh->lifetime = aro->lifetime * UINT32_C(60);
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        /* Register with 2 seconds off the lifetime - don't want the NCE to expire before the route */
        ipv6_route_add_metric(neigh->ip_address, 128, cur_interface->id, neigh->ip_address, ROUTE_ARO, NULL, 0, neigh->lifetime - 2, 32);
        tun_add_node_to_proxy_neightbl(cur_interface, neigh->ip_address);
        tun_add_ipv6_direct_route(cur_interface, neigh->ip_address);
        protocol_6lowpan_neighbor_address_state_synch(cur_interface, aro->eui64, neigh->ip_address + 8);

    } else {
        /* Um, no - can't transmit response if we remove NCE now! */
        //ipv6_neighbour_entry_remove(&cur_interface->ipv6_neighbour_cache, neigh);
        neigh->type = IP_NEIGHBOUR_TENTATIVE;
        neigh->lifetime = 2;
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        ipv6_route_add_metric(neigh->ip_address, 128, cur_interface->id, neigh->ip_address, ROUTE_ARO, NULL, 0, 4, 32);
        rpl_control_unpublish_address(protocol_6lowpan_rpl_domain, neigh->ip_address);
    }
}

void nd_remove_registration(struct net_if *cur_interface, addrtype_e ll_type, const uint8_t *ll_address)
{
    ns_list_foreach_safe(ipv6_neighbour_t, cur, &cur_interface->ipv6_neighbour_cache.list) {
        if ((cur->type == IP_NEIGHBOUR_REGISTERED
                || cur->type == IP_NEIGHBOUR_TENTATIVE)
                && ipv6_neighbour_ll_addr_match(cur, ll_type, ll_address)) {

            ipv6_route_delete(cur->ip_address, 128, cur_interface->id, cur->ip_address,
                              ROUTE_ARO);
            ipv6_neighbour_entry_remove(&cur_interface->ipv6_neighbour_cache,
                                        cur);
        }
    }
}

/* Process ICMP Neighbor Solicitation (RFC 4861 + RFC 6775 + RFC 8505) EARO. */
bool nd_ns_earo_handler(struct net_if *cur_interface, const uint8_t *earo_ptr, size_t earo_len,
                        const uint8_t *slla_ptr, const uint8_t src_addr[16], const uint8_t target[16],
                        struct ipv6_nd_opt_earo *na_earo)
{
    const uint8_t *registered_addr = src_addr;
    struct iobuf_read earo = {
        .data_size = earo_len,
        .data = earo_ptr,
    };
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
     * |  Rsvd | I |R|T|     TID       |     Registration Lifetime     |
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

    // FIXME: It is not clear how ARO and EARO are differentiated.
    if (FIELD_GET(IPV6_ND_OPT_EARO_FLAGS_R_MASK, flags) &&
        FIELD_GET(IPV6_ND_OPT_EARO_FLAGS_T_MASK, flags)) {
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
        na_earo->r = true;
        na_earo->t = true;
        na_earo->tid = tid;
    }

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

    /* We need to have entry in the Neighbour Cache */
    ipv6_neighbour_t *neigh = ipv6_neighbour_lookup_or_create(&cur_interface->ipv6_neighbour_cache, registered_addr);
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
        memcpy(nce_eui64, na_earo->eui64, 8);
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
