/*
 * Copyright (c) 2013-2020, Pelion and affiliates.
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
#include "common/rand.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/serial_number_arithmetic.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/whiteboard/whiteboard.h"
#include "stack/net_6lowpan_parameter.h"
#include "stack/timers.h"

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

static void nd_ns_build(nd_router_t *cur, struct net_if *cur_interface, uint8_t *address_ptr);
static void icmp_nd_router_object_release(nd_router_t *router_object);
static uint8_t nd_router_bootstrap_timer(nd_router_t *cur, struct net_if *cur_interface, uint16_t ticks);
static void nd_ns_forward_timer_reset(uint8_t *root_adr);
static nd_router_t *nd_router_object_scan_by_prefix(const uint8_t *prefix);
static void lowpan_nd_address_cb(struct net_if *interface, if_address_entry_t *addr, if_address_callback_e reason);

//ND Router List
static NS_LIST_DEFINE(nd_router_list, nd_router_t, link);

/*
 * Default values are documented in net_6lowpan_parameter_api.h - keep in sync.
 */
uint8_t nd_base_tick = 1;

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

void icmp_nd_routers_init(void)
{
    ns_list_foreach_safe(nd_router_t, cur, &nd_router_list) {
        ns_list_remove(&nd_router_list, cur);
        icmp_nd_router_object_release(cur);
    }
}


static void icmp_nd_set_nd_def_router_address(uint8_t *ptr, nd_router_t *cur)
{
    memcpy(ptr, ADDR_LINK_LOCAL_PREFIX, 8);
    ptr += 8;
    if (cur->default_hop.addrtype == ADDR_802_15_4_SHORT) {
        memcpy(ptr, ADDR_SHORT_ADR_SUFFIC, 6);
        ptr += 6;
        *ptr++ = cur->default_hop.address[0];
        *ptr = cur->default_hop.address[1];
    } else {
        memcpy(ptr, cur->default_hop.address, 8);
    }
}

static void nd_ns_trig(nd_router_t *router_object, struct net_if *cur)
{
    //
    ns_list_foreach(prefix_entry_t, prefix, &router_object->prefix_list) {
        if (prefix->options & PIO_A) {
            ns_list_foreach(if_address_entry_t, e, &cur->ip_addresses) {
                if (e->source == ADDR_SOURCE_SLAAC && (memcmp(e->address, prefix->prefix, 8) == 0)) {
                    if (cur->if_6lowpan_dad_process.active) {
                        e->state_timer = 5;
                    } else {
                        e->state_timer = 25;
                        cur->if_6lowpan_dad_process.active = true;
                        memcpy(cur->if_6lowpan_dad_process.address, e->address, 16);
                        cur->if_6lowpan_dad_process.count = nd_params.ns_retry_max;
                    }
                }
            }
        }
    }
}

static void nd_router_remove(nd_router_t *router, struct net_if *interface)
{
    tr_debug("route remove");
    ns_list_remove(&nd_router_list, router);
    icmp_nd_router_object_release(router);

    if (ns_list_is_empty(&nd_router_list)) {
        arm_6lowpan_bootstrap_init(interface);
    }
}

static void icmp_nd_router_object_reset(nd_router_t *router_object)
{
    icmpv6_prefix_list_free(&router_object->prefix_list);

    lowpan_context_list_free(&router_object->context_list);
}

/* Returns 1 if the router object has been removed */
static uint8_t icmp_nd_router_prefix_ttl_update(nd_router_t *nd_router_object, struct net_if *cur_interface, uint16_t seconds)
{
    ns_list_foreach(prefix_entry_t, cur, &nd_router_object->prefix_list) {
        if (cur->preftime != 0xffffffff && cur->preftime) {
            if (cur->preftime <=  seconds) {
                tr_warn("PREFTIME zero");
                cur->preftime = 0;
            } else {
                cur->preftime -= seconds;
            }

        }

        if (cur->lifetime != 0xffffffff && cur->lifetime) {
            if (cur->lifetime > seconds) {
                cur->lifetime -= seconds;
            } else {
                tr_debug("Prefix Expiry");
                if (cur->options & PIO_A) {
                    tr_debug("Delete GP Address by Prefix, start RS");
                    nd_router_remove(nd_router_object, cur_interface);
                    return 1;
                }
            }
        }
    }

    return 0;
}

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
    nd_router_t *cur = NULL;
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
                if (memcmp(addr->address, interface->if_6lowpan_dad_process.address, 16) == 0) {
                    cur = nd_get_object_by_nwk_id();
                } else {
                    addr->state_timer = 5;
                }
            } else {
                cur = nd_get_object_by_nwk_id();
                if (cur) {
                    interface->if_6lowpan_dad_process.count = nd_params.ns_retry_max;
                    interface->if_6lowpan_dad_process.active = true;
                    memcpy(interface->if_6lowpan_dad_process.address, addr->address, 16);
                } else {
                    tr_debug("No ND Object for Address");
                }
            }

            if (cur) {
                if (interface->if_6lowpan_dad_process.count) {
                    nd_ns_build(cur, interface, addr->address);
                    addr->state_timer = nd_params.ns_retry_interval_min;
                    addr->state_timer += nd_params.ns_retry_linear_backoff * (nd_params.ns_retry_max - interface->if_6lowpan_dad_process.count);
                    addr->state_timer += (rand_get_16bit() & nd_params.timer_random_max);
                    tr_debug("NS Configured");
                    interface->if_6lowpan_dad_process.count--;
                } else {

                    //ND FAIL
                    tr_error("NS Fail");
                    protocol_6lowpan_neighbor_remove(interface, cur->default_hop.address, cur->default_hop.addrtype);
                    interface->if_6lowpan_dad_process.active = false;
                    protocol_6lowpan_nd_borderrouter_connection_down(interface);
                }
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

/* Update lifetime and expire contexts in ABRO storage */
static void icmp_nd_router_context_ttl_update(nd_router_t *nd_router_object, uint16_t seconds)
{
    ns_list_foreach_safe(lowpan_context_t, cur, &nd_router_object->context_list) {
        /* We're using seconds in call, but lifetime is in 100ms ticks */
        if (cur->lifetime <= (uint32_t)seconds * 10) {
            /* When lifetime in the ABRO storage runs out, just drop it,
             * so we stop advertising it. This is different from the
             * interface context handling.
             */
            ns_list_remove(&nd_router_object->context_list, cur);
            free(cur);
        } else {
            cur->lifetime -= (uint32_t)seconds * 10;
        }
    }
}

static void icmp_nd_router_object_release(nd_router_t *router_object)
{
    if (router_object) {
        icmp_nd_router_object_reset(router_object);
        free(router_object);
    }
}


static bool rpl_parents_only(const ipv6_route_info_t *route, bool valid)
{
    return valid && rpl_data_is_rpl_parent_route(route->source);
}

/* Neighbor Solicitation (RFC4861) with Address Registration Option (RFC6775)
 * and Source Link-Layer Address Option (RFC4861)
 */
static void nd_ns_build(nd_router_t *cur, struct net_if *cur_interface, uint8_t *address_ptr)
{
    uint8_t router[16];
    aro_t aro;
    buffer_t *buf;

    /* If we're a host, we will just send to our ND parent. But as a router,
     * we don't really maintain our ND parent - send NA instead to the RPL
     * parent we would use to talk to the border router.
     */
    if ((cur_interface->lowpan_info & INTERFACE_NWK_ROUTER_DEVICE) && cur_interface->rpl_domain) {
        ipv6_route_t *route = ipv6_route_choose_next_hop(cur->border_router, cur_interface->id, rpl_parents_only);
        if (!route) {
            /* Important to return 1 so this counts as a "success" - caller then backs off due to lack of response and time out */
            return;
        }
        memcpy(router, route->info.next_hop_addr, 16);
    } else
    {
        icmp_nd_set_nd_def_router_address(router, cur);
    }

    aro.status = ARO_SUCCESS;
    aro.present = true;
    aro.lifetime = (cur->life_time / 60) + 1;
    memcpy(aro.eui64, cur_interface->mac, 8);

    buf = icmpv6_build_ns(cur_interface, router, address_ptr, true, false, &aro);
    protocol_push(buf);
}

/* RFC 6775 Duplicate Address Request/Confirmation packets
 *
 *     0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Status     |   Reserved    |     Registration Lifetime     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                            EUI-64                             +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                       Registered Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * (and 8.2.1 implies this is can be followed by options, although
 * none are defined).
 */
static bool nd_dar_dac_valid(buffer_t *buf)
{
    const uint8_t *dptr = buffer_data_pointer(buf);

    if (buf->options.code != 0) {
        return false;
    }

    if (!icmpv6_options_well_formed_in_buffer(buf, 28)) {
        return false;
    }

    if (addr_is_ipv6_multicast(dptr + 12)) {
        return false;
    }

    if (addr_is_ipv6_unspecified(buf->src_sa.address) ||
            addr_is_ipv6_multicast(buf->src_sa.address)) {
        return false;
    }

    return true;
}

buffer_t *nd_dar_parse(buffer_t *buf, struct net_if *cur_interface)
{
#if defined WHITEBOARD && defined HAVE_WS_BORDER_ROUTER
    uint8_t *dptr = buffer_data_pointer(buf);
    buffer_t *retbuf;
    uint8_t status;
    uint16_t lifetime;
    const uint8_t *eui64;

    if (!nd_dar_dac_valid(buf)) {
        goto drop;
    }

    status = *dptr;
    dptr += 2;
    lifetime = read_be16(dptr);
    dptr += 2;

    if (status != ARO_SUCCESS) {
        goto drop;
    }

    whiteboard_entry_t *wb;

    /* EUI-64 */
    eui64 = dptr;
    dptr += 8;
    tr_debug("DAR adr: %s, from %s", tr_ipv6(dptr), tr_ipv6(buf->src_sa.address));

    //SET White board
    wb = whiteboard_table_update(dptr, eui64, &status);
    if (wb && status == ARO_SUCCESS) {
        memcpy(wb->address, dptr, 16);
        memcpy(wb->eui64, eui64, 8);
        wb->interface_index = cur_interface->id;
        wb->ttl = UINT24_C(60) * lifetime;
    }

    retbuf = icmpv6_build_dad(cur_interface, NULL, ICMPV6_TYPE_INFO_DAC, buf->src_sa.address, eui64, dptr, status, lifetime);
    if (retbuf) {
        buffer_free(buf);
        return retbuf;
    }

drop:
#else
    (void)cur_interface;
#endif

    return buffer_free(buf);
}

static void nd_update_registration(struct net_if *cur_interface, ipv6_neighbour_t *neigh, const aro_t *aro)
{
    /* We are about to send an ARO response - update our Neighbour Cache accordingly */
    if (aro->status == ARO_SUCCESS && aro->lifetime != 0) {
        neigh->type = IP_NEIGHBOUR_REGISTERED;
        neigh->lifetime = aro->lifetime * UINT32_C(60);
        ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
        /* Register with 2 seconds off the lifetime - don't want the NCE to expire before the route */
        ipv6_route_add_metric(neigh->ip_address, 128, cur_interface->id, neigh->ip_address, ROUTE_ARO, NULL, 0, neigh->lifetime - 2, 32);

        /* We need to know peer is a host before publishing - this needs MLE. Not yet established
         * what to do without MLE - might need special external/non-external prioritisation at root.
         * This "publish for RFD" rule comes from ZigBee IP.
         */
        mac_neighbor_table_entry_t *entry = mac_neighbor_table_address_discover(mac_neighbor_info(cur_interface), ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh), ADDR_802_15_4_LONG);

        if (entry) {

            if (!entry->ffd_device) {
                rpl_control_publish_host_address(protocol_6lowpan_rpl_domain, neigh->ip_address, neigh->lifetime);
            }
        }
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

/* Process ICMP Neighbor Solicitation (RFC 4861 + RFC 6775) ARO. */
bool nd_ns_aro_handler(struct net_if *cur_interface, const uint8_t *aro_opt, const uint8_t *slla_opt, const uint8_t *src_addr, aro_t *aro_out)
{
    /* Ignore any ARO if source is link-local */
    if (addr_is_ipv6_link_local(src_addr)) {
        return true; /* Transmit NA, without ARO */
    }

    /* If we can't parse the SLLAO, then act as if no SLLAO: ignore ARO */
    sockaddr_t ll_addr;
    if (!cur_interface->if_llao_parse(cur_interface, slla_opt, &ll_addr)) {
        return true; /* Transmit NA, without ARO */
    }

    /*
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Type = 33   |   Length = 2  |    Status     |   Reserved    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Reserved            |     Registration Lifetime     |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                            EUI-64                             +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    /* icmpv6_ns_handler has already checked incoming status == 0 */
    aro_out->lifetime = read_be16(aro_opt + 6);
    memcpy(aro_out->eui64, aro_opt + 8, 8);

    /* Check if we are already using this address ourself */
    if (addr_interface_address_compare(cur_interface, src_addr) == 0) {
        aro_out->present = true;
        aro_out->status = ARO_DUPLICATE;
        return true;
    }

    /* TODO - check hard upper limit on registrations? */
    if (ws_info(cur_interface)) {

        aro_out->status = ws_common_allow_child_registration(cur_interface, aro_out->eui64, aro_out->lifetime);
        if (aro_out->status != ARO_SUCCESS) {
            aro_out->present = true;
            return true;
        }
    }

    /* We need to have entry in the Neighbour Cache */
    ipv6_neighbour_t *neigh = ipv6_neighbour_lookup_or_create(&cur_interface->ipv6_neighbour_cache, src_addr);
    if (!neigh) {
        aro_out->present = true;
        aro_out->status = ARO_FULL;
        return true;
    }

    uint8_t *nce_eui64 = ipv6_neighbour_eui64(&cur_interface->ipv6_neighbour_cache, neigh);
    if (neigh->state != IP_NEIGHBOUR_NEW) {
        switch (neigh->type) {
            case IP_NEIGHBOUR_TENTATIVE:
                /* Is zero EUI-64 still possible? */
                if (memcmp(nce_eui64, aro_out->eui64, 8) && memcmp(nce_eui64, ADDR_EUI64_ZERO, 8)) {
                    /* Have a Tentative NCE with different EUI-64 - ignore NS; two
                     * people trying to register at once. One should retry.
                     */
                    return false;
                }
                break;
            case IP_NEIGHBOUR_REGISTERED:
                if (memcmp(nce_eui64, aro_out->eui64, 8)) {
                    /* Already registered with different EUI-64 - duplicate */
                    aro_out->present = true;
                    aro_out->status = ARO_DUPLICATE;
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
        memcpy(nce_eui64, aro_out->eui64, 8);
    }

    /* Set the LL address, ensure it's marked STALE */
    ipv6_neighbour_entry_update_unsolicited(&cur_interface->ipv6_neighbour_cache, neigh, ll_addr.addr_type, ll_addr.address);
    ipv6_neighbour_set_state(&cur_interface->ipv6_neighbour_cache, neigh, IP_NEIGHBOUR_STALE);
    if (ws_info(cur_interface)) {
        aro_out->status = ARO_SUCCESS;
        aro_out->present = true;
        // Todo: this might not be needed...
        nd_update_registration(cur_interface, neigh, aro_out);
        return true;
    }
    if (cur_interface->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER || nd_params.multihop_dad == false) {
        if (cur_interface->bootstrap_mode == ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
            whiteboard_entry_t *wb;
            wb = whiteboard_table_update(src_addr, aro_out->eui64, &aro_out->status);
            if (wb) {
                if (aro_out->status == ARO_SUCCESS) {
                    memcpy(wb->address, src_addr, 16);
                    memcpy(wb->eui64, aro_out->eui64, 8);
                    wb->interface_index = cur_interface->id;
                    wb->ttl = 50000;//life_time;
                }
            } else {
                tr_warn("white Board Registry fail");
                aro_out->status = ARO_FULL;
                goto RESPONSE;
            }
        }

RESPONSE:
        aro_out->present = true;
        nd_update_registration(cur_interface, neigh, aro_out);
        return true; /* Transmit NA */
    } else { /* Non-border router and multihop DAD: relay as DAR to Border Router */
        nd_router_t *nd_router_obj = 0;

        nd_router_obj = nd_router_object_scan_by_prefix(src_addr);
        if (!nd_router_obj) {
            /* Don't know where to send this. Do we say "yay" or "nay"? */
            /* For now, ignore ARO, as with old code; don't set aro_out.present */
            return true;
        }

        buffer_t *buf = icmpv6_build_dad(cur_interface, NULL, ICMPV6_TYPE_INFO_DAR, nd_router_obj->border_router, aro_out->eui64, src_addr, 0, aro_out->lifetime);
        if (!buf) {
            return false;    /* Failed to build DAR - drop NS */
        }

        tr_debug("RX:NS --> TX DAR to Root");
        protocol_push(buf);
        if (nd_router_obj->ns_forward_timer == 0) {
            nd_router_obj->ns_forward_timer = nd_params.ns_forward_timeout;
        }

        return false; /* Tell ns_handler to not transmit now */
    }
}

buffer_t *nd_dac_handler(buffer_t *buf, struct net_if *cur)
{
    uint8_t *dptr, target_address[16], *reg_address;
    aro_t aro;

    dptr = buffer_data_pointer(buf);

    if (!nd_dar_dac_valid(buf)) {
        return buffer_free(buf);
    }

    nd_ns_forward_timer_reset(buf->src_sa.address);

    aro.status  = *dptr;
    dptr += 2;
    aro.lifetime = read_be16(dptr);
    dptr += 2;
    /* EUI-64 */
    memcpy(aro.eui64, dptr, 8);
    dptr += 8;
    reg_address = dptr;
    dptr += 16;

    ipv6_neighbour_t *neigh = ipv6_neighbour_lookup(&cur->ipv6_neighbour_cache, reg_address);
    if (!neigh || neigh->type == IP_NEIGHBOUR_GARBAGE_COLLECTIBLE || memcmp(ipv6_neighbour_eui64(&cur->ipv6_neighbour_cache, neigh), aro.eui64, 8)) {
        return buffer_free(buf);
    }

    nd_update_registration(cur, neigh, &aro);

    /* RFC 6775 has a bit of a hole here - what's the Target Address? */
    /* It's not in the DAC. We didn't record locally when we sent the DAR */
    /* I guess it's logical that we use a link-local address. We break */
    /* RFC 4861 by responding "solicited", but not to the NS Target... */
    /* However, my reading of RFC 4861 says that the receiver should do */
    /* the right thing. Only problem is that what if they really did want */
    /* to do a NUD probe for our GP addr, but included the ARO by mistake? */
    if (addr_interface_get_ll_address(cur, target_address, 0)) {
        return buffer_free(buf);
    }

    /* NA builder will send it to the address in the buffer's source */
    memcpy(buf->src_sa.address, reg_address, 16);

    buffer_t *na_buf = icmpv6_build_na(cur, true, true, false, target_address, &aro, buf->src_sa.address);

    buffer_free(buf);

    return na_buf;
}


static void nd_ns_forward_timer_reset(uint8_t *root_adr)
{
    ns_list_foreach(nd_router_t, cur, &nd_router_list) {
        if (memcmp(root_adr, cur->border_router, 16) == 0) {
            if (cur->ns_forward_timer) {
                cur->ns_forward_timer = 0;
                tr_warn("RX VALID DAC");
            }
            break;
        }
    }
}

static void nd_router_forward_timer(nd_router_t *cur, uint16_t ticks_update)
{
    struct net_if *cur_interface;
    if (!(cur->ns_forward_timer)) {
        return;
    }

    if (cur->ns_forward_timer > ticks_update) {
        cur->ns_forward_timer -= ticks_update;
        return;
    }

    cur->ns_forward_timer = 0;
    cur_interface = protocol_stack_interface_info_get();
    if (cur_interface) {
        if (cur_interface->if_6lowpan_dad_process.active == false) {
            nd_ns_trig(cur, cur_interface);
        }
    }
}

static nd_router_t *nd_router_object_scan_by_prefix(const uint8_t *ptr)
{
    ns_list_foreach(nd_router_t, cur, &nd_router_list) {
        if (icmpv6_prefix_compare(&cur->prefix_list, ptr, 64)) {
            return cur;
        }
    }

    return NULL;
}

/* Returns 1 if the router object has been removed */
static uint8_t nd_router_ready_timer(nd_router_t *cur, struct net_if *cur_interface, uint16_t ticks_update)
{
    if (!cur->nd_timer) {
        return 0;
    }

    if (cur->nd_timer > ticks_update) {
        cur->nd_timer -= ticks_update;
        return 0;
    }

    //Take out last remaing time from ticks
    ticks_update -= cur->nd_timer;
    uint16_t updated_seconds = 1;
    cur->nd_timer = 10;
    if (ticks_update) {
        updated_seconds += (ticks_update / 10);
        //Set Next second based on over based time
        cur->nd_timer -= (ticks_update % 10);
    }

    if (icmp_nd_router_prefix_ttl_update(cur, cur_interface, updated_seconds)) {
        return 1;
    }

    //Update seconds
    icmp_nd_router_context_ttl_update(cur, updated_seconds);

    return 0;
}

/* Returns 1 if the router object has been removed, or we want no further processing on this tick */
static uint8_t nd_router_bootstrap_timer(nd_router_t *cur, struct net_if *cur_interface, uint16_t ticks)
{
    uint16_t scaled_ticks;
    /*
     * nd_timer is scaled by nd_base_tick during the discovery states,
     * to allow API to slow down the ND process. Note we count up and test
     * inequality, just in case someone decides to change nd_base_tick on
     * the fly.
     */
    if (cur->nd_bootstrap_tick + ticks < nd_base_tick) {
        cur->nd_bootstrap_tick += ticks;
        return 0;
    }

    //Take off scaled ticks
    ticks -= (nd_base_tick - cur->nd_bootstrap_tick);

    scaled_ticks = 1 + (ticks / nd_base_tick);

    cur->nd_bootstrap_tick = 0 + (ticks % nd_base_tick);

    if (!cur->nd_timer) {
        tr_debug("NDB:Tick Update fail %u", scaled_ticks);
        return 0;
    }


    if (cur->nd_timer > scaled_ticks) {
        cur->nd_timer -= scaled_ticks;
        return 0;
    }
    return 0;
}


void nd_object_timer(int ticks_update)
{
    struct net_if *cur_interface = protocol_stack_interface_info_get();

    if (!(cur_interface->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    ns_list_foreach_safe(nd_router_t, cur, &nd_router_list) {
        /* This may nd_router_remove(cur), so need to use safe loop */
        nd_router_forward_timer(cur, ticks_update);

        nd_router_ready_timer(cur, cur_interface, ticks_update);
        return;
    }
}

nd_router_t *nd_get_object_by_nwk_id()
{
    ns_list_foreach(nd_router_t, cur, &nd_router_list)
        return cur;

    return NULL;
}

