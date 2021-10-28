/*
 * Copyright (c) 2017-2020, Pelion and affiliates.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "nsconfig.h"


#ifdef HAVE_THREAD_BORDER_ROUTER
int thread_bbr_na_send(int8_t interface_id, const uint8_t target[static 16])
{
    protocol_interface_info_entry_t *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }
    // Send NA only if it is enabled for the backhaul
    if (!cur->send_na) {
        return -1;
    }

    buffer_t *buffer = icmpv6_build_na(cur, false, true, true, target, NULL, ADDR_UNSPECIFIED);
    protocol_push(buffer);
    return 0;

}

int thread_bbr_nd_entry_add(int8_t interface_id, const uint8_t *addr_data_ptr,  uint32_t lifetime, void *info)
{
    thread_bbr_t *this = thread_bbr_find_by_interface(interface_id);
    if (!this || this->backbone_interface_id < 0) {
        return -1;
    }
    ipv6_route_t *route = ipv6_route_add_with_info(addr_data_ptr, 128, interface_id, NULL, ROUTE_THREAD_PROXIED_HOST, info, 0, lifetime, 0);
    // We are using route info field to store sequence number
    if (!route) {
        // Direct route to host allows ND proxying to work
        tr_err("bbr out of resources");
        return -2;
    }
    // send NA
    thread_bbr_na_send(this->backbone_interface_id, addr_data_ptr);

    return 0;
}

int thread_bbr_dua_entry_add(int8_t interface_id, const uint8_t *addr_data_ptr,  uint32_t lifetime, const uint8_t *mleid_ptr)
{
    thread_bbr_t *this = thread_bbr_find_by_interface(interface_id);
    thread_pbbr_dua_info_t *map;
    if (!this || this->backbone_interface_id < 0) {
        return -1;
    }
    ipv6_route_t *route = ipv6_route_lookup_with_info(addr_data_ptr, 128, interface_id, NULL, ROUTE_THREAD_PROXIED_DUA_HOST, NULL, 0);
    if (!route) {
        map = ns_dyn_mem_alloc(sizeof(thread_pbbr_dua_info_t));
        if (!map) {
            goto error;
        }
        // We are using route info field to store BBR MLEID map
        route = ipv6_route_add_with_info(addr_data_ptr, 128, interface_id, NULL, ROUTE_THREAD_PROXIED_DUA_HOST, map, 0, lifetime, 0);
        if (!route) {
            // Direct route to host allows ND proxying to work
            ns_dyn_mem_free(map);
            goto error;
        }
        // Route info autofreed
        route->info_autofree = true;
    }
    route->lifetime = lifetime; // update lifetime also from old route
    map = route->info.info;
    memcpy(map->mleid_ptr, mleid_ptr, 8);
    map->last_contact_time = protocol_core_monotonic_time;
    route->info.info = map;

    // send NA
    thread_bbr_na_send(this->backbone_interface_id, addr_data_ptr);

    return 0;
error:
    tr_err("out of resources");
    return -2;
}

int thread_bbr_proxy_state_update(int8_t caller_interface_id, int8_t handler_interface_id, bool status)
{
    protocol_interface_info_entry_t *cur = protocol_stack_interface_info_get_by_id(handler_interface_id);
    (void) caller_interface_id;
    if (!cur) {
        tr_error("No Interface");
        return -1;
    }
    // Route prefix is variable-length, so need to zero pad for ip6tos
    bool weHostServiceAlso = false;
    bool validToLearOnMeshRoute;
    uint16_t routerId;
    routerId = cur->mac_parameters->mac_short_address;
    thread_network_data_cache_entry_t *networkData;
    networkData = &cur->thread_info->networkDataStorage;
    validToLearOnMeshRoute = thread_on_mesh_route_possible_add(cur->thread_info->thread_device_mode);

    tr_debug("Proxy update");

    ns_list_foreach(thread_network_data_prefix_cache_entry_t, curPrefix, &networkData->localPrefixList) {

        weHostServiceAlso = thread_nd_hosted_by_this_routerid(routerId, &curPrefix->routeList);

        if (weHostServiceAlso) {
            ipv6_route_add(curPrefix->servicesPrefix, curPrefix->servicesPrefixLen, cur->id, NULL, ROUTE_THREAD, 0xffffffff, 0);
        }

        weHostServiceAlso = thread_nd_hosted_by_this_routerid(routerId, &curPrefix->borderRouterList);

        ns_list_foreach(thread_network_server_data_entry_t, curRoute, &curPrefix->borderRouterList) {
            if (thread_nd_on_mesh_address_valid(curRoute)) {
                if (validToLearOnMeshRoute) {
                    if (curRoute->P_dhcp && weHostServiceAlso) {
                        if (status) {
                            ipv6_route_delete(curPrefix->servicesPrefix, curPrefix->servicesPrefixLen, cur->id, NULL, ROUTE_THREAD);
                        } else {
                            ipv6_route_add(curPrefix->servicesPrefix, curPrefix->servicesPrefixLen, cur->id, NULL, ROUTE_THREAD, 0xffffffff, 0);
                        }

                    }
                }
            }
        }
    }
    return 0;
}
#endif

/*Public API control*/
int thread_bbr_start(int8_t interface_id, int8_t backbone_interface_id)
{
    (void) interface_id;
    (void) backbone_interface_id;
#ifdef HAVE_THREAD_BORDER_ROUTER
    thread_bbr_t *this = thread_bbr_find_by_interface(interface_id);
    link_configuration_s *link_configuration_ptr = thread_joiner_application_get_config(interface_id);
    uint8_t *extended_random_mac = thread_joiner_application_random_mac_get(interface_id);
    char service_name[30] = {0};
    char *ptr;

    if (!this || !link_configuration_ptr || backbone_interface_id < 0) {
        return -1;
    }

    tr_info("Thread BBR start if:%d, bb_if:%d", interface_id, backbone_interface_id);

    this->backbone_interface_id = backbone_interface_id;
    ptr = service_name;
    *ptr++ = 'a' + extended_random_mac[0] % 26;
    *ptr++ = 'a' + extended_random_mac[1] % 26;
    *ptr++ = 'a' + extended_random_mac[2] % 26;
    *ptr++ = 'a' + extended_random_mac[3] % 26;
    memcpy(ptr, "-ARM-", 5);
    ptr += 5;
    memcpy(ptr, link_configuration_ptr->name, 16);

    // Start mdns service
    thread_mdns_start(this->interface_id, this->backbone_interface_id, service_name);
    multicast_fwd_set_proxy_upstream(this->backbone_interface_id);
    multicast_fwd_full_for_scope(this->interface_id, 0);
    multicast_fwd_full_for_scope(this->backbone_interface_id, 0);
    // By default multicast forwarding is not enabled as it causes multicast loops
    multicast_fwd_set_forwarding(this->interface_id, false);

    // Configure BBR neighbour cache parameters
    arm_nwk_ipv6_neighbour_cache_configure(THREAD_BBR_IPV6_NEIGHBOUR_CACHE_SIZE,
                                           THREAD_BBR_IPV6_NEIGHBOUR_CACHE_SHORT_TERM,
                                           THREAD_BBR_IPV6_NEIGHBOUR_CACHE_LONG_TERM,
                                           THREAD_BBR_IPV6_NEIGHBOUR_CACHE_LIFETIME);

    thread_bbr_commercial_init(interface_id, backbone_interface_id);

    return 0;
#else
    return -1;
#endif // HAVE_THREAD_BORDER_ROUTER
}

int thread_bbr_timeout_set(int8_t interface_id, uint32_t timeout_a, uint32_t timeout_b, uint32_t delay)
{
    (void) interface_id;
    (void) timeout_a;
    (void) timeout_b;
    (void) delay;
#ifdef HAVE_THREAD_BORDER_ROUTER
    thread_bbr_commercial_timeout_set(interface_id, timeout_a, timeout_b, delay);
    return 0;
#else
    return -1;
#endif // HAVE_THREAD_BORDER_ROUTER
}


int thread_bbr_prefix_set(int8_t interface_id, uint8_t *prefix)
{
    (void) interface_id;
    (void) prefix;
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_bbr_commercial_prefix_set(interface_id, prefix);
#else
    return -1;
#endif // HAVE_THREAD_BORDER_ROUTER
}

int thread_bbr_sequence_number_set(int8_t interface_id, uint8_t sequence_number)
{
    (void) interface_id;
    (void) sequence_number;
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_bbr_commercial_sequence_number_set(interface_id, sequence_number);
#else
    return -1;
#endif // HAVE_THREAD_BORDER_ROUTER
}

int thread_bbr_validation_interface_address_set(int8_t interface_id, const uint8_t *addr_ptr, uint16_t port)
{
    (void) interface_id;
    (void) addr_ptr;
    (void) port;
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_bbr_commercial_address_set(interface_id, addr_ptr, port);
#else
    return -1;
#endif // HAVE_THREAD_BORDER_ROUTER
}

void thread_bbr_stop(int8_t interface_id)
{
    (void) interface_id;
#ifdef HAVE_THREAD_BORDER_ROUTER

    thread_bbr_t *this = thread_bbr_find_by_interface(interface_id);

    if (!this) {
        return;
    }
    thread_bbr_commercial_delete(interface_id);
    thread_bbr_network_data_remove(this);
    thread_bbr_routing_disable(this);
    thread_border_router_publish(interface_id);
    thread_mdns_stop();
    this->backbone_interface_id = -1;

#else
    return;
#endif // HAVE_THREAD_BORDER_ROUTER

}
