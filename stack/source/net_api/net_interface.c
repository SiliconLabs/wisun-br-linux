/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
/**
 * \file net.c
 * \brief Network API for library model
 *
 * The network API functions for library model
 */
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "common/log_legacy.h"
#include "common/events_scheduler.h"
#include "common/endian.h"
#include "stack/nwk_stats_api.h"
#include "stack/mac/sw_mac.h"
#include "stack/mac/mac_api.h"

#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "legacy/net_socket.h"
#include "legacy/ns_socket.h"
#include "rpl/rpl_of0.h"
#include "rpl/rpl_mrhof.h"
#include "rpl/rpl_control.h"
#include "rpl/rpl_data.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#include "6lowpan/nd/nd_router_object.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "ipv6_stack/ipv6_routing_table.h"


#define TRACE_GROUP "lNet"
/**
 * \brief A function checks that the channel list is not empty. Channel pages 9 and 10 can have eight 32-bit channel masks.
 * \param scan_list is a pointer to the channel list structure given by the application.
 * \return 0 on success.
 * \return -1 if channel list is empty.
 */
static int arm_channel_list_validation(const channel_list_t *scan_list)
{
    uint8_t i = 1;
    if (scan_list) {
        if (scan_list->channel_page == CHANNEL_PAGE_9 || scan_list->channel_page == CHANNEL_PAGE_10) {
            i = 8;
        }
        while (i--)
            if (scan_list->channel_mask[i]) {
                return 0;
            }
    }
    return -1;
}

/**
 * \brief A function to read MAC PAN-ID, Short address & EUID64
 * \param mac_params is a pointer to the structure to where the mac address are written to.
 * \return 0 on success.
 * \return Negative value if interface id is not known.
 */
int8_t arm_nwk_mac_address_read(int8_t interface_id, link_layer_address_s *mac_params)
{
    int8_t ret_val = -2;
    struct net_if *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {
        ret_val = 0;
        memcpy(mac_params->mac_long, cur->mac, 8);
        memcpy(mac_params->iid_eui64, cur->iid_eui64, 8);
        mac_params->PANId = cur->mac_parameters.pan_id;
    }
    return ret_val;
}

/**
  * \brief Get current used channel.
  *
  * \return Active channel
  * \return -1 if invalid network interface ID is given
  */
int16_t arm_net_get_current_channel(int8_t interface_id)
{
    int16_t ret_val = -1;
    struct net_if *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {
        if (cur->lowpan_info & INTERFACE_NWK_ACTIVE) {
            ret_val = cur->mac_parameters.mac_channel;
        }
    }

    return ret_val;
}

/**
 * \brief A function to read library version information.
 * \param ptr is a pointer to an array to where the version information is read to.
 */
void net_get_version_information(uint8_t *ptr)
{
    (void)ptr;
}

/**
 * \brief A function to read networking address informations.
 * \param addr_id identifies the address information type to be read.
 * \param address is a pointer to a buffer to where the address information is written to.
 * \return zero on success, -1 on errors.
 */
int8_t arm_net_address_get(int8_t interface_id, net_address_e addr_id, uint8_t *address)
{
    int8_t ret_val = -1;
    struct net_if *cur;
    const uint8_t *addr;

    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }

    if (!cur->global_address_available && addr_id != ADDR_IPV6_LL) {
        //Should also check Check Bootstrap state
        return -1;
    }

    switch (addr_id) {
        case ADDR_IPV6_LL:
            ret_val = addr_interface_get_ll_address(cur, address, 0);
            break;

        case ADDR_IPV6_GP:
            addr = addr_select_with_prefix(cur, NULL, 0, SOCKET_IPV6_PREFER_SRC_PUBLIC | SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT);
            if (addr) {
                memcpy(address, addr, 16);
                ret_val = 0;
            }
            break;

        case ADDR_IPV6_GP_SEC:
            addr = addr_select_with_prefix(cur, NULL, 0, SOCKET_IPV6_PREFER_SRC_PUBLIC | SOCKET_IPV6_PREFER_SRC_6LOWPAN_LONG);
            /* Return if the "prefer long" gives a different answer to the default "prefer short". Pointer comparison is
             * sufficient as addr_select returns a pointer into the address list. */
            if (addr && addr != addr_select_with_prefix(cur, NULL, 0, SOCKET_IPV6_PREFER_SRC_PUBLIC | SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT)) {
                memcpy(address, addr, 16);
                ret_val = 0;
            }
            break;
    }
    return ret_val;
}

/**
 * \brief A function to read network Interface address count.
 * \param interface_id Id to interface.
 * \param address_count Pointer where address count will be saved.
 * \return zero on success, -1 on errors.
 */
int8_t arm_net_interface_address_list_size(int8_t interface_id, uint16_t *address_count)
{
    int8_t ret_val = -1;
    struct net_if *cur;
    *address_count = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {
        ns_list_foreach(if_address_entry_t, addr, &cur->ip_addresses) {
            if (!addr->tentative) {
                (*address_count)++;
            }
        }

        ret_val = 0;
    }
    return ret_val;
}

/**
 * \brief A function to set interface metric.
 * \param interface_id Network interface ID.
 * \param metric Used to rank otherwise-equivalent routes. Lower is preferred and default is 0. The metric value is added to metric provided by the arm_net_route_add() function.
 * \return 0 On success, -1 on errors.
 */
int8_t arm_net_interface_set_metric(int8_t interface_id, uint16_t metric)
{
    int8_t ret_val = -1;
    struct net_if *cur;
    cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (cur) {
        cur->ipv6_neighbour_cache.route_if_info.metric = metric;
        ret_val = 0;
    }

    return ret_val;
}

/**
 * \brief A function to read the interface metric value on an interface.
 * \param interface_id Network interface ID.
 * \param metric A pointer to the variable where the interface metric value is saved.
 * \return 0 On success, -1 on errors.
 */
int8_t arm_net_interface_get_metric(int8_t interface_id, uint16_t *metric)
{
    int8_t ret_val = -1;
    struct net_if *cur;
    cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (cur) {
        *metric = cur->ipv6_neighbour_cache.route_if_info.metric;
        ret_val = 0;
    }

    return ret_val;
}

/**
 * \brief A function to read network Interface.
 * \param interface_id Id to interface.
 * \param address_buf_size Indicate buffer size in bytes minimal is 16 bytes.
 * \param address_buffer pointer where stack save address one by one.
 * \param writed_address_count pointer where stack save how many address is writed behind address_buffer.
 *
 * \return zero on success, -1 on errors.
 */
int8_t arm_net_address_list_get(int8_t interface_id, uint8_t address_buf_size, uint8_t *address_buffer, int *writed_address_count)
{
    int8_t ret_val = -1;
    struct net_if *cur;
    int address_count = 0;


    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }

    if (address_buf_size >= 16) {
        int loop_counter = 0;
        bool save_address;
        while (loop_counter < 2) {
            ns_list_foreach(if_address_entry_t, e, &cur->ip_addresses) {
                if (e->tentative) {
                    continue;
                }

                save_address = false;
                if (loop_counter) {
                    if (!addr_is_ipv6_link_local(e->address)) {
                        save_address = true;
                    }
                } else {
                    if (addr_is_ipv6_link_local(e->address)) {
                        save_address = true;
                    }
                }
                if (save_address) {
                    memcpy(address_buffer, e->address, 16);
                    address_buf_size -= 16;
                    ret_val = 0;
                    address_count++;
                    if (address_buf_size >= 16) {
                        address_buffer += 16;
                    } else {
                        *writed_address_count = address_count;
                        return ret_val;
                    }
                }
            }
            loop_counter++;
        }
        //Save writed address count to Pointer
        *writed_address_count = address_count;
    }
    return ret_val;
}

int8_t arm_net_address_list_get_next(int8_t interface_id, int *n, uint8_t address_buffer[16])
{
    int8_t ret_val = -1;
    struct net_if *cur;
    int address_count = 0;

    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }

    int loop_counter = 0;
    bool save_address;
    while (loop_counter < 2) {
        ns_list_foreach(if_address_entry_t, e, &cur->ip_addresses) {
            if (e->tentative) {
                continue;
            }

            save_address = false;
            if (loop_counter) {
                if (!addr_is_ipv6_link_local(e->address)) {
                    save_address = true;
                }
            } else {
                if (addr_is_ipv6_link_local(e->address)) {
                    save_address = true;
                }
            }
            if (save_address) {
                if (*n == address_count) {
                    memcpy(address_buffer, e->address, 16);
                    *n = *n + 1;
                    return 0;
                }
                address_count++;
            }
        }
        loop_counter++;
    }
    return ret_val;
}

int8_t arm_net_address_add_to_interface(int8_t interface_id, const uint8_t address[16], uint8_t prefix_len, uint32_t valid_lifetime, uint32_t preferred_lifetime)
{
    struct net_if *cur;
    if_address_entry_t *entry;

    cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (!cur) {
        return -1;
    }

    entry = addr_add(cur, address, prefix_len, ADDR_SOURCE_STATIC, valid_lifetime, preferred_lifetime, false);

    if (!entry) {
        return -1;
    }

    return 0;
}

int8_t arm_net_address_delete_from_interface(int8_t interface_id, const uint8_t address[16])
{
    struct net_if *cur;
    cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (!cur) {
        return -1;
    }

    return addr_delete(cur, address);
}

int8_t arm_net_route_add(const uint8_t *prefix, uint8_t prefix_len, const uint8_t *next_hop, uint32_t lifetime, uint8_t metric, int8_t interface_id)
{
    ipv6_route_t *entry;

    if (prefix_len > 128 || (prefix == NULL && prefix_len != 0)) {
        return -2;
    }

    entry = ipv6_route_add_metric(prefix, prefix_len, interface_id, next_hop, ROUTE_USER, NULL, 0, lifetime, metric);

    if (!entry) {
        return -1;
    }

    return 0;
}

int8_t arm_net_route_delete(const uint8_t *prefix, uint8_t prefix_len, const uint8_t *next_hop, int8_t interface_id)
{
    if (prefix_len > 128 || (prefix == NULL && prefix_len != 0)) {
        return -2;
    }

    return ipv6_route_delete(prefix, prefix_len, interface_id, next_hop, ROUTE_USER);
}

int8_t arm_nwk_interface_lowpan_init(struct rcp *rcp, int mtu, char *interface_name_ptr)
{
    struct net_if *cur = protocol_stack_interface_generate_lowpan(rcp, mtu);
    if (!cur) {
        return -3;
    }
    protocol_6lowpan_configure_core(cur);
    cur->interface_name = interface_name_ptr;
    return cur->id;
}

/**
 * \brief Set network interface link layer parameters.
 *
 * \param interface_id Network interface ID
 * \param tun_driver_id Driver id FOR PHY data IN & OUT
 * \param channel define network link channel
 * \param link_setup Link layer parameters for NET_6LOWPAN_NETWORK_DRIVER defines NetworkID, PAN-ID Short Address
 *

 * \return >=0 Config set OK.
 * \return -1 Unknown network ID or tun driver.
 * \return -2 Interface is active, Bootstrap mode not selected or is not NET_6LOWPAN_NETWORK_DRIVER or NET_6LOWPAN_SNIFFER.
 * \return -3 No Memory for 6LoWPAN stack.
 * \return -4 Null pointer parameter
 * \return -5 Channel list empty
 */
int8_t arm_nwk_interface_network_driver_set(int8_t interface_id, const channel_list_t *nwk_channel_list, network_driver_setup_t *link_setup)
{
    int8_t ret_val = -1;
    struct net_if *cur = 0;

    if (arm_channel_list_validation(nwk_channel_list)) {
        tr_debug("Given channel mask is empty!");
        return -5;
    }

    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }


    if (cur->lowpan_info & INTERFACE_NWK_ACTIVE) {
        ret_val = -2;
    } else if ((cur->configure_flags &  INTERFACE_BOOTSTRAP_DEFINED) == 0) {
        ret_val = -2;
    } else if (link_setup && (link_setup->beacon_payload_tlv_length && link_setup->beacon_payload_tlv_ptr == NULL)) {
        ret_val = -4;
    } else {
        ret_val = -2;
    }
    return ret_val;
}

int8_t arm_nwk_interface_up(int8_t interface_id, const uint8_t *ipv6_address)
{
    int8_t ret_val = -1;
    struct net_if *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }

    if ((cur->lowpan_info & INTERFACE_NWK_ACTIVE) && cur->bootstrap_mode != ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER) {
        return -4;
    }

    if (!cur->if_up || !cur->if_down) {
        return -5;
    }

    ret_val = cur->if_up(cur, ipv6_address);


    return ret_val;
}

int8_t arm_nwk_interface_down(int8_t interface_id)
{

    int8_t ret_val = -1;
    struct net_if *cur = 0;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (cur) {

        if (!(cur->lowpan_info & INTERFACE_NWK_ACTIVE)) {
            ret_val = -4;
        } else if (!cur->if_up || !cur->if_down) {
            return -5;
        } else {
            ret_val = cur->if_down(cur);
        }

    }
    return ret_val;
}

int8_t arm_network_certificate_chain_set(const arm_certificate_chain_entry_s *chain_info)
{
    int8_t ret = -2;


    ret = ws_pae_controller_certificate_chain_set(chain_info);


    return ret;
}

int8_t arm_network_trusted_certificate_add(const arm_certificate_entry_s *cert)
{
    return ws_pae_controller_trusted_certificate_add(cert);
}

int8_t arm_network_trusted_certificate_remove(const arm_certificate_entry_s *cert)
{
    return ws_pae_controller_trusted_certificate_remove(cert);
}

int8_t arm_network_trusted_certificates_remove(void)
{
    return ws_pae_controller_trusted_certificates_remove();
}

int8_t arm_network_own_certificate_add(const arm_certificate_entry_s *cert)
{
    return ws_pae_controller_own_certificate_add(cert);
}

int8_t arm_network_own_certificates_remove(void)
{
    return ws_pae_controller_own_certificates_remove();
}

int8_t arm_network_certificate_revocation_list_add(const arm_cert_revocation_list_entry_s *crl)
{
    return ws_pae_controller_certificate_revocation_list_add(crl);
}

int8_t arm_network_certificate_revocation_list_remove(const arm_cert_revocation_list_entry_s *crl)
{
    return ws_pae_controller_certificate_revocation_list_remove(crl);
}

int8_t arm_6lowpan_bootstrap_set_for_selected_interface(int8_t interface_id)
{
    struct net_if *cur;

    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return -1;
    }

    if (cur->lowpan_info & INTERFACE_NWK_ACTIVE || cur->interface_mode == INTERFACE_UP) {
        return -4;
    }
    return 0;
}

/**
 * \brief Set network interface bootstrap setup.
 *
 * \param interface_id Network interface ID
 * \param bootstrap_mode Selected Bootstrap mode:
 *      * NET_6LOWPAN_BORDER_ROUTER, Initialise Border router basic setup
 *      * NET_6LOWPAN_ROUTER, Enable normal 6LoWPAN ND and RPL to bootstrap
 *      * NET_6LOWPAN_HOST, Enable normal 6LoWPAN ND only to bootstrap
 *      * NET_6LOWPAN_SLEEPY_HOST, Enable normal 6LoWPAN ND only to bootstrap
 *
 * \param net_6lowpan_mode_extension Define MLE protocol use and 6LoWPAN mode
 *
 * \return >=0 Bootstrap mode set OK.
 * \return -1 Unknown network ID.
 * \return -2 Unsupported bootstrap type or extension in this library.
 * \return -3 No Memory for 6LoWPAN stack.
 * \return -4 Null pointer parameter
 */
int8_t arm_nwk_interface_configure_6lowpan_bootstrap_set(int8_t interface_id, net_6lowpan_mode_e bootstrap_mode, net_6lowpan_mode_extension_e net_6lowpan_mode_extension)
{
    int8_t ret_val;
    (void)bootstrap_mode;
    ret_val = arm_6lowpan_bootstrap_set_for_selected_interface(interface_id);

    if (ret_val == 0) {

        if (net_6lowpan_mode_extension == NET_6LOWPAN_WS) {
            ret_val = ws_common_init(interface_id, bootstrap_mode);
        } else {
            ret_val = -1;
        }
    }

    return ret_val;
}

/* Don't have a loopback interface we can optimise for, but we do still need a route so we
 * can talk to ourself at all, in case our address isn't in an on-link prefix.
 */
static void net_automatic_loopback_route_update(struct net_if *interface, const if_address_entry_t *addr, if_address_callback_e reason)
{
    /* Don't care about link-local addresses - we know they're on-link */
    if (addr_is_ipv6_link_local(addr->address)) {
        return;
    }

    /* TODO: When/if we have a real loopback interface, these routes would use it instead of interface->id */
    switch (reason) {
        case ADDR_CALLBACK_DAD_COMPLETE:
            ipv6_route_add(addr->address, 128, interface->id, NULL, ROUTE_LOOPBACK, 0xFFFFFFFF, 0);
            break;
        case ADDR_CALLBACK_DELETED:
            ipv6_route_delete(addr->address, 128, interface->id, NULL, ROUTE_LOOPBACK);
            break;
        default:
            break;
    }
}

/**
  * \brief A function to initialize core elements of NanoStack library.
  *
  * \param core_idle is a function pointer to a function that is called whenever NanoStack is idle.
  * \return 0 on success.
  * \return -1 if a null pointer is given.
  */
int8_t net_init_core(void)
{
    /* Reset Protocol_stats */
    protocol_stats_init();
    protocol_core_init();
    rpl_data_init();
    // XXX application should call these!
    rpl_of0_init();
    rpl_mrhof_init();
    socket_init();
    address_module_init();
    protocol_init();
    addr_notification_register(net_automatic_loopback_route_update);
    return 0;
}

void arm_print_routing_table(void)
{
    arm_print_routing_table2();
}

void arm_print_routing_table2()
{
    ipv6_destination_cache_print();
    ipv6_route_table_print();
    rpl_control_print();
}

void arm_print_neigh_cache(void)
{
    arm_print_neigh_cache2();
}

void arm_print_neigh_cache2()
{
    nwk_interface_print_neigh_cache();
}

void arm_print_protocols(void)
{
    arm_print_protocols2(' ');
}

void arm_print_protocols2(char sep)
{
    socket_list_print(sep);
}

void arm_ncache_flush(void)
{
    nwk_interface_flush_neigh_cache();
}
