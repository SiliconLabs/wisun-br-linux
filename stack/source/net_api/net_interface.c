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
#include "stack/mac/mac_api.h"

#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "legacy/ns_socket.h"
#include "rpl/rpl_of0.h"
#include "rpl/rpl_mrhof.h"
#include "rpl/rpl_data.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_pae_controller.h"

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

static int8_t arm_6lowpan_bootstrap_set_for_selected_interface(int8_t interface_id)
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

int8_t arm_nwk_interface_configure_6lowpan_bootstrap_set(int8_t interface_id,
                                                         net_6lowpan_mode_e bootstrap_mode,
                                                         net_6lowpan_mode_extension_e net_6lowpan_mode_extension)
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
