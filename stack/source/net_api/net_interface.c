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
