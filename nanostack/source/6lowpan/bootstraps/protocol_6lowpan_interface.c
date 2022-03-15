/*
 * Copyright (c) 2015-2019, Pelion and affiliates.
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
 * \file protocol_6lowpan_interface.c
 * \brief Add short description about this file!!!
 *
 */
#include "nsconfig.h"
#include <string.h>
#include <stdint.h>
#include "mbed-client-libservice/ns_trace.h"
#include <stdlib.h>
#include "common/hal_interrupt.h"
#include "mbed-client-libservice/common_functions.h"
#include "service_libs/blacklist/blacklist.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "nanostack-event-loop/eventOS_event.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack/mac/mac_api.h"
#include "nanostack/shalib.h"

#include "nwk_interface/protocol.h"
#include "common_protocols/udp.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/icmpv6_radv.h"
#include "rpl/rpl_control.h"
#include "net_lib/net_load_balance_internal.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/nd/nd_router_object.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"
#include "6lowpan/bootstraps/network_lib.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"

void protocol_mac_reset(protocol_interface_info_entry_t *cur)
{
    if (cur->mac_api) {
        mlme_reset_t reset;
        reset.SetDefaultPIB = true;
        cur->mac_api->mlme_req(cur->mac_api, MLME_RESET, &reset);
    }
}



static int8_t set_6lowpan_nwk_down(protocol_interface_info_entry_t *cur)
{
    int8_t ret_val = -1;
    // Check first current state
    if (cur->lowpan_info & INTERFACE_NWK_ACTIVE) {
        /* Change Active -> Idle */
        /* Disable Protocols Timers */
        mac_neighbor_table_neighbor_list_clean(mac_neighbor_info(cur));

        if (cur->interface_mode == INTERFACE_UP) {
            cur->mac_parameters.pan_id = 0xffff;
            cur->mac_parameters.SecurityEnabled = false;
            cur->mac_parameters.security_frame_counter = 0;
            cur->mac_parameters.mac_security_level = 0;
            protocol_mac_reset(cur);
            cur->interface_mode = INTERFACE_IDLE;
        }
        lowpan_adaptation_interface_reset(cur->id);
        reassembly_interface_reset(cur->id);

        icmp_nd_routers_init();

        /* Init RPL Timers */
        cur->bootstrap_state_machine_cnt = 0;

        cur->lowpan_info &= ~INTERFACE_NWK_ROUTER_DEVICE;
        cur->lowpan_info &= ~(INTERFACE_NWK_BOOTSTRAP_ACTIVE | INTERFACE_NWK_ACTIVE);
        cur->interface_mode = INTERFACE_IDLE;
        ret_val = 0;
    }
    return ret_val;
}

static int8_t set_6lowpan_nwk_up(protocol_interface_info_entry_t *cur)
{
    int8_t ret_val = 1;

    if ((cur->lowpan_info & INTERFACE_NWK_ACTIVE) == 0) {
        /* Change Idle-> Active */
        icmp_nd_routers_init();
        cur->nwk_bootstrap_state = ER_ACTIVE_SCAN;
        cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ACTIVE | INTERFACE_NWK_ACTIVE; //Set Active Bootstrap
        cur->lowpan_info &= ~INTERFACE_NWK_BOOTSTRAP_ADDRESS_REGISTER_READY; //Clear Bind
        cur->bootstrap_state_machine_cnt = 2;
        //Possible mac_mlme_start_req(call)
        mac_helper_panid_set(cur, 0xffff);
        mac_helper_mac16_address_set(cur, 0xffff);


        cur->interface_mode = INTERFACE_UP;
        ret_val = 0;
    }
    return ret_val;
}

int8_t nwk_6lowpan_up(protocol_interface_info_entry_t *cur)
{
    int8_t ret_val;

    ret_val = set_6lowpan_nwk_up(cur);
    if (ret_val == 0) {
        protocol_6lowpan_interface_common_init(cur);

        cur->nwk_mode = ARM_NWK_GP_IP_MODE;
    }

    return ret_val;
}

int8_t nwk_6lowpan_down(protocol_interface_info_entry_t *cur)
{
    int8_t ret_val;
    ret_val = set_6lowpan_nwk_down(cur);
    protocol_core_interface_info_reset(cur);
    return ret_val;
}
