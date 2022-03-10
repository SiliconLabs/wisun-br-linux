/*
 * Copyright (c) 2015-2021, Pelion and affiliates.
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
 * \file protocol_6lowpan_bootstrap.c
 *
 */
#include "nsconfig.h"
#include <string.h>
#include <stdint.h>
#include "mbed-client-libservice/ns_trace.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "mbed-client-libservice/nsdynmemLIB.h"
#include "common/rand.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_timer.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/icmpv6_radv.h"
#include "common_protocols/udp.h"
#include "6lowpan/bootstraps/network_lib.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#include "service_libs/blacklist/blacklist.h"
#include "6lowpan/mac/mac_helper.h"
#include "nanostack/mac/mac_api.h"
#include "rpl/rpl_control.h"

#include "nanostack/shalib.h"
#include "nanostack/net_nvm_api.h"
#include "mbed-client-libservice/common_functions.h"
#include "nanostack/net_interface.h"
#include "security/common/sec_lib.h"
#include "6lowpan/nd/nd_router_object.h"
#include "service_libs/etx/etx.h"
#include "nanostack/mac/mac_api.h"
#include "net_lib/src/net_load_balance_internal.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/nvm/nwk_nvm.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"


/* Fixed-point randomisation limits for randlib_randomise_base() - RFC 3315
 * says RAND is uniformly distributed between -0.1 and +0.1
 */
#define LOWPAN_RAND_LOW   0x7333 // 1 - 0.1; minimum for "1+RAND"
#define LOWPAN_RAND_HIGH  0x8CCD // 1 + 0.1; maximum for "1+RAND"

#define TRACE_GROUP_LOWPAN_BOOT "6Bo"
#define TRACE_GROUP "6Bo"

static void protocol_6lowpan_address_reg_ready(protocol_interface_info_entry_t *cur_interface);

#define MAX_MC_DIS_COUNT 3

void arm_6lowpan_bootstrap_init(protocol_interface_info_entry_t *cur)
{
    //Init 6LoWPAN Bootstrap
    icmp_nd_routers_init();
    cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ACTIVE;
    cur->lowpan_info &= ~INTERFACE_NWK_BOOTSTRAP_ADDRESS_REGISTER_READY;
    bootstrap_next_state_kick(ER_SCAN, cur);
    mac_helper_mac16_address_set(cur, 0xffff);
}


void protocol_6lowpan_link_advertise_handle(nd_router_t *cur, protocol_interface_info_entry_t *cur_interface, uint16_t tick)
{
    cur->mle_advert_timer = 0;
}

static void protocol_6lowpan_nd_ready(protocol_interface_info_entry_t *cur)
{
    if ((cur->lowpan_info & INTERFACE_NWK_BOOTSTRAP_ACTIVE)) {
        tr_debug("ND BS ready");
        bootstrap_next_state_kick(ER_BIND_COMP, cur);
        clear_power_state(ICMP_ACTIVE);
        cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ADDRESS_REGISTER_READY;
    } else {
        tr_debug("RE ND ready");
        clear_power_state(ICMP_ACTIVE);
    }
}

static void protocol_6lowpan_address_reg_ready(protocol_interface_info_entry_t *cur_interface)
{
    nd_router_t *cur;
    cur = nd_get_object_by_nwk_id(cur_interface->nwk_id);

    if (!cur) {
        return;
    }

    cur->nd_timer = 10;
    cur->ns_forward_timer = 0;

    protocol_6lowpan_nd_ready(cur_interface);
    if (cur_interface->lowpan_info & INTERFACE_NWK_ROUTER_DEVICE) {
        addr_add_router_groups(cur_interface);
        addr_add_group(cur_interface, ADDR_REALM_LOCAL_ALL_ROUTERS);
        icmpv6_radv_enable(cur_interface);
        icmpv6_restart_router_advertisements(cur_interface, cur->border_router);
        /* Stop the ND revalidate timer - this means we don't do RS again */
        cur->nd_re_validate = 0;
    }
    cur->mle_advert_timer = 0;
}

void protocol_6lowpan_bootstrap_nd_ready(protocol_interface_info_entry_t *cur_interface)
{

    tr_debug("ND Ready");



    if (cur_interface->lowpan_address_mode == NET_6LOWPAN_GP64_ADDRESS) {
        protocol_6lowpan_address_reg_ready(cur_interface);
    } else {
        //Here we need to verify address mode
        tr_debug("Synch MAC16 with parent");
        nwk_bootstrap_state_update(ARM_NWK_NWK_CONNECTION_DOWN, cur_interface);
    }


}

bool protocol_6lowpan_bootstrap_link_set(protocol_interface_info_entry_t *interface, mlme_pan_descriptor_t *pan_descriptor, const uint8_t *beacon_payload, uint8_t beacon_length)
{
    mlme_start_t start_req;
    memset(&start_req, 0, sizeof(mlme_start_t));
    mac_helper_coordinator_address_set(interface, (addrtype_t)pan_descriptor->CoordAddrMode, pan_descriptor->CoordAddress);

    interface->mac_parameters->mac_channel = pan_descriptor->LogicalChannel;
    interface->mac_parameters->pan_id = pan_descriptor->CoordPANId;
    if (interface->nwk_wpan_nvm_api) {
        wpan_nvm_params_t *params = interface->nwk_wpan_nvm_api->nvm_params_get_cb(interface->nwk_wpan_nvm_api, pan_descriptor->CoordPANId);
        interface->if_lowpan_security_params->mle_security_frame_counter = params->mle_securit_counter;
        mac_helper_link_frame_counter_set(interface->id, params->mac_security_frame_counter);
    }

    start_req.PANId = pan_descriptor->CoordPANId;
    start_req.LogicalChannel = pan_descriptor->LogicalChannel;
    start_req.ChannelPage = 0;
    start_req.BeaconOrder = pan_descriptor->SuperframeSpec[0] >> 4;
    start_req.SuperframeOrder = pan_descriptor->SuperframeSpec[0] & 0x0f;
    //SET Beacon Payload
    uint8_t *b_ptr = mac_helper_beacon_payload_reallocate(interface, beacon_length);
    if (!b_ptr) {
        tr_error("Beacon Payload allocate Fail");
        bootstrap_next_state_kick(ER_BOOTSTRAP_SCAN_FAIL, interface);
        return false;
    }
    memcpy(b_ptr, beacon_payload, beacon_length);
    mac_helper_beacon_payload_register(interface);
    //Start and set pan-id
    interface->mac_api->mlme_req(interface->mac_api, MLME_START, &start_req);
    mac_helper_panid_set(interface, pan_descriptor->CoordPANId);

    return true;
}

void protocol_6lowpan_nd_borderrouter_connection_down(protocol_interface_info_entry_t *interface)
{
    /*if (rpl_object_poisons() == 0) ??? */ {
        mac_helper_mac16_address_set(interface, 0xffff);

        //TRIG Event for ND connection Down
        bootstrap_next_state_kick(ER_BOOTSTRAP_IP_ADDRESS_ALLOC_FAIL, interface);
    }
}

void protocol_6lowpan_bootstrap_re_start(protocol_interface_info_entry_t *interface)
{
    mac_helper_mac16_address_set(interface, 0xffff);
    arm_6lowpan_bootstrap_init(interface);
    tr_info("-->Bootstrap");
}

uint8_t *protocol_6lowpan_nd_border_router_address_get(nwk_interface_id nwk_id)
{
    nd_router_t   *object = nd_get_object_by_nwk_id(nwk_id);
    if (object) {
        return object->border_router;
    }
    return 0;
}

uint8_t protocol_6lowpan_rf_link_scalability_from_lqi(uint8_t lqi)
{
    uint8_t i = 16;
    if (lqi >= 240) {
        i = 1;
    } else {
        lqi /= 16;
        if (lqi) {
            i = (16 - lqi);
        }
    }
    return i;
}

int protocol_6lowpan_del_ll16(protocol_interface_info_entry_t *cur, uint16_t mac_short_address)
{
    uint8_t address[16];
    memcpy(address, ADDR_LINK_LOCAL_PREFIX, 8);
    memcpy(address + 8, ADDR_SHORT_ADR_SUFFIC, 6);
    common_write_16_bit(mac_short_address, &address[14]);

    return addr_delete(cur, address);
}

bool lowpan_neighbour_data_clean(int8_t interface_id, const uint8_t *link_local_address)
{

    protocol_interface_info_entry_t *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return false;
    }
    bool return_value = false;
    mac_neighbor_table_entry_t *neigh_entry = mac_neighbor_entry_get_by_ll64(mac_neighbor_info(cur), link_local_address, false, NULL);
    if (neigh_entry) {
        //Remove entry
        if (neigh_entry->link_role == PRIORITY_PARENT_NEIGHBOUR || neigh_entry->link_role == SECONDARY_PARENT_NEIGHBOUR) {
            return_value = true;
        }
        mac_neighbor_table_neighbor_remove(mac_neighbor_info(cur), neigh_entry);
    }
    return return_value;
}

