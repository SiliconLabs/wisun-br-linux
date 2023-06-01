/*
 * Copyright (c) 2017-2018, Pelion and affiliates.
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

#include <string.h>

#include "nwk_interface/protocol.h"
#include "common_protocols/ipv6_constants.h"
#include "mpl/mpl.h"

#include "stack/net_multicast.h"

int8_t multicast_mpl_domain_subscribe(int8_t interface_id,
                                      const uint8_t address[16],
                                      multicast_mpl_seed_id_mode_e seed_id_mode,
                                      const void *seed_id)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!interface) {
        return -1;
    }

    return mpl_domain_create(interface, address, seed_id, seed_id_mode, -1, 0, NULL, NULL) ? 0 : -1;
}

int8_t multicast_mpl_domain_subscribe_with_parameters
(int8_t interface_id,
 const uint8_t address[16],
 multicast_mpl_seed_id_mode_e seed_id_mode,
 const void *seed_id,
 bool proactive_forwarding,
 uint16_t seed_set_entry_lifetime,
 uint32_t data_message_imin,
 uint32_t data_message_imax,
 uint8_t data_message_k,
 uint8_t data_message_timer_expirations,
 uint32_t control_message_imin,
 uint32_t control_message_imax,
 uint8_t control_message_k,
 uint8_t control_message_timer_expirations)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!interface) {
        return -1;
    }

    const trickle_params_t data_params = {
        .Imax = MPL_MS_TO_TICKS(data_message_imax),
        .Imin = MPL_MS_TO_TICKS(data_message_imin),
        .k = data_message_k,
        .TimerExpirations = data_message_timer_expirations
    },
    control_params = {
        .Imax = MPL_MS_TO_TICKS(control_message_imax),
        .Imin = MPL_MS_TO_TICKS(control_message_imin),
        .k = control_message_k,
        .TimerExpirations = control_message_timer_expirations
    };
    return mpl_domain_create(interface, address, seed_id, seed_id_mode, proactive_forwarding, seed_set_entry_lifetime, &data_params, &control_params) ? 0 : -1;
}

int_fast8_t multicast_mpl_set_default_parameters(int8_t interface_id,
                                                 bool proactive_forwarding,
                                                 uint16_t seed_set_entry_lifetime,
                                                 uint32_t data_message_imin,
                                                 uint32_t data_message_imax,
                                                 uint8_t data_message_k,
                                                 uint8_t data_message_timer_expirations,
                                                 uint32_t control_message_imin,
                                                 uint32_t control_message_imax,
                                                 uint8_t control_message_k,
                                                 uint8_t control_message_timer_expirations)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!interface) {
        return -1;
    }

    interface->mpl_proactive_forwarding = proactive_forwarding;
    interface->mpl_seed_set_entry_lifetime = seed_set_entry_lifetime;
    interface->mpl_data_trickle_params.Imin = MPL_MS_TO_TICKS(data_message_imin);
    interface->mpl_data_trickle_params.Imax = MPL_MS_TO_TICKS(data_message_imax);
    interface->mpl_data_trickle_params.k = data_message_k;
    interface->mpl_data_trickle_params.TimerExpirations = data_message_timer_expirations;
    interface->mpl_control_trickle_params.Imin = MPL_MS_TO_TICKS(control_message_imin);
    interface->mpl_control_trickle_params.Imax = MPL_MS_TO_TICKS(control_message_imax);
    interface->mpl_control_trickle_params.k = control_message_k;
    interface->mpl_control_trickle_params.TimerExpirations = control_message_timer_expirations;

    return 0;
}

int_fast8_t multicast_mpl_set_default_seed_id(int8_t interface_id,
                                              multicast_mpl_seed_id_mode_e seed_id_mode,
                                              const void *seed_id)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!interface) {
        return -1;
    }

    switch (seed_id_mode) {
        case MULTICAST_MPL_SEED_ID_128_BIT:
        case MULTICAST_MPL_SEED_ID_64_BIT:
        case MULTICAST_MPL_SEED_ID_16_BIT:
            memcpy(interface->mpl_seed_id, seed_id, seed_id_mode);
            break;
        case MULTICAST_MPL_SEED_ID_IPV6_SRC_FOR_DOMAIN:
        case MULTICAST_MPL_SEED_ID_IID_EUI64:
        case MULTICAST_MPL_SEED_ID_IID_SLAAC:
        case MULTICAST_MPL_SEED_ID_MAC:
        case MULTICAST_MPL_SEED_ID_MAC_SHORT:
            break;
        default:
            return -2;
    }

    interface->mpl_seed_id_mode = seed_id_mode;

    return 0;
}

int8_t multicast_mpl_domain_unsubscribe(int8_t interface_id,
                                        const uint8_t address[16])
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);
    if (!interface) {
        return -1;
    }

    return mpl_domain_delete(interface, address) ? 0 : -1;
}

void multicast_set_parameters(uint8_t i_min, uint8_t i_doublings, uint8_t k, uint8_t timer_expirations, uint16_t window_expiration)
{
    struct net_if *cur = protocol_stack_interface_info_get();
    if (!cur) {
        return;
    }

    trickle_time_t i_max = i_min;
    for (; i_doublings; i_doublings--) {
        if (i_max <= TRICKLE_TIME_MAX / 2) {
            i_max *= 2;
        } else {
            i_max = TRICKLE_TIME_MAX;
            break;
        }
    }

    /* Set the interface's default parameters, and also update the All-Forwarders domain */
    cur->mpl_data_trickle_params.Imin = i_min;
    cur->mpl_data_trickle_params.Imax = i_max;
    cur->mpl_data_trickle_params.k = k;
    cur->mpl_data_trickle_params.TimerExpirations = timer_expirations;
    /* MPL core uses a 4:1 ratio for seed and message lifetimes - we somewhat
     * arbitrarily treat window expiration parameter as a request for message lifetime.
     */
    uint32_t message_lifetime_ticks = (uint32_t) i_max * timer_expirations + window_expiration;
    uint32_t seed_lifetime_ticks = 4 * message_lifetime_ticks;
    cur->mpl_seed_set_entry_lifetime = (seed_lifetime_ticks + 20) / 20; // convert to seconds
    mpl_domain_t *domain = mpl_domain_lookup(cur, ADDR_ALL_MPL_FORWARDERS);
    if (!domain) {
        return;
    }

    mpl_domain_change_timing(domain, &cur->mpl_data_trickle_params, cur->mpl_seed_set_entry_lifetime);
}


uint8_t multicast_add_address(const uint8_t *address_ptr, uint8_t use_trickle)
{
    uint8_t ret_val = 1;
    if (!addr_is_ipv6_multicast(address_ptr)) {
        return 0;
    }

    uint8_t scope = addr_ipv6_multicast_scope(address_ptr);
    if (scope == 0) { // reserved
        return 0;
    } else if (scope <= IPV6_SCOPE_LINK_LOCAL) {
        use_trickle = false;
    }

    // Hacky hack.
    // Consider 6LoWPAN and Ethernet interfaces - if in the same scope zone, attach to one,
    // 6LoWPAN by preference. If different, attach to both.
    // If use_trickle is set, then
    //    1) Make sure MPL is enabled on 6LoWPAN by creating the ff03::fc domain
    //    2) Subscribe to that MPL domain if Realm Local and not acting as single domain
    //       (If larger scope, then we don't create a domain, we tunnel in ff03::fc)
    struct net_if *lowpan = protocol_stack_interface_info_get();

    if (lowpan) {
        if (use_trickle && !lowpan->mpl_seed) {
            mpl_domain_create(lowpan, ADDR_ALL_MPL_FORWARDERS, NULL, MULTICAST_MPL_SEED_ID_DEFAULT, -1, 0, NULL, NULL);
        }

        if (use_trickle && scope == IPV6_SCOPE_REALM_LOCAL) {
            ret_val = multicast_mpl_domain_subscribe(lowpan->id, address_ptr, MULTICAST_MPL_SEED_ID_DEFAULT, NULL);
        } else
        {
            addr_add_group(lowpan, address_ptr);
        }
    }

    return ret_val;
}

uint8_t multicast_free_address(const uint8_t *address_ptr)
{
    // Hacky hack
    struct net_if *lowpan = protocol_stack_interface_info_get();
    if (lowpan) {
        /* First try to delete from MPL - if that fails, delete as plain group */
        if (multicast_mpl_domain_unsubscribe(lowpan->id, address_ptr) < 0)
        {
            addr_remove_group(lowpan, address_ptr);
        }
    }

    return 0;
}
