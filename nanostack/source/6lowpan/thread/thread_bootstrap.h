/*
 * Copyright (c) 2014-2019, Pelion and affiliates.
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

/*
 * \file thread_bootstrap.h
 * \brief Add short description about this file!!!
 *
 */

#ifndef THREAD_BOOTSTRAP_H_
#define THREAD_BOOTSTRAP_H_

#include "eventOS_event.h"
#include "net_polling_api.h"
#include "service_libs/mle_service/mle_service_api.h"

#define THREAD_NETWORK_ACTIVE_SCAN_COUNTER 3
/** Thread Attach Retry limiters */
#define THREAD_CHILD_ID_REQUEST_MAX_RETRY_CNT 3
#define THREAD_PARENT_REQUEST_MAX_RETRY_CNT 2
#define THREAD_REQUEST_MAX_RETRY_CNT 3

#define THREAD_CHILD_ID_TIMEOUT (2 * 1000) /* 2 second */

struct thread_info_s;
struct protocol_interface_info_entry;
struct thread_leader_data_s;
struct link_configuration;
struct mac_neighbor_table_entry;
struct mle_tlv_info_s;

typedef enum {
    CON_ERROR_POLL,
    CON_ERROR_LINK_TX_FAIL,
    CON_ERROR_NO_THREAD_NETWORK_AVAILABLE,
    CON_ERROR_NEIGHBOR_UNREACHABLE,
    CON_ERROR_NETWORK_KICK,
    CON_ERROR_NETWORK_REATTACH,
    CON_ERROR_PARTITION_MERGE,
    CON_ERROR_NETWORK_ATTACH_FAIL,
    CON_PARENT_CONNECT_DOWN
} nwk_connect_error_types;


typedef enum {
    THREAD_INIT_EVENT = 0, /**< Initialize Thread Tasklet*/
    THREAD_CHILD_UPDATE,
    THREAD_BOOTSTRAP_RESET,
    THREAD_ATTACH_READY,
    THREAD_ATTACH_UPGRADE_REED,
    THREAD_ATTACH_DOWNGRADE_ROUTER,
    THREAD_ATTACH_ACTIVE_ROUTER,
    THREAD_ATTACH_ROUTER_ID_GET_FAIL,
    THREAD_ATTACH_ROUTER_ID_RELEASED,
    THREAD_CHILD_ID_REQUEST,
    THREAD_ANNOUNCE_ACTIVE

} thread_bootstrap_event_type_e;

typedef enum {
    THREAD_NORMAL_ATTACH = 0,
    THREAD_REATTACH,
    THREAD_REATTACH_REED,
    THREAD_PARTITION_MERGE,
    THREAD_ANY_ATTACH
} thread_bootstrap_state_type_e;

#define thread_interface_up(cur) ((void) 0)
#define thread_bootstrap_state_machine(cur) ((void)0)
#define thread_bootstrap_child_update_trig(cur) ((void)0)
#define thread_bootstrap_connection_error(interface_id, errorType, LinkId) ((void)0)
#define thread_bootstrap_network_data_update(cur,force_stable_update, force_unstable_update) ((void)0)
#define thread_bootstrap_network_data_changed(cur,force_stable_update,force_unstable_update) ((void)0)
#define thread_bootstrap_dynamic_configuration_save(cur) ((void)0)


#ifdef HAVE_THREAD_V2

void thread_bootstrap_address_registration_init(void);
bool thread_bootstrap_address_registration_running(void);
void thread_bootstrap_address_registration_deinit(void);
bool thread_bootstrap_is_domain_prefix(protocol_interface_info_entry_t *interface, const uint8_t *addr);
void thread_bootstrap_dua_address_generate(protocol_interface_info_entry_t *cur, const uint8_t *domain_prefix, uint8_t domain_prefix_len);
void thread_bootstrap_address_registration(struct protocol_interface_info_entry *interface, const uint8_t *addr, const uint8_t *child_mac64, bool refresh_child_entry, bool duplicate_child_detected);
void thread_bootstrap_child_address_registration_response_process(struct protocol_interface_info_entry *interface);
void thread_bootstrap_address_registration_timer_set(protocol_interface_info_entry_t *interface, uint16_t dua_delay_seconds, uint16_t mlr_refresh_seconds);
void thread_bootstrap_address_registration_timer(protocol_interface_info_entry_t *interface, uint16_t seconds);
#else

#define thread_bootstrap_address_registration_init()
#define thread_bootstrap_address_registration_running() ((void)0)
#define thread_bootstrap_address_registration_deinit()
#define thread_bootstrap_is_domain_prefix(interface, addr) ((void)0)
#define thread_bootstrap_dua_address_generate(cur, domain_prefix, domain_prefix_len)
#define thread_bootstrap_address_registration(interface, addr, child_mac64, refresh_child_entry, duplicate_child_detected)
#define thread_bootstrap_child_address_registration_response_process(interface)
#define thread_bootstrap_address_registration_timer_set(interface, dua_delay_seconds, mlr_refresh_seconds)
#define thread_bootstrap_address_registration_timer(interface, seconds)

#endif
#endif /* THREAD_BOOTSTRAP_H_ */
