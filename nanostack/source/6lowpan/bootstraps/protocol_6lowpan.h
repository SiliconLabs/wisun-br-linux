/*
 * Copyright (c) 2015-2018, 2020, Pelion and affiliates.
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
 * \file protocol_6lowpan.h
 *
 */

#ifndef PROTOCOL_6LOWPAN_H_
#define PROTOCOL_6LOWPAN_H_

struct protocol_interface_info_entry;
struct route_info_entry_t;
struct ns_sockaddr;
struct rpl_domain;
struct rpl_dodag;
struct mlme_pan_descriptor_s;


extern struct rpl_domain *protocol_6lowpan_rpl_domain;
extern struct rpl_dodag *protocol_6lowpan_rpl_root_dodag;

typedef enum {
    PRIORITY_1ST,
    PRIORITY_2ND,
} neighbor_priority;

void protocol_6lowpan_interface_common_init(struct protocol_interface_info_entry *cur);
void protocol_6lowpan_configure_core(struct protocol_interface_info_entry *cur);

uint16_t protocol_6lowpan_neighbor_priority_set(int8_t interface_id, addrtype_t addr_type, const uint8_t *addr_ptr);
uint16_t protocol_6lowpan_neighbor_second_priority_set(int8_t interface_id, addrtype_t addr_type, const uint8_t *addr_ptr);
void protocol_6lowpan_neighbor_priority_clear_all(int8_t interface_id, neighbor_priority priority);


int8_t protocol_6lowpan_neighbor_address_state_synch(struct protocol_interface_info_entry *cur, const uint8_t eui64[8], const uint8_t iid[8]);
int8_t protocol_6lowpan_neighbor_remove(struct protocol_interface_info_entry *cur, uint8_t *address_ptr, addrtype_t type);

void protocol_6lowpan_allocate_mac16(protocol_interface_info_entry_t *cur);

int8_t protocol_6lowpan_interface_compare_cordinator_netid(struct protocol_interface_info_entry *cur, uint8_t *adr_ptr);
int8_t protocol_6lowpan_interface_get_mac_coordinator_address(protocol_interface_info_entry_t *cur, struct ns_sockaddr *adr_ptr);

int16_t protocol_6lowpan_rpl_global_priority_get(void);
bool protocol_6lowpan_latency_estimate_get(int8_t interface_id, uint32_t *latency);
bool protocol_6lowpan_stagger_estimate_get(int8_t interface_id, uint32_t data_amount, uint16_t *stagger_min, uint16_t *stagger_max, uint16_t *stagger_rand);

#endif /* PROTOCOL_6LOWPAN_H_ */
