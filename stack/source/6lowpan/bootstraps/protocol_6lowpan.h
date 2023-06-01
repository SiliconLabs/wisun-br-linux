/*
 * Copyright (c) 2015-2018, 2020, Pelion and affiliates.
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

/*
 * \file protocol_6lowpan.h
 *
 */

#ifndef PROTOCOL_6LOWPAN_H_
#define PROTOCOL_6LOWPAN_H_
#include <stdint.h>
#include <stdbool.h>

struct net_if;
struct ns_sockaddr;
struct rpl_domain;
struct rpl_dodag;
enum addrtype;

extern struct rpl_domain *protocol_6lowpan_rpl_domain;
extern struct rpl_dodag *protocol_6lowpan_rpl_root_dodag;

typedef enum {
    PRIORITY_1ST,
    PRIORITY_2ND,
} neighbor_priority_e;

void protocol_6lowpan_interface_common_init(struct net_if *cur);
void protocol_6lowpan_configure_core(struct net_if *cur);

uint16_t protocol_6lowpan_neighbor_priority_set(int8_t interface_id, enum addrtype addr_type, const uint8_t *addr_ptr);
uint16_t protocol_6lowpan_neighbor_second_priority_set(int8_t interface_id, enum addrtype addr_type, const uint8_t *addr_ptr);
void protocol_6lowpan_neighbor_priority_clear_all(int8_t interface_id, neighbor_priority_e priority);


int8_t protocol_6lowpan_neighbor_address_state_synch(struct net_if *cur, const uint8_t eui64[8], const uint8_t iid[8]);

void protocol_6lowpan_allocate_mac16(struct net_if *cur);

#endif /* PROTOCOL_6LOWPAN_H_ */
