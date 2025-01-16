/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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

#ifndef WS_BOOTSTRAP_H_
#define WS_BOOTSTRAP_H_
#include <stdint.h>
#include <stdbool.h>

#include "ws/ws_common.h"
#include "net/protocol.h"

struct rpl_instance;
struct ws_stack_info;
struct ws_llc_mngt_req;
struct ws_neighbour_info;
struct mcps_data_rx_ie_list;
struct ws_neigh_table;
struct mcps_data_ind;
struct ws_neigh;

void ws_bootstrap_init(int8_t interface_id);

void ws_bootstrap_up(struct net_if *cur, const uint8_t *ipv6_address);

void ws_bootstrap_neighbor_add_cb(struct ws_neigh_table *table, struct ws_neigh *ws_neigh);
void ws_bootstrap_neighbor_del_cb(struct ws_neigh_table *table, struct ws_neigh *ws_neigh);


void ws_bootstrap_fhss_activate(struct net_if *cur);
int ws_bootstrap_set_domain_rf_config(struct net_if *cur);

void ws_bootstrap_ip_stack_reset(struct net_if *cur);
void ws_bootstrap_ip_stack_activate(struct net_if *cur);

void ws_bootstrap_packet_congestion_init(struct net_if *cur);

void ws_bootstrap_nw_key_set(struct net_if *cur,
                             uint8_t key_index,
                             const uint8_t key[16],
                             uint32_t frame_counter);
void ws_bootstrap_nw_key_index_set(struct net_if *cur, uint8_t index);

#endif
