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

#include "6lowpan/ws/ws_common.h"
#include "nwk_interface/protocol.h"

struct rpl_instance;
struct ws_stack_info;
struct ws_llc_mngt_req;
struct ws_neighbour_info;
struct mcps_data_rx_ie_list;
struct mcps_data_ind;

int ws_bootstrap_init(int8_t interface_id);

int8_t ws_bootstrap_up(struct net_if *cur, const uint8_t *ipv6_address);

void ws_bootstrap_state_machine(struct net_if *cur);

void ws_bootstrap_configuration_trickle_reset(struct net_if *cur);

void ws_bootstrap_seconds_timer(struct net_if *cur, uint32_t seconds);

void ws_bootstrap_trickle_timer(struct net_if *cur, uint16_t ticks);

/*
 * Functions shared with different bootstrap modes
 */

/*State machine transactions*/
void ws_bootstrap_event_discovery_start(struct net_if *cur);

// Bootstrap state machine state Functions
struct ws_neighbor_class_entry *ws_bootstrap_neighbor_add(struct net_if *net_if, const uint8_t eui64[8], uint8_t role);
void ws_bootstrap_neighbor_del(const uint8_t *mac64);


void ws_bootstrap_fhss_configure_channel_masks(struct net_if *cur, fhss_ws_configuration_t *fhss_configuration);
int8_t ws_bootstrap_fhss_set_defaults(struct net_if *cur, fhss_ws_configuration_t *fhss_configuration);
void ws_bootstrap_fhss_activate(struct net_if *cur);
uint16_t ws_bootstrap_randomize_fixed_channel(uint16_t configured_fixed_channel, uint8_t number_of_channels, uint8_t *channel_mask);
int ws_bootstrap_set_domain_rf_config(struct net_if *cur);


void ws_bootstrap_llc_hopping_update(struct net_if *cur, const fhss_ws_configuration_t *fhss_configuration);

void ws_bootstrap_ip_stack_reset(struct net_if *cur);
void ws_bootstrap_ip_stack_activate(struct net_if *cur);

void ws_bootstrap_packet_congestion_init(struct net_if *cur);

void ws_bootstrap_asynch_trickle_stop(struct net_if *cur);
void ws_bootstrap_advertise_start(struct net_if *cur);
void ws_bootstrap_pan_advert(struct net_if *cur);
void ws_bootstrap_pan_config(struct net_if *cur);

#endif
