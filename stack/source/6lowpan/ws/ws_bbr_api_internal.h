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

#ifndef WS_BBR_API_PRIVATE_H_
#define WS_BBR_API_PRIVATE_H_

#include <stdint.h>
#include <stdbool.h>

struct ws_pom_ie;
struct net_if;

extern uint16_t test_pan_size_override;

void ws_bbr_seconds_timer(struct net_if *cur, uint32_t seconds);

void ws_bbr_pan_version_increase(struct net_if *cur);
void ws_bbr_lpan_version_increase(struct net_if *cur);

uint16_t ws_bbr_pan_size(struct net_if *cur);

int ws_bbr_get_backbone_id();

void ws_bbr_rpl_config(struct net_if *cur, uint8_t imin, uint8_t doubling, uint8_t redundancy, uint16_t dag_max_rank_increase, uint16_t min_hop_rank_increase, uint32_t lifetime);

bool ws_bbr_ready_to_start(struct net_if *cur);

bool ws_bbr_backbone_address_get(uint8_t *address);

uint16_t ws_bbr_bsi_generate(struct net_if *interface);
uint16_t ws_bbr_pan_id_get(struct net_if *interface);
void ws_bbr_init(struct net_if *interface);

#endif
