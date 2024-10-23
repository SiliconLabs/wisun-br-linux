/*
 * Copyright (c) 2016-2021, Pelion and affiliates.
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

#ifndef LOWPAN_ADAPTATION_INTERFACE_H_
#define LOWPAN_ADAPTATION_INTERFACE_H_
#include <stdint.h>
#include <stdbool.h>

struct net_if;
struct mcps_data_cnf;
struct mcps_data_ind;
struct buffer;
struct mpx_api;
enum buffer_priority;
typedef enum addrtype addrtype_e;

void lowpan_adaptation_interface_init(int8_t interface_id);

int8_t lowpan_adaptation_interface_free(int8_t interface_id);

int8_t lowpan_adaptation_interface_reset(int8_t interface_id);

void lowpan_adaptation_interface_mpx_register(int8_t interface_id, struct mpx_api *mpx_api, uint16_t mpx_user_id);

int lowpan_adaptation_queue_size(int8_t interface_id);

/**
 * \brief call this before normal TX. This function prepare buffer link specific metadata and verify packet destination
 */
struct buffer *lowpan_adaptation_data_process_tx_preprocess(struct net_if *cur, struct buffer *buf);

int8_t lowpan_adaptation_interface_tx(struct net_if *cur, struct buffer *buf);

struct buffer *lowpan_adaptation_reassembly(struct net_if *cur, struct buffer *buf);

int8_t lowpan_adaptation_free_messages_from_queues_by_address(struct net_if *cur, const uint8_t *address_ptr, addrtype_e adr_type);

#endif
