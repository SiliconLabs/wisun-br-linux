/*
 * Copyright (c) 2013-2017, Pelion and affiliates.
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
#ifndef ND_ROUTER_OBJECT_H_
#define ND_ROUTER_OBJECT_H_
#include <stdint.h>
#include <stdbool.h>
#include "6lowpan/nd/nd_defines.h"

struct nd_parameters;
struct aro;
enum addrtype;

extern uint8_t nd_base_tick;
extern struct nd_parameters nd_params;

void icmp_nd_set_nd_def_router_address(uint8_t *ptr, nd_router_t *cur);

buffer_t *nd_dar_parse(buffer_t *buf, struct net_if *cur_interface);
buffer_t *nd_dac_handler(buffer_t *buf, struct net_if *cur);
void nd_ns_build(nd_router_t *cur, struct net_if *cur_interface, uint8_t *address_ptr);

void icmp_nd_routers_init(void);

bool nd_ns_aro_handler(struct net_if *cur_interface, const uint8_t *aro_opt, const uint8_t *slaa_opt, const uint8_t *target, struct aro *aro_out);
void nd_remove_registration(struct net_if *cur_interface, enum addrtype ll_type, const uint8_t *ll_address);

nd_router_t *nd_get_object_by_nwk_id();
void nd_object_timer(int ticks_update);

void icmp_nd_router_object_reset(nd_router_t *router_object);

#endif
