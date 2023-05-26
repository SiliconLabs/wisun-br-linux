/*
 * Copyright (c) 2021, Pelion and affiliates.
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

#ifndef WS_BOOTSTRAP_FFN_H_
#define WS_BOOTSTRAP_FFN_H_
#include <stdint.h>
#include "common/log.h"
#include "common/events_scheduler.h"

struct net_if;
struct ws_mngt;
struct llc_neighbour_req;
struct mcps_data_ind;
struct mcps_data_ie_list;
typedef enum auth_result auth_result_e;

#ifdef HAVE_WS_ROUTER

void ws_bootstrap_ffn_seconds_timer(struct net_if *cur, uint32_t seconds);

#else
#include "stack/source/6lowpan/ws/ws_pae_controller.h"

#define ws_bootstrap_ffn_seconds_timer(cur, seconds) ((void) 0)
#endif

#endif
