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

#ifndef WS_BOOTSTRAP_LFN_H_
#define WS_BOOTSTRAP_LFN_H_
#include <stdint.h>
#include "common/log.h"
#include "common/events_scheduler.h"

struct net_if;
struct mcps_data_ind;
struct mcps_data_ie_list;

#ifdef HAVE_WS_HOST

void ws_bootstrap_lfn_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type);
void ws_bootstrap_lfn_asynch_confirm(struct net_if *interface, uint8_t asynch_message);
void ws_bootstrap_lfn_event_handler(struct net_if *cur, arm_event_s *event);
void ws_bootstrap_lfn_state_machine(struct net_if *cur);
void ws_bootstrap_lfn_seconds_timer(struct net_if *cur, uint32_t seconds);

#else

static inline void ws_bootstrap_lfn_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type)
{
    BUG("not compiled with HAVE_WS_HOST");
}

static inline void ws_bootstrap_lfn_asynch_confirm(struct net_if *interface, uint8_t asynch_message)
{
    BUG("not compiled with HAVE_WS_HOST");
}

#define ws_bootstrap_lfn_event_handler(cur, event) ((void) 0)
#define ws_bootstrap_lfn_state_machine(cur) ((void) 0)
#define ws_bootstrap_lfn_seconds_timer(cur, seconds) ((void) 0)

#endif

#endif
