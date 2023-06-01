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

void ws_bootstrap_ffn_candidate_table_reset(struct net_if *cur);
void ws_bootstrap_ffn_eapol_parent_synch(struct net_if *cur, struct llc_neighbour_req *neighbor_info);

void ws_bootstrap_ffn_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type);
void ws_bootstrap_ffn_asynch_confirm(struct net_if *interface, uint8_t asynch_message);
void ws_bootstrap_ffn_event_handler(struct net_if *cur, struct event_payload *event);
void ws_bootstrap_ffn_state_machine(struct net_if *cur);
void ws_bootstrap_ffn_seconds_timer(struct net_if *cur, uint32_t seconds);

void ws_bootstrap_authentication_completed(struct net_if *cur, auth_result_e result, uint8_t *target_eui_64);
const uint8_t *ws_bootstrap_authentication_next_target(struct net_if *cur, const uint8_t *previous_eui_64, uint16_t *pan_id);

void ws_ffn_trickle_stop(struct ws_mngt *mngt);
void ws_ffn_pas_trickle(struct net_if *cur, int ticks);
void ws_ffn_pas_test_exec(struct net_if *cur, int procedure);
void ws_ffn_pas_test_trigger(struct net_if *cur, int seconds);
void ws_ffn_pcs_trickle(struct net_if *cur, int ticks);
void ws_ffn_pcs_test_exec(struct net_if *cur, int procedure);
void ws_ffn_pcs_test_trigger(struct net_if *cur, int seconds);

#else
#include "stack/source/6lowpan/ws/ws_pae_controller.h"

static inline void ws_bootstrap_ffn_candidate_table_reset(struct net_if *cur)
{
}

static inline void ws_bootstrap_ffn_eapol_parent_synch(struct net_if *cur, struct llc_neighbour_req *neighbor_info)
{
}

static inline void ws_bootstrap_ffn_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

static inline void ws_bootstrap_ffn_asynch_confirm(struct net_if *interface, uint8_t asynch_message)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

#define ws_bootstrap_ffn_event_handler(cur, event) ((void) 0)
#define ws_bootstrap_ffn_state_machine(cur) ((void) 0)
#define ws_bootstrap_ffn_seconds_timer(cur, seconds) ((void) 0)

static inline void ws_bootstrap_authentication_completed(struct net_if *cur, auth_result_e result, uint8_t *target_eui_64)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

static inline const uint8_t *ws_bootstrap_authentication_next_target(struct net_if *cur, const uint8_t *previous_eui_64, uint16_t *pan_id)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

static inline void ws_ffn_trickle_stop(struct ws_mngt *mngt)
{
    // empty
}

static inline void ws_ffn_pas_trickle(struct net_if *cur, int ticks)
{
    // empty
}

static inline void ws_ffn_pas_test_exec(struct net_if *cur, int procedure)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

static inline void ws_ffn_pas_test_trigger(struct net_if *cur, int seconds)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

static inline void ws_ffn_pcs_trickle(struct net_if *cur, int ticks)
{
    // empty
}

static inline void ws_ffn_pcs_test_exec(struct net_if *cur, int procedure)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

static inline void ws_ffn_pcs_test_trigger(struct net_if *cur, int seconds)
{
    BUG("not compiled with HAVE_WS_ROUTER");
}

#endif

#endif
