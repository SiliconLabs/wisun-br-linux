/*
 * Copyright (c) 2015-2017, Pelion and affiliates.
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

#ifndef MPL_H_
#define MPL_H_
#include <stdint.h>
#include <stdbool.h>

#include <stdint.h>

struct net_if;
struct trickle_params;
typedef struct buffer buffer_t;
typedef enum multicast_mpl_seed_id_mode multicast_mpl_seed_id_mode_e;

/* Timing is in 50 ms (1/20 s) ticks */
#define MPL_TICK_MS 50

#define MPL_MS_TO_TICKS(t) (((t) + MPL_TICK_MS - 1) / MPL_TICK_MS)

extern const struct trickle_params rfc7731_default_data_message_trickle_params;
#define RFC7731_DEFAULT_SEED_SET_ENTRY_LIFETIME (30 * 60) // seconds

typedef struct mpl_domain mpl_domain_t;
bool mpl_hbh_len_check(const uint8_t *opt_data, uint8_t opt_data_len);
bool mpl_process_hbh(buffer_t *buf, struct net_if *cur, uint8_t *opt_data);

bool mpl_forwarder_process_message(buffer_t *buf, mpl_domain_t *domain, bool decrement_hop_limit);

void mpl_slow_timer(int seconds);

void mpl_clear_realm_scope_seeds(struct net_if *cur);

/* Time units for trickle parameters is 50 ms (1/20 s) ticks */
mpl_domain_t *mpl_domain_create(struct net_if *cur, const uint8_t address[16],
                                const uint8_t *seed_id, multicast_mpl_seed_id_mode_e seed_id_type,
                                uint16_t seed_set_entry_lifetime,
                                const struct trickle_params *data_trickle_params);
mpl_domain_t *mpl_domain_lookup(struct net_if *cur, const uint8_t address[16]);
bool mpl_domain_delete(struct net_if *cur, const uint8_t address[16]);

/* Back door to implement deprecated multicast_set_parameters() API */
void mpl_domain_change_timing(mpl_domain_t *domain, const struct trickle_params *data_trickle_params, uint16_t seed_set_entry_lifetime);

void mpl_fast_timer(int ticks);

#endif
