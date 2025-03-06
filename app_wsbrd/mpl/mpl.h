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
struct trickle_legacy_params;
typedef struct buffer buffer_t;

// RFC 7731 6.1. MPL Option
enum {
    MPL_SEED_IPV6_SRC = 0,
    MPL_SEED_16_BIT   = 1,
    MPL_SEED_64_BIT   = 2,
    MPL_SEED_128_BIT  = 3,
};

typedef struct mpl_domain mpl_domain_t;
bool mpl_hbh_len_check(const uint8_t *opt_data, uint8_t opt_data_len);
bool mpl_process_hbh(buffer_t *buf, struct net_if *cur, uint8_t *opt_data);

bool mpl_forwarder_process_message(buffer_t *buf, mpl_domain_t *domain, bool decrement_hop_limit);

void mpl_timer(int seconds);

/* Time units for trickle parameters is 50 ms (1/20 s) ticks */
mpl_domain_t *mpl_domain_create(struct net_if *cur, const uint8_t address[16],
                                uint16_t seed_set_entry_lifetime, uint8_t seed_id_mode,
                                const struct trickle_legacy_params *data_trickle_params);
mpl_domain_t *mpl_domain_lookup(struct net_if *cur, const uint8_t address[16]);

#endif
