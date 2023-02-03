/*
 * Copyright (c) 2013-2017, Pelion and affiliates.
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
#ifndef ND_ROUTER_OBJECT_H_
#define ND_ROUTER_OBJECT_H_
#include <stdint.h>
#include <stdbool.h>
#include "6lowpan/nd/nd_defines.h"

typedef struct nd_parameters {
    uint8_t rs_retry_max;                   /**< Define Bootstrap RS max retry count. */
    uint8_t ns_retry_max;                   /**< Define Bootstrap NS max retry count. */
    uint16_t timer_random_max;              /**< Define Interval random in 6LoWPAN bootstrap timer ticks for RS, NS and starting NS - NA process.  */
    uint16_t rs_retry_interval_min;         /**< Define Retry interval in 6LoWPAN bootstrap timer ticks waiting for RA. */
    uint16_t ns_retry_interval_min;         /**< Define Retry interval in 6LoWPAN bootstrap timer ticks waiting for NA. */
    uint16_t ns_retry_linear_backoff;       /**< Define Retry interval linear backoff in bootstrap timer ticks. */
    bool multihop_dad;                      /**< Define whether to perform duplicate address detection with border router or locally. */
    bool send_nud_probes;                   /**< Define whether IPv6 NUD probes are enabled (disabling may limit fault detection). */
    uint16_t ns_forward_timeout;            /**< Define timeout when forwarding NS messages - if reached, our own address discovery process is restarted. */
} nd_parameters_s;

struct aro;
enum addrtype;

extern struct nd_parameters nd_params;
struct ipv6_nd_opt_earo;

void icmp_nd_routers_init(void);


bool nd_ns_earo_handler(struct net_if *cur_interface, const uint8_t *earo_ptr, size_t earo_len,
                        const uint8_t *slla_ptr, const uint8_t src_addr[16], const uint8_t target[16],
                        struct ipv6_nd_opt_earo *na_earo);
void nd_remove_registration(struct net_if *cur_interface, enum addrtype ll_type, const uint8_t *ll_address);

#endif
