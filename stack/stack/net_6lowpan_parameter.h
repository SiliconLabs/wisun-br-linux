/*
 * Copyright (c) 2014-2015, 2017, Pelion and affiliates.
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
#ifndef NET_6LOWPAN_PARAMETER_API_H_
#define NET_6LOWPAN_PARAMETER_API_H_

#include <stdint.h>
#include <stdbool.h>

/**
 * \file net_6lowpan_parameter.h
 * \brief API for setting up 6LoWPAN network parameters
 *
 * \section tim-para-def 6LoWPAN Default timer values
 * - Timer values are specified in ticks
 * - Default 6LoWPAN ND Bootstrap tick is 1 tick = 100ms
 *
 * - Default Random value 0x1f = [0..3.1] seconds.
 * - Default RS retry counter 3.
 * - Default RS retry interval is 15 + random --> [1.5..4.6] seconds.
 * - Default NS retry counter 5.
 * - Default NS retry interval is 100 + random + backoff --> [10.0..13.1+10.0*retry] seconds.
 * - Default NS retry linear backoff is 100.
 *
 * - Default RA transmit interval is 150, exponentially backed off --> 15.0, 30.0, 60.0 seconds.
 * - Default RA transmit counter is 5.
 *
 * - Default NS forward timeout is 300 --> 30.0 seconds.
 *
 *  \section Changing random and interval values
 *  - Random parameter + NS or RS minimum interval must sum to less than 0xFFFF.
 *  - Random maximums are manipulated as bit masks, so must be (2^n)-1.
 */

/*!
 * \struct nd_parameters
 * \brief 6LoWPAN Neighbor Discovery parameters
 */
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

/**
 * \brief Function to change 6LoWPAN ND bootstrap parameters.
 *
 * Note: This function should be called after net_init_core() and definitely
 * before creating any 6LoWPAN interface.
 *
 * For future compatibility, to support extensions to this structure, read
 * the current parameters using net_6lowpan_timer_parameter_read(),
 * modify known fields, then set.
 *
 * \param parameter_ptr Pointer for ND parameters.
 *
 * \return 0, Change OK.
 * \return -1, Invalid values.
 * \return -2, 6LoWPAN interface already active.
 *
 */
int8_t net_6lowpan_nd_parameter_set(const nd_parameters_s *parameter_ptr);

/**
 * \brief Function to read 6LoWPAN ND bootstrap parameters.
 *
 * \param parameter_ptr Output pointer for ND parameters.
 *
 */
void net_6lowpan_nd_parameter_read(nd_parameters_s *parameter_ptr);

#endif /* NET_6LOWPAN_DEFAULT_PARAMETER_API_H_ */
