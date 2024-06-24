/*
 * Copyright (c) 2014-2017, 2019, Pelion and affiliates.
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
#ifndef TRICKLE_H_
#define TRICKLE_H_
#include <stdint.h>
#include <stdbool.h>

/*
 * Implement a generic RFC 6206 Trickle Algorithm
 */

/* Trickle time is in arbitrary ticks - users can choose appropriate size
 * per algorithm implementation.
 */
typedef uint16_t trickle_legacy_time_t;

#define TRICKLE_TIME_MAX    UINT16_MAX

#define TRICKLE_EXPIRATIONS_INFINITE UINT8_MAX

/* We consider that all the time values are in seconds but the algorithm work
 * with any unit as soon as the caller is consistent
 */

/* Public structure - fill in with your Trickle algorithm parameters */
typedef struct trickle_legacy_params {
    trickle_legacy_time_t Imin;    /* minimum interval */
    trickle_legacy_time_t Imax;    /* maximum interval */
    uint8_t k;              /* redundancy constant (0 = infinity) */
    uint8_t TimerExpirations; /* MPL: expirations before terminating (0 = don't run, 0xFF = infinity) */
} trickle_legacy_params_t;

/* This structure is read-only for users. Initialised by trickle_legacy_start() */
typedef struct trickle_legacy {
    const char *debug_name;
    uint8_t c;              /* counter */
    uint8_t e;              /* MPL: expiration events since the Trickle timer was last reset */
    trickle_legacy_time_t I;       /* current interval */
    trickle_legacy_time_t t;       /* potential transmission time */
    trickle_legacy_time_t now;     /* time counter */
} trickle_legacy_t;

/* Initialize */
void trickle_legacy_start(trickle_legacy_t *t, const char *debug_name, const trickle_legacy_params_t *params);

/* Stop the timer (by setting e to infinite) */
void trickle_legacy_stop(trickle_legacy_t *t);

/* Indicate whether the timer is running (e < TimerExpirations) */
bool trickle_legacy_running(const trickle_legacy_t *t, const trickle_legacy_params_t *params);

/* Call when you have a received an up-to-date information */
void trickle_legacy_consistent(trickle_legacy_t *t);

/* Call when you have a received an out-of-date information */
void trickle_legacy_inconsistent(trickle_legacy_t *t, const trickle_legacy_params_t *params);

/* Call regulary with the number of tick since trickle_legacy_start(). If return true,
 * you should transmit information now
 */
bool trickle_legacy_tick(trickle_legacy_t *t, const trickle_legacy_params_t *params, uint16_t ticks);

#endif
