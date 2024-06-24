/*
 * Copyright (c) 2014-2019, Pelion and affiliates.
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
#include <stdint.h>

#include "common/rand.h"
#include "common/log.h"

#include "trickle_legacy.h"

/* RFC 6206 Rule 2 */
void trickle_begin_interval(trickle_legacy_t *t, const trickle_legacy_params_t *params)
{
    t->c = 0;
    if (t->I > 2) { //Take random only when t->I is bigger than 2 otherwise result will be 1
        t->t = rand_get_random_in_range(t->I / 2, t->I - 1);
    } else {
        t->t = 1;
    }
    t->now = 0;
    TRACE(TR_TRICKLE, "tkl %-8s reset: t=%ds I[%d,%d]=%ds k=%d",
          t->debug_name, t->t, params->Imin, params->Imax, t->I, params->k);
}

/* RFC 6206 Rule 1 */
void trickle_legacy_start(trickle_legacy_t *t, const char *debug_name, const trickle_legacy_params_t *params)
{
    t->debug_name = debug_name;
    t->e = 0;
    t->I = rand_get_random_in_range(params->Imin, params->Imax);
    trickle_begin_interval(t, params);
}

/* We don't expose the raw reset as API; users should use "inconsistent_heard".
 * This avoids repeated resets stopping transmission by restarting the interval.
 */
static void trickle_reset_timer(trickle_legacy_t *t, const trickle_legacy_params_t *params)
{
    t->e = 0;
    t->I = params->Imin;
    trickle_begin_interval(t, params);
}

/* RFC 6206 Rule 3 */
void trickle_legacy_consistent(trickle_legacy_t *t)
{
    if (t->c < UINT8_MAX) {
        t->c++;
    }
}

/* RFC 6206 Rule 6 */
void trickle_legacy_inconsistent(trickle_legacy_t *t, const trickle_legacy_params_t *params)
{
    if (t->I != params->Imin || !trickle_legacy_running(t, params)) {
        trickle_reset_timer(t, params);
    }
}

bool trickle_legacy_running(const trickle_legacy_t *t, const trickle_legacy_params_t *params)
{
    return t->e < params->TimerExpirations;
}


/* Returns true if you should transmit now */
bool trickle_legacy_tick(trickle_legacy_t *t, const trickle_legacy_params_t *params, uint16_t ticks)
{
    const char *status;
    if (!trickle_legacy_running(t, params)) {
        return false;
    }

    bool transmit = false;
    trickle_legacy_time_t new_time = t->now + ticks;

    /* Catch overflow */
    if (new_time < t->now) {
        new_time = TRICKLE_TIME_MAX;
    }

    /* RFC 6206 Rule 4 */
    if (t->now < t->t && new_time >= t->t) {
        /* Treat k == 0 as "infinity", as per RFC 6206 6.5 */
        if (t->c < params->k || params->k == 0) {
            transmit = true;
            status = "fire ";
        } else {
            status = "inhib";
        }
        TRACE(TR_TRICKLE, "tkl %-8s %s: t=%ds I[%d,%d]=%ds k=%d c=%d",
              t->debug_name, status, t->t, params->Imin, params->Imax, t->I, params->k, t->c);
    }

    /* RFC 6206 Rule 5 */
    t->now = new_time;
    if (new_time >= t->I) {
        if (t->I <= TRICKLE_TIME_MAX / 2) {
            t->I *= 2;
        } else {
            t->I = TRICKLE_TIME_MAX;
        }

        if (t->I > params->Imax) {
            t->I = params->Imax;
        }

        if (t->e < TRICKLE_EXPIRATIONS_INFINITE - 1) {
            t->e++;
        }
        trickle_begin_interval(t, params);
    }

    return transmit;
}

/* Stop the timer (by setting e to infinite) */
void trickle_legacy_stop(trickle_legacy_t *t)
{
    t->e = TRICKLE_EXPIRATIONS_INFINITE;
}
