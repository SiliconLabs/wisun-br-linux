/*
 * Copyright (c) 2020-2021, Pelion and affiliates.
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

#include <string.h>
#include <stdint.h>
#include "stack-services/ns_list.h"
#include "stack-services/ns_trace.h"
#include "service_libs/utils/ns_time.h"
#include "stack/ns_time_api.h"

#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "6lowpan/ws/ws_config.h"

#include "6lowpan/ws/ws_pae_time.h"

#define TRACE_GROUP "wst"

// Wednesday, January 1, 2020 0:00:00 GMT
#define CURRENT_TIME_INIT_VALUE        1577836800

#define SECONDS_IN_WEEK                (7 * 24 * 60 * 60)

static uint64_t ws_pae_current_time = CURRENT_TIME_INIT_VALUE;

uint64_t ws_pae_time_old_or_new_select(uint64_t old_time, uint64_t new_time)
{
    // If current time is more than one week in the past use the stored time
    if (old_time > SECONDS_IN_WEEK && new_time < old_time - SECONDS_IN_WEEK) {
        return old_time;
    }

    return new_time;
}

bool ws_pae_time_old_and_new_validate(uint64_t old_time, uint64_t new_time)
{
    /* If new time is more than one week in the past or more than a month in the
       future the old time is not valid */
    if ((old_time > SECONDS_IN_WEEK && new_time < old_time - SECONDS_IN_WEEK) ||
            new_time > (old_time + SYSTEM_TIME_MAXIMUM_DIFF)) {
        return false;
    }

    return true;
}

uint64_t ws_pae_current_time_get(void)
{
    if (!ns_time_system_time_acquired_get()) {
        return ws_pae_current_time;
    }

    uint64_t new_time;
    if (ns_time_system_time_read(&new_time) == 0) {
        new_time = ws_pae_time_old_or_new_select(ws_pae_current_time, new_time);
        return new_time;
    }

    return ws_pae_current_time;
}

void ws_pae_current_time_update(uint16_t seconds)
{
    ws_pae_current_time += seconds;
}

int8_t ws_pae_stored_time_check_and_set(uint64_t stored_time)
{
    uint64_t new_system_time;

    tr_debug("Stored time check and set: %"PRIi64, stored_time);

    if (!ns_time_system_time_acquired_get()) {
        ws_pae_current_time = stored_time;
        return stored_time;
    }

    if (ns_time_system_time_read(&new_system_time) == 0) {
        // Use either stored time or current time as reference when calculating lifetimes
        ws_pae_current_time = ws_pae_time_old_or_new_select(stored_time, new_system_time);
    }
    return 0;
}
