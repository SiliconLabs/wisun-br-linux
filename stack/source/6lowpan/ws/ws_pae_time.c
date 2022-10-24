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

#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "6lowpan/ws/ws_config.h"

#include "6lowpan/ws/ws_pae_time.h"

#define TRACE_GROUP "wst"

// Wednesday, January 1, 2020 0:00:00 GMT
#define CURRENT_TIME_INIT_VALUE        1577836800

#define SECONDS_IN_WEEK                (7 * 24 * 60 * 60)

static uint64_t ws_pae_current_time = CURRENT_TIME_INIT_VALUE;

uint64_t ws_pae_current_time_get(void)
{
    uint64_t new_time;

    ns_time_system_time_read(&new_time);
    return new_time;
}

void ws_pae_current_time_update(uint16_t seconds)
{
    ws_pae_current_time += seconds;
}

int8_t ws_pae_stored_time_check_and_set(uint64_t stored_time)
{
    uint64_t new_system_time;

    ns_time_system_time_read(&new_system_time);
    ws_pae_current_time = new_system_time;
    return 0;
}
