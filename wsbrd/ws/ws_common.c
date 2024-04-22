/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/parsers.h"
#include "common/rand.h"
#include "common/ws_regdb.h"
#include "common/log.h"
#include "common/endian.h"
#include "common/ns_list.h"
#include "common/specs/icmpv6.h"
#include "common/mathutils.h"
#include "common/specs/ws.h"
#include "common/events_scheduler.h"
#include "common/ws_ie.h"

#include "6lowpan/mac/mpx_api.h"
#include "ws/ws_config.h"
#include "ws/ws_llc.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_bootstrap_6lbr.h"
#include "ws/ws_pae_controller.h"

#include "ws/ws_common.h"

int DEVICE_MIN_SENS = -93;

void ws_common_seconds_timer(int seconds)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    ws_bootstrap_seconds_timer(cur, seconds);
    ws_mngt_async_trickle_timer_cb(&cur->ws_info, seconds);
}

bool ws_common_is_valid_nr(uint8_t node_role)
{
    switch (node_role) {
    case WS_NR_ROLE_BR:
    case WS_NR_ROLE_ROUTER:
    case WS_NR_ROLE_LFN:
        return true;
    }
    return false;
}

// Wi-SUN FAN 1.1v07 - 3.1 Definitions
// Exponentially Weighted Moving Average (EWMA).
//
// Given a sequence of values X (t=0, 1, 2, 3, …), EWMA(t) is
// defined as S(X(t)) + (1-S)(EWMA(t-1)).
//
// … where …
//
// Smoothing Factor 0 < S < 1
// EWMA (0) = X(0).
float ws_common_rsl_calc(float rsl_dbm, int rx_power_dbm)
{
    if (isnan(rsl_dbm))
        return rx_power_dbm;
    else
        return (rx_power_dbm + 7 * rsl_dbm) / 8;
}
