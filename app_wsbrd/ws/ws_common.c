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

#include <stdbool.h>
#include <stdint.h>
#include <math.h>

#include "common/specs/ws.h"

#include "ws_common.h"

int DEVICE_MIN_SENS = -93;

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
