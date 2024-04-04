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

#ifndef WS_COMMON_DEFINES_H_
#define WS_COMMON_DEFINES_H_
#include <stdint.h>
#include <stdbool.h>
#include "common/int24.h"

#include "ws/ws_ie_lib.h"

#define WS_EXCLUDED_MAX_RANGE_TO_SEND 3

#define WS_CHAN_PLAN_TAG_CURRENT 255

/**
 * @brief ws_excluded_channel_range_data_t Excludd Chanel range information
 */
typedef struct ws_excluded_channel_range_data {
    uint16_t range_start;
    uint16_t range_end;
} ws_excluded_channel_range_data_t;

/**
 * @brief ws_excluded_channel_data_t Excludd Chanel information
 */
typedef struct ws_excluded_channel_data {
    unsigned excluded_channel_ctrl: 2;
    unsigned excluded_range_length: 3;
    ws_excluded_channel_range_data_t excluded_range[WS_EXCLUDED_MAX_RANGE_TO_SEND];
    uint8_t channel_mask_bytes_inline;
    uint8_t channel_mask[32];
} ws_excluded_channel_data_t;

#define WS_NEIGHBOR_LINK_TIMEOUT 2200

#define WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME 600

#endif
