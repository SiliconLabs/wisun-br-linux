/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#ifndef CHANNEL_LIST_H_
#define CHANNEL_LIST_H_
#include <stdint.h>
#include "nanostack/mac/platform/arm_hal_phy.h"

/** Channel list */
typedef struct channel_list_s {
    channel_page_e channel_page;    /**< Channel page */
    uint32_t channel_mask[8];       /**< Channel mask. Each bit defining one channel */
    uint16_t next_channel_number;   /**< Next channel to use in the list */
} channel_list_s;

#endif

