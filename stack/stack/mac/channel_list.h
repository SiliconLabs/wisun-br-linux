/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#ifndef CHANNEL_LIST_H_
#define CHANNEL_LIST_H_
#include <stdint.h>

/** Channel page numbers */
typedef enum {
    CHANNEL_PAGE_0 = 0,     ///< Page 0
    CHANNEL_PAGE_1 = 1,     ///< Page 1
    CHANNEL_PAGE_2 = 2,     ///< Page 2
    CHANNEL_PAGE_3 = 3,     ///< Page 3
    CHANNEL_PAGE_4 = 4,     ///< Page 4
    CHANNEL_PAGE_5 = 5,     ///< Page 5
    CHANNEL_PAGE_6 = 6,     ///< Page 6
    CHANNEL_PAGE_9 = 9,     ///< Page 9
    CHANNEL_PAGE_10 = 10,   ///< Page 10
    CHANNEL_PAGE_UNDEFINED  ///< Undefined
} channel_page_e;

/** Channel list */
typedef struct channel_list {
    channel_page_e channel_page;    /**< Channel page */
    uint8_t channel_mask[32];       /**< Channel mask. Each bit defining one channel */
    uint16_t next_channel_number;   /**< Next channel to use in the list */
} channel_list_t;

#endif

