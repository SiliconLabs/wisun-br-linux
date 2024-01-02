/*
 * Copyright (c) 2016-2018, 2020, Pelion and affiliates.
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
#ifndef MAC_COMMON_DEFINES_H_
#define MAC_COMMON_DEFINES_H_

#include <stdint.h>

// FIXME: Merge with other 15.4 definitions


/**
 * @brief struct mlme_security MLME/MCPS security structure
 * This structure encapsulates security related variables,
 * which are always used together if SecurityLevel > 0.
 *
 * See IEEE standard 802.15.4-2006 (e.g end of table 41) for more details
 */
typedef struct mlme_security {
    unsigned SecurityLevel: 3;  /**< Security level */
    uint8_t KeyIndex;           /**< Key index */
} mlme_security_t;

#endif
