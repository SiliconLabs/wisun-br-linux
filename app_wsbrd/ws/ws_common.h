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

#ifndef WS_COMMON_H_
#define WS_COMMON_H_
#include <stdint.h>
#include <stdbool.h>

#include "common/ws/ws_neigh.h"
#include "common/ws/ws_types.h"

#include "ws/ws_mngt.h"
#include "ws/ws_ie_custom.h"

extern int DEVICE_MIN_SENS;

enum ws_edfe_mode {
    WS_EDFE_DEFAULT  = 0,
    WS_EDFE_DISABLED = 1,
    WS_EDFE_ENABLED  = 2,
    WS_EDFE_MAX      = 3,
};

enum ws_mode_switch_mode {
    WS_MODE_SWITCH_DEFAULT  = 0,
    WS_MODE_SWITCH_DISABLED = 1,
    WS_MODE_SWITCH_PHY      = 2,
    WS_MODE_SWITCH_MAC      = 3,
};

struct ws_pan_information {
    int pan_id;
    int test_pan_size;
    uint16_t max_pan_size;
    struct ws_jm_ie jm;
    uint16_t routing_cost;      /**< ETX to border Router. */
    uint16_t pan_version;       /**< Pan configuration version will be updatd by Border router at PAN. */
    uint16_t lfn_version;      /**< LFN Pan configuration version will be updatd by Border router at PAN. */
    bool lfn_version_set: 1;   /**< 1 LFN PAN version is set. */
    unsigned version: 3;        /**< Pan version support. */
};

typedef struct ws_info {
    char network_name[33];
    struct ws_mngt mngt;
    struct ws_ie_custom_list ie_custom_list;
    bool enable_lfn;
    bool enable_ffn10;
    enum ws_edfe_mode edfe_mode;
    unsigned int key_index_mask;  // Bitmask of installed key indices
    struct ws_pan_information pan_information;
    struct ws_phy_config phy_config;
    struct ws_neigh_table neighbor_storage;
    struct ws_fhss_config fhss_config;
    int tx_power_dbm;
    uint8_t ffn_gtk_index;
    uint8_t lfn_gtk_index;
    uint8_t edfe_src[8];
} ws_info_t;

bool ws_common_is_valid_nr(uint8_t node_role);

#endif //WS_COMMON_H_
