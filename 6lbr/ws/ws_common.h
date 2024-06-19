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

#include "common/specs/ws.h"
#include "common/ns_list.h"

#include "ws/ws_config.h"
#include "ws/ws_neigh.h"
#include "ws/ws_mngt.h"
#include "ws/ws_common_defines.h"
#include "ws/ws_ie_custom.h"

#define NO_PENDING_PROCESS 0
#define PENDING_KEY_INDEX_ADVERTISMENT 1
#define PENDING_KEY_INDEX_ACTIVATE 2

typedef struct ws_pending_key_index {
    unsigned state: 2;
    uint8_t index;
} ws_pending_key_index_t;

struct ws_fhss_config {
    uint8_t  regulatory_domain;
    int      regional_regulation;
    uint8_t  op_class;
    uint8_t  chan_plan_id;
    uint8_t  chan_count;
    uint32_t chan_spacing;
    uint24_t chan0_freq;
    uint8_t  chan_plan;
    uint8_t  uc_chan_mask[32];
    uint8_t  bc_chan_mask[32];
    uint8_t  uc_dwell_interval;
    uint32_t bc_interval;
    uint8_t  bc_dwell_interval;
    uint32_t lfn_bc_interval;
    uint8_t  lfn_bc_sync_period;
    uint32_t async_frag_duration_ms;
    int      bsi;
};

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

struct ws_phy_config {
    uint8_t op_mode;
    uint8_t phy_mode_id;
    uint8_t phy_op_modes[16]; // 15 possible phy_mode_id + 1 sentinel value
    uint8_t ms_mode;
    uint8_t phy_mode_id_ms_tx;
    uint8_t phy_mode_id_ms_base;
    int     rcp_rail_config_index; // Index number in rcp.rail_config_list. Needed to configure the RCP.
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
    ws_pending_key_index_t pending_key_index_info;
    struct ws_pan_information pan_information;
    struct ws_phy_config phy_config;
    struct ws_neigh_table neighbor_storage;
    struct ws_fhss_config fhss_config;
    int tx_power_dbm;
    uint8_t edfe_src[8];
} ws_info_t;

int8_t ws_common_generate_channel_list(uint8_t chan_mask[32],
                                       uint16_t chan_count,
                                       uint8_t regional_regulation,
                                       uint8_t regulatory_domain,
                                       uint8_t op_class,
                                       uint8_t chan_plan_id);

void ws_common_calc_chan_excl(ws_excluded_channel_data_t *chan_excl, const uint8_t chan_mask_custom[],
                              const uint8_t chan_mask_reg[], uint16_t chan_count);

void ws_common_seconds_timer(int seconds);

uint8_t ws_common_allow_child_registration(struct net_if *cur, const uint8_t *eui64, uint16_t aro_timeout);

bool ws_common_negative_aro_mark(struct net_if *interface, const uint8_t *eui64);

uint32_t ws_common_version_timeout_get(uint8_t config);

uint32_t ws_common_latency_estimate_get(struct net_if *cur);

uint32_t ws_common_datarate_get_from_phy_mode(uint8_t phy_mode_id, uint8_t operating_mode);

uint32_t ws_common_datarate_get(struct net_if *cur);

bool ws_common_is_valid_nr(uint8_t node_role);

float ws_common_rsl_calc(float rsl_dbm, int rx_power_dbm);

int ws_common_get_fixed_channel(const uint8_t bitmask[32]);

#endif //WS_COMMON_H_
