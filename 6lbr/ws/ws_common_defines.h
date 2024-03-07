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

/* WS excluded channel Control */
#define WS_EXC_CHAN_CTRL_NONE 0             /**< No excluded channels */
#define WS_EXC_CHAN_CTRL_RANGE 1            /**< Excluded channels are in 1 or multiple channel range */
#define WS_EXC_CHAN_CTRL_BITMASK 2          /**< Excluded channels are marked to bitmask which length based on configured channels */

#define WS_EXCLUDED_MAX_RANGE_TO_SEND 3

#define WS_CHAN_PLAN_TAG_CURRENT 255

/**
 * @brief ws_pan_information_t PAN information
 */
typedef struct ws_pan_information {
    int pan_id;
    int test_pan_size;
    uint16_t max_pan_size;
    struct ws_jm_ie jm;
    uint16_t routing_cost;      /**< ETX to border Router. */
    uint16_t pan_version;       /**< Pan configuration version will be updatd by Border router at PAN. */
    uint16_t lfn_version;      /**< LFN Pan configuration version will be updatd by Border router at PAN. */
    unsigned version: 3;        /**< Pan version support. */
} ws_pan_information_t;

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

/**
 * @brief ws_hopping_schedule_t Chanel hopping schedule information
 */
typedef struct ws_hopping_schedule {
    uint8_t regulatory_domain;          /**< PHY regulatory domain default to "KR" 0x09 */
    uint8_t operating_class;            /**< PHY operating class default to 1 */
    uint8_t operating_mode;             /**< PHY operating mode default to "1b" symbol rate 50, modulation index 1 */
    uint8_t phy_mode_id;                /**< PHY mode ID, default to 255 */
    uint8_t phy_op_modes[16];           /**< 15 possible phy_mode_id + 1 sentinel value */
    uint8_t ms_mode;
    uint8_t phy_mode_id_ms_tx;
    uint8_t phy_mode_id_ms_base;
    int rcp_rail_config_index;          /**< Index number in rcp.rail_config_list. Needed to configure the RCP */
    uint8_t channel_plan_id;            /**< Channel plan ID, default to 255 */
    uint8_t channel_plan;               /**< 0: use regulatory domain values 1: application defined plan */
    uint32_t channel_spacing;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    uint24_t ch0_freq; // Default should be derived from regulatory domain
    ws_excluded_channel_data_t uc_excluded_channels;
    ws_excluded_channel_data_t bc_excluded_channels;
} ws_hopping_schedule_t;

#define MPX_KEY_MANAGEMENT_ENC_USER_ID 0x0001   /**< MPX Key management user ID */
#define MPX_LOWPAN_ENC_USER_ID 0xA0ED           /**< MPX Lowpan User Id */

/*
 * Wi-SUN MPX MTU size
 *
 */

#define WS_MPX_MAX_MTU 1576

#define WS_NEIGHBOR_LINK_TIMEOUT 2200

#define WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME 600
#define WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_LARGE 520
#define WS_NEIGHBOR_TEMPORARY_LINK_MIN_TIMEOUT_SMALL 260

#define WS_EAPOL_TEMPORARY_ENTRY_SMALL_TIMEOUT 330
#define WS_EAPOL_TEMPORARY_ENTRY_MEDIUM_TIMEOUT WS_EAPOL_TEMPORARY_ENTRY_SMALL_TIMEOUT
#define WS_EAPOL_TEMPORARY_ENTRY_LARGE_TIMEOUT 750

/*
 * Threshold (referenced to DEVICE_MIN_SENS) above which a neighbor node may be considered for inclusion into candidate parent set
 */
#define CAND_PARENT_THRESHOLD 10
/*
 * Hysteresis factor to be applied to CAND_PARENT_THRESHOLD when admitting or dropping nodes from the candidate parent set.
 */
#define CAND_PARENT_HYSTERISIS 3

/* WS requires at least 19 MAC retransmissions (total 1+19=20 attempts). Default 802.15.4 macMaxFrameRetries is 3 (total 1+3=4 attempts).
 * At least 4 request restarts must be used: (Initial channel + WS_TX_REQUEST_RESTART_MAX) * MAC attempts = (1+4)*4=20 attempts
 *
 * Valid settings could be for example:
 * WS_MAX_FRAME_RETRIES     WS_TX_REQUEST_RESTART_MAX       Total attempts
 * 0                        19                              1+0*1+19=20
 * 1                        9                               1+1*1+9=20
 * 2                        6                               1+2*1+6=21
 * 3                        4                               1+3*1+4=20
 *
 */
// This configuration is used when bootstrap is ready
#define WS_MAX_FRAME_RETRIES            3

// Configuring data request restart allows MAC to push failed packet back to MAC TX queue up to WS_CCA_REQUEST_RESTART_MAX times for CCA failure and WS_TX_REQUEST_RESTART_MAX for TX failure.
// Packet cannot be taken back to transmission before it has finished the blacklist period.
#define WS_CCA_REQUEST_RESTART_MAX          4
#define WS_TX_REQUEST_RESTART_MAX           4
#define WS_REQUEST_RESTART_BLACKLIST_MIN    20
#define WS_REQUEST_RESTART_BLACKLIST_MAX    300

#if (1 + WS_MAX_FRAME_RETRIES) * (1 + WS_TX_REQUEST_RESTART_MAX) < 20
#warning "MAX frame retries set too low"
#endif

// Total CCA attempts: 1 + WS_MAX_CSMA_BACKOFFS
#define WS_MAX_CSMA_BACKOFFS    3

// Default 802.15.4 values
#define WS_MAC_MIN_BE   3
#define WS_MAC_MAX_BE   5

/*
 * Automatic CCA threshold: default threshold and range in dBm.
 */
#define CCA_DEFAULT_DBM -60
#define CCA_HIGH_LIMIT  -60
#define CCA_LOW_LIMIT   -100

/*
 * EAPOL relay and PAE authenticator socket settings
 */
#define EAPOL_RELAY_SOCKET_PORT               10253
#define BR_EAPOL_RELAY_SOCKET_PORT            10255
#define PAE_AUTH_SOCKET_PORT                  10254

#endif
