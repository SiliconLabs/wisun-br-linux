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

/* WS excluded channel Control */
#define WS_EXC_CHAN_CTRL_NONE 0             /**< No excluded channels */
#define WS_EXC_CHAN_CTRL_RANGE 1            /**< Excluded channels are in 1 or multiple channel range */
#define WS_EXC_CHAN_CTRL_BITMASK 2          /**< Excluded channels are marked to bitmask which length based on configured channels */

#define WS_EXCLUDED_MAX_RANGE_TO_SEND 3

#define WS_CHAN_PLAN_TAG_CURRENT 255

struct ws_jm { // Join metrics
    unsigned int mask;
    uint8_t version;
    uint8_t plf; // PAN Load Factor
};

/**
 * @brief ws_pan_information_t PAN information
 */
typedef struct ws_pan_information {
    uint16_t pan_id;
    uint16_t pan_size;          /**< Number devices connected to Border Router. */
    struct ws_jm jm;
    uint16_t routing_cost;      /**< ETX to border Router. */
    uint16_t pan_version;       /**< Pan configuration version will be updatd by Border router at PAN. */
    uint16_t lfn_version;      /**< LFN Pan configuration version will be updatd by Border router at PAN. */
    bool pan_version_set: 1;    /**< 1 PAN version is set. */
    bool lfn_version_set: 1;   /**< 1 LFN PAN version is set. */
    bool lfn_window_style: 1;   /**< 1 FFN management trasmission. */
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
    uint16_t excluded_channel_count;
    uint8_t channel_mask_bytes_inline;
    uint8_t channel_mask[32];
} ws_excluded_channel_data_t;

/**
 * @brief ws_hopping_schedule_t Chanel hopping schedule information
 */
typedef struct ws_hopping_schedule {
    uint8_t fhss_uc_dwell_interval;
    uint8_t fhss_bc_dwell_interval;
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
    uint8_t uc_channel_function;        /**< 0: Fixed channel, 1:TR51CF, 2: Direct Hash, 3: Vendor defined */
    uint8_t bc_channel_function;        /**< 0: Fixed channel, 1:TR51CF, 2: Direct Hash, 3: Vendor defined */
    uint32_t channel_spacing;
    uint8_t number_of_channels;         /**< derived from regulatory domain */
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    uint16_t uc_fixed_channel;
    uint16_t bc_fixed_channel;
    uint16_t fhss_bsi;
    uint32_t fhss_broadcast_interval;
    uint24_t ch0_freq; // Default should be derived from regulatory domain
    ws_excluded_channel_data_t uc_excluded_channels;
    ws_excluded_channel_data_t bc_excluded_channels;
} ws_hopping_schedule_t;

/**
 * @brief ws_utt_ie_t WS UTT-IE
 */
typedef struct ws_utt_ie {
    uint8_t message_type;
    uint24_t ufsi; // Filled by MAC
} ws_utt_ie_t;

/**
 * @brief ws_utt_ie_t WS LUTT-IE
 */
typedef struct ws_lutt_ie {
    uint8_t  message_type;
    uint16_t slot_number; // Filled by MAC
    uint24_t interval_offset; // Filled by MAC
} ws_lutt_ie_t;

/**
 * @brief ws_lbt_ie_t WS LBT-IE
 */
typedef struct ws_lbt_ie {
    uint16_t slot_number; // Filled by MAC
    uint24_t interval_offset; // Filled by MAC
} ws_lbt_ie_t;

/**
 * @brief ws_nr_ie_t WS NR-IE
 */
typedef struct ws_nr_ie {
    uint8_t node_role: 3;
    uint8_t reserved: 5;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    uint24_t listen_interval_min;
    uint24_t listen_interval_max;
} ws_nr_ie_t;

/**
 * @brief ws_lus_ie_t WS LUS-IE
 */
typedef struct ws_lus_ie {
    uint24_t listen_interval;
    uint8_t channel_plan_tag;
} ws_lus_ie_t;

/**
 * @brief ws_lus_ie_t WS FLUS-IE
 */
typedef struct ws_flus_ie {
    uint8_t dwell_interval;
    uint8_t channel_plan_tag;
} ws_flus_ie_t;

/**
 * @brief ws_lnd_ie_t WS LND-IE
 */
typedef struct ws_lnd_ie {
    uint8_t response_threshold;
    uint24_t response_delay; // Filled by MAC
    uint8_t discovery_slot_time;
    uint8_t discovery_slots;
    uint16_t discovery_first_slot; // Filled by MAC
} ws_lnd_ie_t;

/**
 * @brief ws_lto_ie_t WS LTO-IE
 */
typedef struct ws_lto_ie {
    uint24_t offset;
    uint24_t adjusted_listening_interval;
} ws_lto_ie_t;

/**
 * @brief ws_lbs_ie_t WS LBS-IE
 */
typedef struct ws_lbs_ie {
    uint24_t broadcast_interval;
    uint16_t broadcast_scheduler_id;
    uint8_t channel_plan_tag;
    uint8_t broadcast_sync_period;
} ws_lbs_ie_t;


/**
 * @brief ws_panid_ie_t WS PANID-IE
 */
typedef struct ws_panid_ie {
    uint16_t        panid;
} ws_panid_ie_t;

/**
 * @brief ws_lbc_ie_t WS LBC-IE read
 */
typedef struct ws_lbc_ie {
    uint24_t lfn_broadcast_interval;
    uint8_t broadcast_sync_period;
} ws_lbc_ie_t;

/**
 * @brief ws_pom_ie_t PHY Operating Modes
 */
typedef struct ws_pom_ie {
    uint8_t phy_op_mode_number: 4; /**< Number of PHY Operating Modes */
    uint8_t mdr_command_capable: 1;/**< Indicate if the transmitter supports MDR Command */
    uint8_t reserved: 3;           /**< Reserved, set to 0. */
    uint8_t phy_op_mode_id[15];
} ws_pom_ie_t;

/**
 * @brief ws_bt_ie_t WS BT-IE read
 */
typedef struct ws_bt_ie {
    uint16_t broadcast_slot_number;
    uint24_t broadcast_interval_offset;
} ws_bt_ie_t;

/**
 * @brief ws_fc_ie_t WS FC-IE element
 */
typedef struct ws_fc_ie {
    uint8_t tx_flow_ctrl;
    uint8_t rx_flow_ctrl;
} ws_fc_ie_t;

/**
 * @brief ws_lfnver_ie_t WS LFNVER-IE element
 */
typedef struct ws_lfnver_ie {
    uint16_t lfn_version;
} ws_lfnver_ie_t;

/**
 * @brief ws_lgtkhash_ie_t WS LGTKHASH-IE element
 */
typedef struct ws_lgtkhash_ie {
    unsigned active_lgtk_index: 2; /**< Indicate Active LGTK index 0-2 */
    uint8_t valid_hashs;           /**< Valid entries */
    uint8_t gtkhashs[8][4];        /**< A generic struct to handle GTKs */
} ws_lgtkhash_ie_t;

typedef struct ws_lbats_ie {
    uint8_t additional_transmissions;
    uint16_t next_transmit_delay;
} ws_lbats_ie_t;

/**
 * @brief ws_channel_plan_zero_t WS channel plan 0 define domain and class
 */
typedef struct ws_channel_plan_zero {
    uint8_t regulatory_domain;
    uint8_t operating_class;
} ws_channel_plan_zero_t;

/**
 * @brief ws_channel_plan_one_t WS channel plan 1 define ch0, channel spacing and channel count
 */
typedef struct ws_channel_plan_one {
    uint24_t ch0; // kHz
    unsigned channel_spacing: 4;
    uint16_t number_of_channel;
} ws_channel_plan_one_t;

/**
 * @brief ws_channel_plan_two_t WS channel plan 2 define regulator domain and chanel plan 1
 */
typedef struct ws_channel_plan_two {
    uint8_t regulatory_domain;
    uint8_t channel_plan_id;
} ws_channel_plan_two_t;

/**
 * @brief ws_channel_function_zero_t WS function 0 fixed channel
 */
typedef struct ws_channel_function_zero {
    uint16_t fixed_channel;
} ws_channel_function_zero_t;

/**
 * @brief ws_channel_function_three_t WS function 3 vendor specific channel hop
 */
typedef struct ws_channel_function_three {
    uint8_t channel_hop_count;
    const uint8_t *channel_list;
} ws_channel_function_three_t;

/**
 * @brief ws_excluded_channel_range_t WS excluded channel range
 */
typedef struct ws_excluded_channel_range {
    uint8_t number_of_range;
    const uint8_t *range_start;
} ws_excluded_channel_range_t;

/**
 * @brief ws_excluded_channel_mask_t WS excluded channel mask
 */
typedef struct ws_excluded_channel_mask {
    const uint8_t *channel_mask;
    uint8_t mask_len_inline;
} ws_excluded_channel_mask_t;

/**
 * @brief ws_generic_channel_info_t Generic Channel Info
 */
typedef struct ws_generic_channel_info {
    unsigned channel_plan: 3;
    unsigned channel_function: 3;
    unsigned excluded_channel_ctrl: 2;
    union ws_channel_plan {
        ws_channel_plan_zero_t zero;
        ws_channel_plan_one_t one;
        ws_channel_plan_two_t two;
    } plan;
    union ws_channel_function {
        ws_channel_function_zero_t zero;
        ws_channel_function_three_t three;
    } function;
    union ws_excluded_channel {
        ws_excluded_channel_range_t range;
        ws_excluded_channel_mask_t mask;
    } excluded_channels;
} ws_generic_channel_info_t;

/**
 * @brief ws_lcp_ie_t LFN Channel information
 */
typedef struct ws_lcp_ie {
    uint8_t lfn_channel_plan_tag;
    struct ws_generic_channel_info chan_plan;
} ws_lcp_ie_t;

/**
 * @brief ws_us_ie_t WS US-IE read
 */
typedef struct ws_us_ie {
    uint8_t dwell_interval;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    struct ws_generic_channel_info chan_plan;
} ws_us_ie_t;

/**
 * @brief ws_bs_ie_t WS BS-IE read
 */
typedef struct ws_bs_ie {
    uint32_t broadcast_interval;
    uint16_t broadcast_schedule_identifier;
    uint8_t dwell_interval;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    struct ws_generic_channel_info chan_plan;
} ws_bs_ie_t;

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

#define WS_RPL_PARENT_CANDIDATE_MAX 5
#define WS_RPL_SELECTED_PARENT_MAX 2

#define WS_CERTIFICATE_RPL_PARENT_CANDIDATE_MAX 8
#define WS_CERTIFICATE_RPL_SELECTED_PARENT_MAX 4

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


/* Default FHSS timing information
 *
 */
#define WS_FHSS_UC_DWELL_INTERVAL     255
#define WS_FHSS_BC_INTERVAL           1020
#define WS_FHSS_BC_DWELL_INTERVAL     255

/*
 * EAPOL relay and PAE authenticator socket settings
 */
#define EAPOL_RELAY_SOCKET_PORT               10253
#define BR_EAPOL_RELAY_SOCKET_PORT            10255
#define PAE_AUTH_SOCKET_PORT                  10254

/*
 * EAPOL and multicast neighbor tables size
 */
#define MAX_NEIGH_TEMPORARY_EAPOL_SIZE 5

#endif
