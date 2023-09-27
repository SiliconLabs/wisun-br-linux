/*
 * Copyright (c) 2018, 2020-2021, Pelion and affiliates.
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
#ifndef FHSS_WS_EXT_H
#define FHSS_WS_EXT_H
#include <stdint.h>
#include <stdbool.h>
#include "common/int24.h"

/**
 * @brief ws_channel_mask_t WS neighbour supported channel mask
 */
struct ws_channel_mask {
    uint16_t channel_count;                     /**<active channels at mask */
    uint8_t channel_mask[32];                   /**< Supported channels */
};

/**
 * @brief fhss_ws_neighbor_timing_info Neighbor timing/hopping schedule information structure.
 */
struct fhss_ws_neighbor_timing_info {
    uint8_t clock_drift;                        /**< Neighbor clock drift */
    uint8_t timing_accuracy;                    /**< Neighbor timing accuracy */
    union {
        struct {
            uint8_t  uc_dwell_interval_ms;  // from US-IE
            uint24_t ufsi;                  // from UTT-IE
            uint32_t utt_rx_tstamp_us;

            uint32_t bc_interval_ms;        // from BS-IE
            uint16_t bsi;                   // from BS-IE
            uint8_t  bc_dwell_interval_ms;  // from BS-IE
            uint16_t bc_slot;               // from BT-IE
            uint24_t bc_interval_offset_ms; // from BT-IE
            uint32_t bt_rx_tstamp_us;
        } ffn;
        struct {
            uint24_t uc_listen_interval_ms; // from LUS-IE
            uint16_t uc_slot_number;        // from LUTT-IE
            uint24_t uc_interval_offset_ms; // from LUTT-IE
            uint32_t lutt_rx_tstamp_us;

            uint24_t lpa_response_delay_ms; // from LND-IE
            uint8_t  lpa_slot_duration_ms;  // from LND-IE
            uint8_t  lpa_slot_count;        // from LND-IE
            uint16_t lpa_slot_first;        // from LND-IE
            uint32_t lnd_rx_tstamp_us;
        } lfn;
    };
    uint8_t  uc_chan_func;  // from US-IE or LUS-IE/LCP-IE
    uint16_t uc_chan_count; // from US-IE or LUS-IE/LCP-IE
    uint16_t uc_chan_fixed; // from US-IE or LUS-IE/LCP-IE
    uint8_t  bc_chan_func;  // from BS-IE
    uint16_t bc_chan_fixed; // from BS-IE
    struct ws_channel_mask uc_channel_list;          /**< Neighbor unicast channel list */
    struct ws_channel_mask bc_channel_list;          /**< Neighbor broadcast channel list */
};

#endif // FHSS_WS_EXT_H
