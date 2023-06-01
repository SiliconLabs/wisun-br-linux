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
 * \file fhss_ws_extension.h
 * \brief
 */

typedef struct fhss_api fhss_api_t;


/**
 * @brief ws_channel_mask_t WS neighbour supported channel mask
 */
typedef struct ws_channel_mask {
    uint16_t channel_count;                     /**<active channels at mask */
    uint8_t channel_mask[32];                   /**< Supported channels */
} ws_channel_mask_t;

/**
 * @brief fhss_ws_neighbor_timing_info Neighbor timing/hopping schedule information structure.
 */
typedef struct fhss_ws_neighbor_timing_info {
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
    ws_channel_mask_t uc_channel_list;          /**< Neighbor unicast channel list */
    ws_channel_mask_t bc_channel_list;          /**< Neighbor broadcast channel list */
} fhss_ws_neighbor_timing_info_t;

/**
 * @brief Get neighbor timing/hopping schedule.
 * @param api FHSS instance.
 * @param eui64 EUI-64 address of node for which the info is requested.
 * @return Neighbor timing/hopping schedule.
 */
typedef fhss_ws_neighbor_timing_info_t *fhss_get_neighbor_info(const fhss_api_t *api, uint8_t eui64[8]);

/**
 * @brief Set parent which broadcast channels must be listened by FHSS.
 * @param fhss_api FHSS instance.
 * @param eui64 EUI-64 address of parent.
 * @param bc_timing_info Pointer to parent broadcast timing/hopping schedule info.
 * @param force_synch If false, synchronization is done only if minimum (internal) synchronization interval is exceed.
 * @return 0 on success, -1 on fail.
 */
int ns_fhss_ws_set_parent(const fhss_api_t *fhss_api, const uint8_t eui64[8], const struct fhss_ws_neighbor_timing_info *timing, const bool force_synch);

/**
 * @brief Remove parent which was set by ns_fhss_ws_set_parent function.
 * @param fhss_api FHSS instance.
 * @param eui64 EUI-64 address of parent.
 * @return 0 on success, -1 on fail.
 */
int ns_fhss_ws_remove_parent(const fhss_api_t *fhss_api, const uint8_t eui64[8]);

/* @brief Update the MAC layer with the new timing information about a neighbor.
 *     This function is not called by the original nanostack. It is used to push
 *     relevant information to the host in the case of a splited stack.
 * @param eui64 MAC adress of the remote host
 * @param fhss_data Pointer to timing information
 */
void ns_fhss_ws_update_neighbor(const uint8_t eui64[8], fhss_ws_neighbor_timing_info_t *fhss_data);


/**
 * @brief Inform the MAC layer it can drop a neighbor from its list. This
 *     function is not called by the original nanostack. It is used to push
 *     relevant information to the host in the case of a splited stack.
 * @param eui64 MAC adress of the remote host
 */
void ns_fhss_ws_drop_neighbor(const uint8_t eui64[8]);

/**
 * @brief Set neighbor timing/hopping schedule request function.
 * @param fhss_api FHSS instance.
 * @param get_neighbor_info Neighbor info function pointer.
 * @return 0 on success, -1 on fail.
 */
int ns_fhss_set_neighbor_info_fp(const fhss_api_t *fhss_api, fhss_get_neighbor_info *get_neighbor_info);

/**
 * @brief Set node hop count. Hop count is used to specify TX/RX slot. When hop count is set to 0xFF, TX/RX slots are ignored.
 * @param fhss_api FHSS instance.
 * @param hop_count Hop count to be set.
 * @return 0 on success, -1 on fail.
 */
int ns_fhss_ws_set_hop_count(const fhss_api_t *fhss_api, const uint8_t hop_count);

/**
 * @brief WS TX allowance levels.
 */
typedef enum {
    /** Allow transmitting only on TX slots. */
    WS_TX_SLOT,
    /** Allow transmitting only on TX and RX slots. */
    WS_TX_AND_RX_SLOT,
} fhss_ws_tx_allow_level_e;

/**
 * @brief Set node unicast TX allowance level. Allows device to use the unicast and broadcast channel for unicast transmission as described by fhss_ws_tx_allow_level_e.
 * @param fhss_api FHSS instance.
 * @param global_level Level of TX allowance in normal mode.
 * @param ef_level Level of TX allowance in expedited forwarding mode.
 * @return 0 on success, -1 on fail.
 */
int ns_fhss_ws_set_tx_allowance_level(const fhss_api_t *fhss_api, const fhss_ws_tx_allow_level_e global_level, const fhss_ws_tx_allow_level_e ef_level);

#endif // FHSS_WS_EXT_H
