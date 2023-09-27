/*
 * Copyright (c) 2015-2021, Pelion and affiliates.
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
#ifndef FHSS_CONFIG_H
#define FHSS_CONFIG_H
#include <stdint.h>

/**
 * @brief WS channel functions.
 */
typedef enum {
    /** Fixed channel. */
    WS_FIXED_CHANNEL,
    /** TR51 channel function. */
    WS_TR51CF,
    /** Direct Hash channel function. */
    WS_DH1CF,
    /** Vendor Defined channel function. */
    WS_VENDOR_DEF_CF
} fhss_ws_channel_functions_e;

/**
 * \brief Struct fhss_ws_configuration defines configuration of WS FHSS.
 */
typedef struct fhss_ws_configuration {
    /** WS unicast channel function. */
    fhss_ws_channel_functions_e ws_uc_channel_function;

    /** WS broadcast channel function. */
    fhss_ws_channel_functions_e ws_bc_channel_function;

    /** Broadcast schedule identifier. */
    uint16_t bsi;

    /** Unicast dwell interval. Range: 15-250 milliseconds. */
    uint8_t fhss_uc_dwell_interval;

    /** Broadcast interval. Duration between broadcast dwell intervals. Range: 0-16777216 milliseconds. */
    uint32_t fhss_broadcast_interval;
    uint32_t lfn_bc_interval;

    /** Broadcast dwell interval. Range: 15-250 milliseconds. */
    uint8_t fhss_bc_dwell_interval;

    /** Unicast fixed channel */
    uint8_t unicast_fixed_channel;

    /** Broadcast fixed channel */
    uint8_t broadcast_fixed_channel;

    /** Domain channel mask, Wi-SUN uses it to exclure channels on US-IE and BS-IE. */
    uint8_t domain_channel_mask[32];

    /** Wi-SUN specific unicast channel mask */
    uint8_t unicast_channel_mask[32];

    /** Wi-SUN specific broadcast channel mask */
    uint8_t broadcast_channel_mask[32];

    /** Channel mask size */
    uint16_t channel_mask_size;

    /** Number of channel retries defines how many consecutive channels are used when retransmitting a frame after initial transmission channel. */
    uint8_t number_of_channel_retries;

} fhss_ws_configuration_t;

#endif
