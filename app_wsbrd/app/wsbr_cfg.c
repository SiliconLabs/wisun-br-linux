/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2024 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#include "wsbr_cfg.h"

#define MPL_SAFE_HOP_COUNT 6

const struct wsbr_cfg size_params[6] = {
    [WS_NETWORK_SIZE_CERTIFICATION] = {
        // Discovery
        .trickle_discovery.Imin_ms = 15 * 1000,
        .trickle_discovery.Imax_ms = 60 * 1000,
        .trickle_discovery.k = 3,

        // Wi-SUN FAN 1.1v08 6.2.1.1 Configuration Parameters
        .trickle_mpl.Imin_ms =  6 * 1000,      // Arbitrary (Wi-SUN 10s default is too long)
        .trickle_mpl.Imax_ms = 48 * 1000, // 48s instead of 80s with modified Imin
        // RFC 7731 5.4. MPL Parameters
        .trickle_mpl.k = 3,         // Arbitrary (RFC 7731 k=1 default is too small)
        .trickle_mpl_e_max = 3,
        .mpl_seed_set_entry_lifetime = 30 * 60,
    },
    [WS_NETWORK_SIZE_SMALL] = {
        // Discovery
        .trickle_discovery.Imin_ms = 15 * 1000,
        .trickle_discovery.Imax_ms = 60 * 1000,
        .trickle_discovery.k = 1,

        // MPL
        .trickle_mpl.Imin_ms = 1 * 1000,
        .trickle_mpl.Imax_ms = 10 * 1000,
        .trickle_mpl.k = 8,
        .trickle_mpl_e_max = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 10 * MPL_SAFE_HOP_COUNT * (2 + 1),
    },
    [WS_NETWORK_SIZE_MEDIUM] = {
        // Discovery
        .trickle_discovery.Imin_ms = 60 * 1000,
        .trickle_discovery.Imax_ms = 960 * 1000,
        .trickle_discovery.k = 1,

        // MPL
        .trickle_mpl.Imin_ms = 1 * 1000,
        .trickle_mpl.Imax_ms = 32 * 1000,
        .trickle_mpl.k = 8,
        .trickle_mpl_e_max = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 32 * MPL_SAFE_HOP_COUNT * (2 + 1),
    },
    [WS_NETWORK_SIZE_LARGE] = {
        // Discovery
        .trickle_discovery.Imin_ms = 120 * 1000,
        .trickle_discovery.Imax_ms = 1536 * 1000,
        .trickle_discovery.k = 1,

        // MPL
        .trickle_mpl.Imin_ms = 5 * 1000,
        .trickle_mpl.Imax_ms = 40 * 1000,
        .trickle_mpl.k = 8,
        .trickle_mpl_e_max = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 40 * MPL_SAFE_HOP_COUNT * (2 + 1),
    },
    [WS_NETWORK_SIZE_XLARGE] = {
        // Discovery
        .trickle_discovery.Imin_ms = 240 * 1000,
        .trickle_discovery.Imax_ms = 1920 * 1000,
        .trickle_discovery.k = 1,

        // MPL
        .trickle_mpl.Imin_ms = 10 * 1000,
        .trickle_mpl.Imax_ms = 80 * 1000,
        .trickle_mpl.k = 8,
        .trickle_mpl_e_max = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 80 * MPL_SAFE_HOP_COUNT * (2 + 1),
    },
    [WS_NETWORK_SIZE_AUTO] = {
        // Discovery (same as SMALL base)
        .trickle_discovery.Imin_ms = 15 * 1000,
        .trickle_discovery.Imax_ms = 60 * 1000,
        .trickle_discovery.k = 1,

        // MPL (same as SMALL)
        .trickle_mpl.Imin_ms = 1 * 1000,
        .trickle_mpl.Imax_ms = 10 * 1000,
        .trickle_mpl.k = 8,
        .trickle_mpl_e_max = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 10 * MPL_SAFE_HOP_COUNT * (2 + 1),
    },
};
