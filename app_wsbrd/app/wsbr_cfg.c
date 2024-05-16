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

#include "ws/ws_config.h"

#include "app_wsbrd/mpl/mpl.h"

#include "wsbr_cfg.h"

const struct wsbr_cfg size_params[5] = {
    [WS_NETWORK_SIZE_CERTIFICATION] = {
        // Discovery
        .trickle_discovery.Imin = 15,
        .trickle_discovery.Imax = 60,
        .trickle_discovery.k = 1,
        .trickle_discovery.TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE,

        // MPL
        .trickle_mpl.Imin = 10,
        .trickle_mpl.Imax = 80,
        .trickle_mpl.k = 8,
        .trickle_mpl.TimerExpirations = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 80 * MPL_SAFE_HOP_COUNT * (2 + 1),

        // Security protocol
        .security_protocol_config.sec_prot_trickle_params.Imin = 60 * 10,
        .security_protocol_config.sec_prot_trickle_params.Imax = 120 * 10,
        .security_protocol_config.sec_prot_trickle_params.k = 0,
        .security_protocol_config.sec_prot_trickle_params.TimerExpirations = 4,
        .security_protocol_config.sec_prot_retry_timeout = 450 * 10,
    },
    [WS_NETWORK_SIZE_SMALL] = {
        // Discovery
        .trickle_discovery.Imin = 15,
        .trickle_discovery.Imax = 60,
        .trickle_discovery.k = 1,
        .trickle_discovery.TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE,

        // MPL
        .trickle_mpl.Imin = 1,
        .trickle_mpl.Imax = 10,
        .trickle_mpl.k = 8,
        .trickle_mpl.TimerExpirations = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 10 * MPL_SAFE_HOP_COUNT * (2 + 1),

        // Security protocol
        .security_protocol_config.sec_prot_trickle_params.Imin = 60 * 10,
        .security_protocol_config.sec_prot_trickle_params.Imax = 120 * 10,
        .security_protocol_config.sec_prot_trickle_params.k = 0,
        .security_protocol_config.sec_prot_trickle_params.TimerExpirations = 4,
        .security_protocol_config.sec_prot_retry_timeout = 450 * 10,
    },
    [WS_NETWORK_SIZE_MEDIUM] = {
        // Discovery
        .trickle_discovery.Imin = 60,
        .trickle_discovery.Imax = 960,
        .trickle_discovery.k = 1,
        .trickle_discovery.TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE,

        // MPL
        .trickle_mpl.Imin = 1,
        .trickle_mpl.Imax = 32,
        .trickle_mpl.k = 8,
        .trickle_mpl.TimerExpirations = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 32 * MPL_SAFE_HOP_COUNT * (2 + 1),

        // Security protocol
        .security_protocol_config.sec_prot_trickle_params.Imin = 60 * 10,
        .security_protocol_config.sec_prot_trickle_params.Imax = 120 * 10,
        .security_protocol_config.sec_prot_trickle_params.k = 0,
        .security_protocol_config.sec_prot_trickle_params.TimerExpirations = 4,
        .security_protocol_config.sec_prot_retry_timeout = 450 * 10,
    },
    [WS_NETWORK_SIZE_LARGE] = {
        // Discovery
        .trickle_discovery.Imin = 120,
        .trickle_discovery.Imax = 1536,
        .trickle_discovery.k = 1,
        .trickle_discovery.TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE,

        // MPL
        .trickle_mpl.Imin = 5,
        .trickle_mpl.Imax = 40,
        .trickle_mpl.k = 8,
        .trickle_mpl.TimerExpirations = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 40 * MPL_SAFE_HOP_COUNT * (2 + 1),

        // Security protocol
        .security_protocol_config.sec_prot_trickle_params.Imin = 60 * 10,
        .security_protocol_config.sec_prot_trickle_params.Imax = 240 * 10,
        .security_protocol_config.sec_prot_trickle_params.k = 0,
        .security_protocol_config.sec_prot_trickle_params.TimerExpirations = 4,
        .security_protocol_config.sec_prot_retry_timeout = 750 * 10,
    },
    [WS_NETWORK_SIZE_XLARGE] = {
        // Discovery
        .trickle_discovery.Imin = 240,
        .trickle_discovery.Imax = 1920,
        .trickle_discovery.k = 1,
        .trickle_discovery.TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE,

        // MPL
        .trickle_mpl.Imin = 10,
        .trickle_mpl.Imax = 80,
        .trickle_mpl.k = 8,
        .trickle_mpl.TimerExpirations = 2,
        // Imax * MPL_SAFE_HOP_COUNT * (TimerExpirations + 1)
        .mpl_seed_set_entry_lifetime = 80 * MPL_SAFE_HOP_COUNT * (2 + 1),

        // Security protocol
        .security_protocol_config.sec_prot_trickle_params.Imin = 60 * 10,
        .security_protocol_config.sec_prot_trickle_params.Imax = 240 * 10,
        .security_protocol_config.sec_prot_trickle_params.k = 0,
        .security_protocol_config.sec_prot_trickle_params.TimerExpirations = 4,
        .security_protocol_config.sec_prot_retry_timeout = 750 * 10,
    },
};
