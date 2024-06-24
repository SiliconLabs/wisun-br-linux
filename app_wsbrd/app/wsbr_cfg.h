/*
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

#ifndef WSBR_CFG_H
#define WSBR_CFG_H

#include <stdint.h>

#include "security/protocols/sec_prot_cfg.h"
#include "common/trickle_legacy.h"

enum ws_network_size {
    WS_NETWORK_SIZE_SMALL,
    WS_NETWORK_SIZE_MEDIUM,
    WS_NETWORK_SIZE_LARGE,
    WS_NETWORK_SIZE_XLARGE,
    WS_NETWORK_SIZE_CERTIFICATION,
};

struct wsbr_cfg {
    struct trickle_legacy_params trickle_discovery;

    // MPL paramters
    struct trickle_legacy_params trickle_mpl;
    uint16_t mpl_seed_set_entry_lifetime;

    struct sec_prot_cfg security_protocol_config;
};

extern const struct wsbr_cfg size_params[5];

#endif
