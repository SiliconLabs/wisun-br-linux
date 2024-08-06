/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WS_TYPES_H
#define WS_TYPES_H
#include <stdint.h>

#include "common/bits.h"
#include "common/int24.h"
#include "common/ws_chan_mask.h"
#include "common/ws_regdb.h"
#include "common/specs/ws.h"

struct ws_fhss_config {
    const struct chan_params *chan_params;
    int      regional_regulation;
    uint8_t  chan_plan;
    uint8_t  uc_chan_mask[WS_CHAN_MASK_LEN];
    uint8_t  bc_chan_mask[WS_CHAN_MASK_LEN];
    uint8_t  uc_dwell_interval;
    uint32_t bc_interval;
    uint8_t  bc_dwell_interval;
    uint32_t lfn_bc_interval;
    uint8_t  lfn_bc_sync_period;
    uint32_t async_frag_duration_ms;
    int      bsi;
};

struct ws_phy_config {
    const struct phy_params *params;
    uint8_t phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) + 1]; // +1 for sentinel
    uint8_t ms_mode;
    uint8_t phy_mode_id_ms_tx;
    uint8_t phy_mode_id_ms_base;
    int     rcp_rail_config_index; // Index number in rcp.rail_config_list. Needed to configure the RCP.
};

#endif
