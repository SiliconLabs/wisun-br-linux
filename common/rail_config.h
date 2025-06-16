/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023-2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef COMMON_RAIL_CONFIG_H
#define COMMON_RAIL_CONFIG_H

#include "common/specs/ws.h"
#include "common/bits.h"

struct ws_ms_chan_mask;
struct ws_fhss_config;
struct ws_phy_config;
struct rcp;

void rail_print_config_list(struct rcp *rcp);
void rail_fill_ms_chan_masks(const struct rcp *rcp, const struct ws_fhss_config *fhss, const struct ws_phy_config *phy,
                             struct ws_ms_chan_mask *ms_chan_mask);

/*
 * - Fills phy->rcp_rail_config_index based on fhss->chan_params and
 *   phy->params. FATAL() if no matching RCP radio configuration is found.
 * - Fills phy_config->phy_op_modes based on the available RCP radio
 *   configurations, the selected base PHY, and optional user override.
 */
void rail_fill_pom(const struct rcp *rcp, const struct ws_fhss_config *fhss, struct ws_phy_config *phy,
                   const uint8_t ws_phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) - 1 + 1]);

#endif
