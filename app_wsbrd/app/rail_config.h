/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef RAIL_CONFIG_H
#define RAIL_CONFIG_H

/*
 * Helpers for RAdio Interface Library (RAIL) configuration.
 */

struct wsbr_ctxt;

#include "common/rail_config.h"

void rail_fill_pom(const struct rcp *rcp, const struct ws_fhss_config *fhss, struct ws_phy_config *phy,
                   const uint8_t ws_phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) - 1 + 1]);
#endif
