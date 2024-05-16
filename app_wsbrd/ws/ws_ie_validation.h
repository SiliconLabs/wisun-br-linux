/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WS_IE_VALIDATION_H
#define WS_IE_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>

struct ws_netname_ie;
struct ws_lcp_ie;
struct ws_us_ie;
struct ws_bs_ie;
struct ws_info;

bool ws_ie_validate_us(const struct ws_info *ws_info, const struct ws_us_ie *ie_us);
bool ws_ie_validate_bs(const struct ws_info *ws_info, const struct ws_bs_ie *ie_us);
bool ws_ie_validate_lcp(const struct ws_info *ws_info, const struct ws_lcp_ie *ie_lcp);
bool ws_ie_validate_netname(const struct ws_info *ws_info, const struct ws_netname_ie *ie_netname);

#endif
