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
#ifndef COMMON_WS_IE_VALIDATION_H
#define COMMON_WS_IE_VALIDATION_H

#include <stdbool.h>

struct ws_generic_channel_info;
struct ws_fhss_config;
struct iobuf_read;
struct ws_pan_ie;
struct ws_us_ie;
struct ws_bs_ie;

bool ws_ie_validate_chan_plan(struct ws_fhss_config *fhss, const struct ws_generic_channel_info *schedule);
bool ws_ie_validate_schedule(struct ws_fhss_config *fhss, const struct ws_generic_channel_info *schedule);
bool ws_ie_validate_us(struct ws_fhss_config *fhss, const struct iobuf_read *ie_wp, struct ws_us_ie *ie_us);
bool ws_ie_validate_bs(struct ws_fhss_config *fhss, const struct iobuf_read *ie_wp, struct ws_bs_ie *ie_bs);
bool ws_ie_validate_netname(const char *netname, const struct iobuf_read *ie_wp);
bool ws_ie_validate_pan(const struct iobuf_read *ie_wp, struct ws_pan_ie *ie_pan);

#endif
