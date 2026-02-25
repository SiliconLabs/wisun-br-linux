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
#ifndef DC_COMMANDLINE_H
#define DC_COMMANDLINE_H

#include <net/if.h>

#include "common/rcp_api.h"
#include "common/commandline.h"
#include "common/authenticator/authenticator.h"
#include "common/sl_ws.h"

struct dc_cfg {
    struct rcp_cfg rcp_cfg;
    struct auth_cfg auth_cfg;

    char tun_dev[IF_NAMESIZE];
    bool tun_autoconf;
    char user[LOGIN_NAME_MAX];
    char group[LOGIN_NAME_MAX];

    int  ws_domain;
    int  ws_phy_mode_id;
    int  ws_chan_plan_id;
    int  ws_mode;
    int  ws_class;
    int  ws_chan0_freq;
    int  ws_chan_spacing;
    int  ws_chan_count;
    int  ws_uc_dwell_interval_ms;
    uint8_t ws_allowed_channels[WS_CHAN_MASK_LEN];
    uint8_t ws_custom_allowed_channels[WS_CHAN_MASK_LEN];

    uint8_t target_pmk[32];
    struct eui64 target_eui64;
    char target_id[SL_DC_ID_LEN + 1];
    int disc_period_s;
    int disc_count_max;

    bool list_rf_configs;
    int  color_output;
    struct rcp_log_cfg rcp_traces;
};

void parse_commandline(struct dc_cfg *config, int argc, char *argv[]);

#endif
