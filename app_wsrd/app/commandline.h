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
#ifndef WSRD_COMMANDLINE_H
#define WSRD_COMMANDLINE_H

#include <net/if.h>
#include <sys/uio.h>
#include <limits.h>
#include <stdbool.h>

#include "common/ws/ws_chan_mask.h"
#include "common/ws/ws_ie.h"
#include "common/duty_cycle.h"
#include "common/trickle.h"
#include "common/rcp_api.h"

#include "app_wsrd/supplicant/supplicant.h"

// This struct is filled by parse_commandline() and never modified after.
struct wsrd_conf {
    struct rcp_cfg rcp_cfg;

    char ws_netname[WS_NETNAME_LEN];
    bool rpl_compat;

    char tun_dev[IF_NAMESIZE];
    bool tun_autoconf;
    char user[LOGIN_NAME_MAX];
    char group[LOGIN_NAME_MAX];

    struct trickle_cfg disc_cfg;
    int pan_timeout_ms;

    int  ws_domain;
    int  ws_phy_mode_id;
    int  ws_chan_plan_id;
    int  ws_mode;
    int  ws_class;
    struct duty_cycle_cfg duty_cycle;
    int  ws_chan0_freq;
    int  ws_chan_spacing;
    int  ws_chan_count;
    uint8_t ws_allowed_channels[WS_CHAN_MASK_LEN];
    int tx_power;
    // -1 for base mode +1 for sentinel
    uint8_t ws_phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) - 1 + 1];

    struct supp_cfg supp_cfg;

    char storage_prefix[PATH_MAX];
    bool storage_delete;

    int  ws_uc_dwell_interval_ms;

    struct eui64 ws_mac_address;
    struct eui64 ws_allowed_mac_addresses[10];
    uint8_t ws_allowed_mac_address_count;
    struct eui64 ws_denied_mac_addresses[10];
    uint8_t ws_denied_mac_address_count;

    bool list_rf_configs;
    int  color_output;
};

void parse_commandline(struct wsrd_conf *config, int argc, char *argv[]);

#endif
