/*
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

#include <sys/uio.h>
#include <limits.h>
#include <stdbool.h>

#include "common/ws_chan_mask.h"
#include "common/ws_ie.h"

// This struct is filled by parse_commandline() and never modified after.
struct wsrd_conf {
    char uart_dev[PATH_MAX];
    int  uart_baudrate;
    bool uart_rtscts;
    char cpc_instance[PATH_MAX];

    char ws_netname[WS_NETNAME_LEN];

    int  ws_domain;
    int  ws_phy_mode_id;
    int  ws_chan_plan_id;
    int  ws_mode;
    int  ws_class;
    int  ws_chan0_freq;
    int  ws_chan_spacing;
    int  ws_chan_count;
    uint8_t ws_allowed_channels[WS_CHAN_MASK_LEN];

    struct iovec ca_cert;
    struct iovec cert;
    struct iovec key;

    int  ws_uc_dwell_interval_ms;

    bool list_rf_configs;
    int  color_output;
};

void parse_commandline(struct wsrd_conf *config, int argc, char *argv[]);

#endif
