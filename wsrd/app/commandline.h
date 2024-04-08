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

#include <limits.h>
#include <stdbool.h>

// This struct is filled by parse_commandline() and never modified after.
struct wsrd_conf {
    char uart_dev[PATH_MAX];
    int  uart_baudrate;
    bool uart_rtscts;
    char cpc_instance[PATH_MAX];

    bool list_rf_configs;
    int  color_output;
};

void parse_commandline(struct wsrd_conf *config, int argc, char *argv[]);

#endif
