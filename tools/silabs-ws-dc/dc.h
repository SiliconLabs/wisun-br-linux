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
#ifndef DC_H
#define DC_H
#include <netinet/in.h>

#include "common/ws_interface.h"
#include "common/tun.h"

#include "commandline.h"

struct dc {
    struct dc_cfg cfg;
    struct ws_ctx ws;
    struct tun_ctx tun;
    struct in6_addr addr_linklocal;
};

extern struct dc g_dc;

int dc_main(int argc, char *argv[]);

#endif
