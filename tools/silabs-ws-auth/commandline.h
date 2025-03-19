/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2026 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SL_AUTH_COMMANDLINE_H
#define SL_AUTH_COMMANDLINE_H

#include "common/authenticator/authenticator.h"

struct sl_auth_cfg {
    struct auth_cfg auth;
    struct eui64 eui64;
    bool enable_lfn;
    bool storage_delete;
    bool storage_exit;
};

void parse_commandline(struct sl_auth_cfg *cfg, int argc, char *argv[]);

#endif
