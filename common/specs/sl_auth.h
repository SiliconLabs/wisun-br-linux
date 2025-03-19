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
#ifndef SL_AUTH_H
#define SL_AUTH_H

#include <stdint.h>

#include "common/crypto/ws_keys.h"
#include "common/eui64.h"

struct sl_auth_mqtt_info {
    struct eui64 eui64;
    uint8_t gtk_index;
    uint8_t lgtk_index;
    uint16_t reserved;
    uint8_t gtk[WS_GTK_COUNT + WS_LGTK_COUNT][16];
};

#endif
