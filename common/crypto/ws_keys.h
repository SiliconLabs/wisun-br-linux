/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WS_KEYS_H
#define WS_KEYS_H

#include <stdint.h>

#include "common/timer.h"

struct ws_gtk {
    uint8_t key[16];
    struct timer_entry expiration_timer;
};

#define WS_GTK_COUNT  4
#define WS_LGTK_COUNT 3

void ws_generate_gak(const char *netname, const uint8_t gtk[16], uint8_t gak[16]);
void ws_derive_ptkid(const uint8_t ptk[48], const uint8_t auth_eui64[8], const uint8_t supp_eui64[8],
                     uint8_t ptkid[16]);

#endif
