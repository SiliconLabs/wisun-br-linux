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
    uint32_t frame_counter;
    struct timer_entry expiration_timer;
};

#define WS_GTK_COUNT  4
#define WS_LGTK_COUNT 3

/*
 * When storing frame counter to disk, it may not be flushed immediately, and
 * also it may not be up-to-date with the RCP. Add an arbirary increment when
 * loading to ensure no counter value is re-used.
 */
#define WS_GTK_COUNTER_INC 200000

static inline bool ws_gtk_installed(const struct ws_gtk *gtk)
{
    return !timer_stopped(&gtk->expiration_timer);
}

uint8_t ws_gtkl(const struct ws_gtk *gtks, int count);
void ws_gtk_clear(struct timer_group *group, struct ws_gtk *gtk);
void ws_generate_gak(const char *netname, const uint8_t gtk[16], uint8_t gak[16]);
void ws_derive_ptkid(const uint8_t ptk[48], const uint8_t auth_eui64[8], const uint8_t supp_eui64[8],
                     uint8_t ptkid[16]);

/*
 * Store frame counters for all keys ever used, and restore counters if a
 * previous key is re-used. This is particularly relevant when switching
 * between PANs. Each key has an associated counter-xx:xx:xx:xx:xx:xx:xx:xx
 * file with the suffix being the key hash as defined in the GTKHASH-IE.
 */
void ws_gtk_counter_load(struct ws_gtk *gtk);
void ws_gtk_counter_store(const struct ws_gtk *gtk);
void ws_gtk_counter_del(const struct ws_gtk *gtk);

#endif
