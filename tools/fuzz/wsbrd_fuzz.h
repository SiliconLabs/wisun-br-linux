/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBRD_FUZZ_H
#define WSBRD_FUZZ_H

#include <stdbool.h>
#include <time.h>

#include "interfaces.h"

struct wsbr_ctxt;

struct fuzz_ctxt {
    struct wsbr_ctxt *wsbrd; // Avoids accessing g_ctxt directly

    bool fuzzing_enabled;
    bool rand_predictable;
    time_t mbedtls_time;

    int replay_count;
    int replay_fds[10];
    int replay_i;
    uint8_t tun_gua[16];
    uint8_t tun_lla[16];
    int iface_count;
    struct fuzz_iface *iface_list;
    uint64_t replay_time_ms;
    uint64_t target_time_ms;
};

extern struct fuzz_ctxt g_fuzz_ctxt;

int wsbr_fuzz_main(int argc, char *argv[]);

#endif
