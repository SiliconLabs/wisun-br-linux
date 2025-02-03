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
#ifndef WSRD_H
#define WSRD_H

#include "common/ws/ws_interface.h"
#include "common/trickle.h"
#include "common/timer.h"
#include "app_wsrd/supplicant/supplicant.h"
#include "app_wsrd/app/commandline.h"
#include "app_wsrd/app/join_state.h"
#include "app_wsrd/ipv6/ipv6.h"

struct wsrd {
    struct wsrd_conf config;

    enum wsrd_state state;

    struct ws_ctx ws;

    struct trickle pas_tkl;
    struct timer_entry pan_selection_timer;
    struct trickle pcs_tkl;

    struct ipv6_ctx ipv6;

    struct supp_ctx supp;
    struct eui64 eapol_target_eui64;
};

// Necessary for simulation and fuzzing, prefer passing a pointer when possible.
extern struct wsrd g_wsrd;

int wsrd_main(int argc, char *argv[]);

#endif
