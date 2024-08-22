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
#ifndef WSRD_WS_H
#define WSRD_WS_H

#include <sys/queue.h>
#include <stddef.h>
#include <stdint.h>

#include "common/ws_interface.h"
#include "common/trickle.h"
#include "app_wsrd/supplicant/supplicant.h"
#include "app_wsrd/ipv6/ipv6.h"

struct wsrd_ws_ctx {
    struct ws_ctx ws;

    struct trickle pas_tkl;
    struct timer_entry pan_selection_timer;
    struct trickle pcs_tkl;

    struct ipv6_ctx ipv6;

    struct supplicant_ctx supp;
    struct eui64 eapol_target_eui64;
};

void ws_on_recv_ind(struct ws_ctx *ws, struct ws_ind *ind);
void ws_on_recv_cnf(struct ws_ctx *ws, struct ws_frame_ctx *frame_ctx, const struct rcp_tx_cnf *cnf);

void ws_on_pan_selection_timer_timeout(struct timer_group *group, struct timer_entry *timer);
void ws_on_pas_interval_done(struct trickle *tkl);
void ws_on_send_pas(struct trickle *tkl);
void ws_on_send_pcs(struct trickle *tkl);

#endif
