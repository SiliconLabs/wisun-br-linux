/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WS_ETX_H
#define WS_ETX_H

#include <stdbool.h>

#include "common/timer.h"

struct eui64;

struct ws_etx {
    float etx;
    int tx_cnt;
    int ack_cnt;
    int tx_req_cnt;
    int compute_cnt;
    struct timer_entry timer_compute;
    struct timer_entry timer_outdated;
};

struct ws_etx_ctx {
    struct timer_group timer_group;

    /*
     * Called when ETX is out-of-date. This should initiate some traffic in
     * order to measure ETX.
     */
    void (*on_etx_outdated)(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx);

    // Called when ETX has changed, in order to update RPL parents.
    void (*on_etx_update)(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx);

    // Minimum number of TX requests to trigger ETX update
    int update_min_tx_req_cnt;

    // Minimum delay between ETX updates in milliseconds
    uint64_t update_min_delay_ms;

    // ETX refresh period in milliseconds
    uint64_t refresh_period_ms;
};

void ws_etx_init(struct ws_etx *ws_etx);
void ws_etx_reset(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx);
void ws_etx_update(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx, int tx_count, bool ack);

#endif
