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
#include <math.h>

#include "common/specs/ws.h"
#include "common/ws/ws_neigh.h"
#include "common/ws/ws_ewma.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/eui64.h"
#include "common/log.h"

#include "ws_etx.h"

// NOTE: This module depends on ws_neigh to access the EUI-64
static void ws_etx_trace_update(struct ws_etx *ws_etx, float etx)
{
    struct ws_neigh *ws_neigh = container_of(ws_etx, struct ws_neigh, ws_etx);

    TRACE(TR_NEIGH_15_4, "neigh-15.4 set %s etx tx=%u / ack=%u => old=%.2f new=%.2f",
          tr_eui64(ws_neigh->eui64.u8), ws_etx->tx_cnt, ws_etx->ack_cnt, ws_etx->etx, etx);
}

// Wi-SUN FAN 1v33 6.2.3.1.6.1 Link Metrics
static void ws_etx_timeout_compute(struct timer_group *group, struct timer_entry *timer)
{
    struct ws_etx_ctx *ws_etx_ctx = container_of(group, struct ws_etx_ctx, timer_group);
    struct ws_etx *ws_etx = container_of(timer, struct ws_etx, timer_compute);
    float etx;

    /*
     * The ETX calculation epoch is triggered when both the following
     * conditions are satisfied:
     *   1. At least 4 transmissions have occurred since the last ETX
     *      calculation.
     *   2. At least 1 minute has expired since the last ETX calculation.
     *
     * [...]
     *
     * At node start up, 1 transmission attempts will trigger the ETX
     * calculation epoch (to speed boot time).
     * NOTE: The required number of transmission attempts for other
     * computations is defined by update_min_tx_req_cnt.
     */
    if (!(ws_etx->tx_req_cnt >= ws_etx_ctx->update_min_tx_req_cnt || isnan(ws_etx->etx))) {
        // Probe right now until we reach the N necessary measurements
        if (timer_stopped(&ws_etx->timer_outdated) && ws_etx_ctx->on_etx_outdated)
            ws_etx_ctx->on_etx_outdated(ws_etx_ctx, ws_etx);
        return;
    }

    /*
     * ETX MUST be calculated as
     *   (frame transmission attempts)/(received frame acknowledgements) * 128
     * with a maximum value of 1024, where 0 received frame acknowledgments
     * sets ETX to the maximum value.
     */
    if (ws_etx->ack_cnt)
        etx = MIN((float)ws_etx->tx_cnt / ws_etx->ack_cnt * 128, WS_ETX_MAX);
    else
        etx = WS_ETX_MAX;

    /*
     * Arbitrary: we give less weight to the first few ETX calculations.
     * This allows to converge to a more accurate ETX value faster.
     */
    if (ws_etx->compute_cnt < 8)
        ws_etx->compute_cnt++;

    /*
     * The ETX calculation is performed at a defined epoch, with the ETX result
     * fed into an EWMA using smoothing factor of 1/8.
     */
    etx = ws_ewma_next(ws_etx->etx, etx, 1.f / (float)ws_etx->compute_cnt);

    ws_etx_trace_update(ws_etx, etx);

    ws_etx->etx = etx;
    ws_etx->tx_cnt  = 0;
    ws_etx->ack_cnt = 0;
    ws_etx->tx_req_cnt = 0;

    /*
     * NOTE: Per the rule 2 above, the minimum delay should be set to 1 minute.
     * We allow this delay to be changed.
     */
    timer_start_rel(&ws_etx_ctx->timer_group, &ws_etx->timer_compute, ws_etx_ctx->update_min_delay_ms);

    /*
     * A Router SHOULD refresh its neighbor link metrics at least every 30
     * minutes.
     * NOTE: This period can be changed.
     */
    timer_start_rel(&ws_etx_ctx->timer_group, &ws_etx->timer_outdated, ws_etx_ctx->refresh_period_ms);

    if (ws_etx_ctx->on_etx_update)
        ws_etx_ctx->on_etx_update(ws_etx_ctx, ws_etx);
}

static void ws_etx_timeout_outdated(struct timer_group *group, struct timer_entry *timer)
{
    struct ws_etx_ctx *ws_etx_ctx = container_of(group, struct ws_etx_ctx, timer_group);
    struct ws_etx *ws_etx = container_of(timer, struct ws_etx, timer_outdated);

    if (ws_etx_ctx->on_etx_outdated)
        ws_etx_ctx->on_etx_outdated(ws_etx_ctx, ws_etx);
}

void ws_etx_init(struct ws_etx *ws_etx)
{
    ws_etx->etx = NAN;
    ws_etx->tx_cnt = 0;
    ws_etx->ack_cnt = 0;
    ws_etx->tx_req_cnt = 0;
    ws_etx->compute_cnt = 0;
    ws_etx->timer_compute.callback = ws_etx_timeout_compute;
    ws_etx->timer_outdated.callback = ws_etx_timeout_outdated;
}

void ws_etx_reset(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx)
{
    timer_stop(&ws_etx_ctx->timer_group, &ws_etx->timer_compute);
    timer_stop(&ws_etx_ctx->timer_group, &ws_etx->timer_outdated);
    ws_etx_init(ws_etx);
}

void ws_etx_update(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx, int tx_count, bool ack)
{
    ws_etx->tx_req_cnt++;
    ws_etx->tx_cnt  += tx_count;
    ws_etx->ack_cnt += ack;
    /*
     * FIXME: ETX computation is scheduled to ensure the confirmed frame is
     * properly processed by higher layers.
     */
    if (timer_stopped(&ws_etx->timer_compute))
        timer_start_rel(&ws_etx_ctx->timer_group, &ws_etx->timer_compute, 0);
}
