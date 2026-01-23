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
#include <assert.h>
#include "net/protocol.h"
#include "common/memutils.h"
#include "common/log.h"

#include "timers.h"

#define timer_entry(name, callback, period_ms, is_periodic) \
    [WS_TIMER_##name] = { #name, callback, period_ms, is_periodic, 0 }
struct ws_timer g_timers[] = {
    timer_entry(ICMP_FAST,              icmp_fast_timer,                            100,                     true),
};
static_assert(ARRAY_SIZE(g_timers) == WS_TIMER_COUNT, "missing timer declarations");

void ws_timer_start(enum timer_id id)
{
    BUG_ON(g_timers[id].period_ms % WS_TIMER_GLOBAL_PERIOD_MS);
    g_timers[id].timeout = g_timers[id].period_ms / WS_TIMER_GLOBAL_PERIOD_MS;
}

void ws_timer_stop(enum timer_id id)
{
    g_timers[id].timeout = 0;
}


void ws_timer_cb(struct timer_group *group, struct timer_entry *timer)
{
    for (int i = 0; i < ARRAY_SIZE(g_timers); i++) {
        if (!g_timers[i].timeout)
            continue;

        g_timers[i].timeout--; // Always advance one tick at a time
        if (g_timers[i].timeout)
            continue;

        g_timers[i].callback(1);
        TRACE(TR_TIMERS, "timer: %s", g_timers[i].trace_name);
        if (g_timers[i].periodic)
            ws_timer_start(i);
    }
}
