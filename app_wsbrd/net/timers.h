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
#ifndef WS_TIMERS_H
#define WS_TIMERS_H

#include <stdbool.h>

struct timer_entry;
struct timer_group;

#define WS_TIMER_GLOBAL_PERIOD_MS 50

enum timer_id {
    WS_TIMER_MONOTONIC_TIME,
    WS_TIMER_MPL,
    WS_TIMER_RPL,
    WS_TIMER_IPV6_DESTINATION,
    WS_TIMER_IPV6_ROUTE,
    WS_TIMER_CIPV6_FRAG,
    WS_TIMER_ICMP_FAST,
    WS_TIMER_6LOWPAN_MLD_FAST,
    WS_TIMER_6LOWPAN_MLD_SLOW,
    WS_TIMER_6LOWPAN_ND,
    WS_TIMER_6LOWPAN_ADAPTATION,
    WS_TIMER_6LOWPAN_NEIGHBOR_SLOW,
    WS_TIMER_6LOWPAN_NEIGHBOR_FAST,
    WS_TIMER_6LOWPAN_CONTEXT,
    WS_TIMER_6LOWPAN_REACHABLE_TIME,
    WS_TIMER_WS_COMMON_FAST,
    WS_TIMER_ASYNC,
    WS_TIMER_PAE_FAST, // HAVE_AUTH_LEGACY only
    WS_TIMER_PAE_SLOW, // HAVE_AUTH_LEGACY only
    WS_TIMER_DHCPV6_SOCKET,
    WS_TIMER_LPA,
    WS_TIMER_LTS,
    WS_TIMER_COUNT,
};

extern int g_monotonic_time_100ms;

// Expose timer array to avoid boilerplate API functions when "low level"
// operation are needed.
struct ws_timer {
    const char *trace_name;
    void (*callback)(int);
    int period_ms;
    bool periodic;
    int timeout;
};
extern struct ws_timer g_timers[WS_TIMER_COUNT];

void ws_timer_start(enum timer_id id);
void ws_timer_stop(enum timer_id id);

void ws_timer_cb(struct timer_group *group, struct timer_entry *timer);

#endif
