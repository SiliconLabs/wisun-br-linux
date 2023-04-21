#ifndef WS_TIMERS_H
#define WS_TIMERS_H

#include <stdbool.h>

#define WS_TIMER_GLOBAL_PERIOD_MS 50

enum timer_id {
    WS_TIMER_MONOTONIC_TIME,
    WS_TIMER_MPL_FAST,
    WS_TIMER_MPL_SLOW,
    WS_TIMER_RPL_FAST,
    WS_TIMER_RPL_SLOW,
    WS_TIMER_IPV6_DESTINATION,
    WS_TIMER_IPV6_ROUTE,
    WS_TIMER_IPV6_FRAG,
    WS_TIMER_CIPV6_FRAG,
    WS_TIMER_ICMP_FAST,
    WS_TIMER_6LOWPAN_MLD_FAST,
    WS_TIMER_6LOWPAN_MLD_SLOW,
    WS_TIMER_6LOWPAN_ADDR_FAST,
    WS_TIMER_6LOWPAN_ADDR_SLOW,
    WS_TIMER_6LOWPAN_ND,
    WS_TIMER_6LOWPAN_ETX,
    WS_TIMER_6LOWPAN_ADAPTATION,
    WS_TIMER_6LOWPAN_NEIGHBOR,
    WS_TIMER_6LOWPAN_NEIGHBOR_SLOW,
    WS_TIMER_6LOWPAN_NEIGHBOR_FAST,
    WS_TIMER_6LOWPAN_CONTEXT,
    WS_TIMER_6LOWPAN_BOOTSTRAP,
    WS_TIMER_6LOWPAN_REACHABLE_TIME,
    WS_TIMER_WS_COMMON_FAST,
    WS_TIMER_WS_COMMON_SLOW,
    WS_TIMER_PAE_FAST,
    WS_TIMER_PAE_SLOW,
    WS_TIMER_DHCPV6_SOCKET,
#ifdef HAVE_WS_BORDER_ROUTER
    WS_TIMER_LPA,
    WS_TIMER_LTS,
#endif
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

void ws_timer_global_tick();

#endif
