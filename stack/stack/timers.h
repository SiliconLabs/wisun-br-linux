#ifndef NS_TIMERS_H
#define NS_TIMERS_H

#define TIMER_GLOBAL_PERIOD_MS 50

enum timer_id {
    TIMER_PROTOCOL_CORE,
    TIMER_MPL_FAST,
    TIMER_MPL_SLOW,
    TIMER_RPL_FAST,
    TIMER_RPL_SLOW,
    TIMER_IPV6_DESTINATION,
    TIMER_IPV6_ROUTE,
    TIMER_IPV6_FRAG,
    TIMER_PAE_FAST,
    TIMER_PAE_SLOW,
    TIMER_DHCPV6_SOCKET,
    TIMER_DHCPV6_SERVER,
    TIMER_COUNT,
};

void timer_start(enum timer_id id);
void timer_stop(enum timer_id id);

void timer_global_tick();

#endif
