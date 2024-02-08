#include <assert.h>
#include "6lbr/6lowpan/iphc_decode/lowpan_context.h"
#include "6lbr/6lowpan/lowpan_adaptation_interface.h"
#include "6lbr/6lowpan/fragmentation/cipv6_fragmenter.h"
#include "6lbr/ipv6/nd_router_object.h"
#include "6lbr/ws/ws_common.h"
#include "6lbr/ws/ws_mngt.h"
#include "6lbr/ws/ws_pae_controller.h"
#include "6lbr/ipv6/ipv6_routing_table.h"
#include "6lbr/nwk_interface/protocol.h"
#include "6lbr/mpl/mpl.h"
#include "6lbr/rpl/rpl.h"
#include "common/memutils.h"
#include "common/log.h"

#include "timers.h"

int g_monotonic_time_100ms = 0;

static void timer_update_monotonic_time(int ticks)
{
    g_monotonic_time_100ms += ticks;
}

static void timer_refresh_neighbors(int time_update)
{
    struct net_if *interface = protocol_stack_interface_info_get();
    ws_neigh_table_expire(&interface->ws_info.neighbor_storage, time_update);
}

#define timer_entry(name, callback, period_ms, is_periodic) \
    [WS_TIMER_##name] = { #name, callback, period_ms, is_periodic, 0 }
struct ws_timer g_timers[] = {
    timer_entry(MONOTONIC_TIME,         timer_update_monotonic_time,                100,                     true),
    timer_entry(MPL,                    mpl_timer,                                  1000,                    true),
    timer_entry(RPL,                    rpl_timer,                                  1000,                    true),
    timer_entry(IPV6_DESTINATION,       ipv6_destination_cache_timer,               DCACHE_GC_PERIOD * 1000, true),
    timer_entry(IPV6_ROUTE,             ipv6_route_table_ttl_update,                1000,                    true),
    timer_entry(CIPV6_FRAG,             cipv6_frag_timer,                           1000,                    true),
    timer_entry(ICMP_FAST,              icmp_fast_timer,                            100,                     true),
    timer_entry(PAE_FAST,               ws_pae_controller_fast_timer,               100,                     true),
    timer_entry(PAE_SLOW,               ws_pae_controller_slow_timer,               1000,                    true),
    timer_entry(WS_COMMON_SLOW,         ws_common_seconds_timer,                    1000,                    true),
    timer_entry(6LOWPAN_ADAPTATION,     lowpan_adaptation_interface_slow_timer,     1000,                    true),
    timer_entry(6LOWPAN_NEIGHBOR,       timer_refresh_neighbors,                    5000,                    true),
    timer_entry(6LOWPAN_NEIGHBOR_SLOW,  ipv6_neighbour_cache_slow_timer,            1000,                    true),
    timer_entry(6LOWPAN_NEIGHBOR_FAST,  ipv6_neighbour_cache_fast_timer,            100,                     true),
    timer_entry(6LOWPAN_CONTEXT,        lowpan_context_timer,                       100,                     true),
    timer_entry(6LOWPAN_REACHABLE_TIME, update_reachable_time,                      1000,                    true),
    timer_entry(LPA,                    ws_mngt_lpa_timer_cb,                       0,                       false),
    timer_entry(LTS,                    ws_mngt_lts_timer_cb,                       0,                       true),
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

void ws_timer_global_tick()
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
