#include "nsconfig.h"
#include <assert.h>
#include "stack/source/nwk_interface/protocol_core.h"
#include "stack/source/mpl/mpl.h"
#include "stack/dhcp_service_api.h"
#include "stack/timers.h"
#include "common/utils.h"
#include "common/log.h"

#ifdef HAVE_DHCPV6_SERVER
#include "stack/source/dhcpv6_server/dhcpv6_server_service.h"
#else
#define dhcpv6_server_service_timer_cb NULL
#define DHCPV6_TIMER_UPDATE_PERIOD_IN_SECONDS 0
#endif

static struct {
    void (*callback)(int);
    int period_ms;
    bool periodic;
    int timeout;
} s_timers[] = {
    [TIMER_PROTOCOL_CORE] { core_timer_event_handle,        100,                                          true,  0 },
    [TIMER_MPL]           { mpl_fast_timer,                 MPL_TICK_MS,                                  false, 0 },
    [TIMER_DHCPV6_SERVER] { dhcpv6_server_service_timer_cb, DHCPV6_TIMER_UPDATE_PERIOD_IN_SECONDS * 1000, true,  0 },
    [TIMER_DHCPV6_SOCKET] { dhcp_service_timer_cb,          100,                                          false, 0 },
};
static_assert(ARRAY_SIZE(s_timers) == TIMER_COUNT, "missing timer declarations");

void timer_start(enum timer_id id)
{
    BUG_ON(s_timers[id].period_ms % TIMER_GLOBAL_PERIOD_MS);
    s_timers[id].timeout = s_timers[id].period_ms / TIMER_GLOBAL_PERIOD_MS;
}

void timer_stop(enum timer_id id)
{
    s_timers[id].timeout = 0;
}

void timer_global_tick()
{
    for (int i = 0; i < ARRAY_SIZE(s_timers); i++) {
        if (!s_timers[i].timeout)
            continue;

        s_timers[i].timeout--; // Always advance one tick at a time
        if (s_timers[i].timeout)
            continue;

        s_timers[i].callback(1);
        if (s_timers[i].periodic)
            timer_start(i);
    }
}
