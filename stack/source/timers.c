#include <assert.h>
#include "stack-scheduler/source/timer_sys.h"
#include "stack/source/nwk_interface/protocol_timer.h"
#include "stack/source/mpl/mpl.h"
#include "stack/timers.h"
#include "common/utils.h"
#include "common/log.h"

static struct {
    void (*callback)(int);
    int period_ms;
    bool periodic;
    int timeout;
} s_timers[] = {
    [TIMER_PROTOCOL] { protocol_timer_cb,        PROTOCOL_TIMER_PERIOD_MS, true,  0 },
    [TIMER_MPL]      { mpl_fast_timer,           MPL_TICK_MS,              false, 0 },
    [TIMER_SYS]      { system_timer_tick_update, TIMER_SYS_TICK_PERIOD,    true,  0 },
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
