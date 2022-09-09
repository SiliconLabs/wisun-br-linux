#include <sys/timerfd.h>
#include <unistd.h>

#include "stack-scheduler/source/timer_sys.h"
#include "stack/timers.h"
#include "common/log.h"
#include "timers.h"
#include "wsbr.h"

void wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    int ret;
    struct itimerspec parms = {
        .it_value.tv_nsec = TIMER_GLOBAL_PERIOD_MS * 1000 * 1000,
        .it_interval.tv_nsec = TIMER_GLOBAL_PERIOD_MS * 1000 * 1000,
    };

    timer_sys_init();
    timer_start(TIMER_PROTOCOL);
    ctxt->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    FATAL_ON(ctxt->timerfd < 0, 2, "timerfd_create: %m");
    ret = timerfd_settime(ctxt->timerfd, 0, &parms, NULL);
    FATAL_ON(ret < 0, 2, "timerfd_settime: %m");
}

void wsbr_common_timer_process(struct wsbr_ctxt *ctxt)
{
    uint64_t val;
    int ret;

    ret = read(ctxt->timerfd, &val, sizeof(val));
    WARN_ON(ret < sizeof(val), "cancelled timer?");
    WARN_ON(val != 1, "missing timers: %u", (unsigned int)val - 1);
    timer_global_tick();
}

void wsbr_spinel_replay_timers(struct spinel_buffer *buf)
{
    WARN("%s: not implemented", __func__);
}
