#include <sys/eventfd.h>
#include <unistd.h>

#include <ns3/simulator.h>

extern "C" {
#include "app_wsbrd/wsbr.h"
#include "common/log.h"
}
#include "wsbrd_ns3.hpp"

static void wsbr_ns3_timer_tick(struct wsbr_ctxt *ctxt)
{
    uint64_t val = 1;
    int ret;

    ret = write(ctxt->timerfd, &val, 8);
    FATAL_ON(ret < 0, 2, "write: %m");
    FATAL_ON(ret < 8, 2, "write: Short write");
}

extern "C" void __wrap_wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    ctxt->timerfd = eventfd(0, EFD_NONBLOCK);
    FATAL_ON(ctxt->timerfd < 0, 2, "eventfd: %m");
    wsbr_ns3_timer_tick(ctxt);
}

extern "C" void __real_wsbr_common_timer_process(struct wsbr_ctxt *ctxt);
extern "C" void __wrap_wsbr_common_timer_process(struct wsbr_ctxt *ctxt)
{
    ns3::Simulator::ScheduleWithContext(
        g_simulation_id,
        ns3::MilliSeconds(50),
        wsbr_ns3_timer_tick, ctxt
    );
    __real_wsbr_common_timer_process(ctxt);
}
