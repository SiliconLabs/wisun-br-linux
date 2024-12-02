/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include <sys/eventfd.h>
#include <unistd.h>

#include <ns3/simulator.h>
#include <ns3/libwsbrd-ns3.hpp>

extern "C" {
#include "app_wsbrd/app/wsbrd.h"
#include "common/capture.h"
#include "common/log.h"
}

static void wsbr_ns3_timer_tick(struct wsbr_ctxt *ctxt)
{
    uint64_t val = 1;
    int ret;

    ret = xwrite(ctxt->timerfd, &val, 8);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < 8, 2, "%s: write: Short write", __func__);
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

extern "C" int __wrap_clock_gettime(clock_t clockid, struct timespec *tp)
{
    ns3::Time now = ns3::Now();
    tp->tv_sec = now.GetSeconds();
    tp->tv_nsec = now.GetNanoSeconds() % 1000000000;
    return 0;
}
