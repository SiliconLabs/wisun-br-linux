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
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <ns3/event-id.h>
#include <ns3/simulator.h>
#include <ns3/libwsbrd-ns3.hpp>

extern "C" {
#include "common/log.h"
#include "common/mathutils.h"
}

static ns3::EventImpl *g_timer_event = NULL;

extern "C" int __wrap_timerfd_create(int clockid, int flags)
{
    return eventfd(0, 0);
}

static void dc_ns3_timer_trig(int fd)
{
    uint64_t val = 1;
    int ret;

    ret = write(fd, &val, 8);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < 8, 2, "%s: write: Short write", __func__);
    g_timer_event = NULL;
}

extern "C" int __wrap_timerfd_settime(int fd, int flags,
                                      const struct itimerspec *it_new,
                                      struct itimerspec *it_old)
{
    ns3::Time t = ns3::Seconds(it_new->it_value.tv_sec) +
                  ns3::NanoSeconds(it_new->it_value.tv_nsec);

    BUG_ON(flags != TFD_TIMER_ABSTIME);
    BUG_ON(it_old);
    BUG_ON(it_new->it_interval.tv_sec || it_new->it_interval.tv_nsec);
    if (g_timer_event) {
        g_timer_event->Cancel();
        g_timer_event = NULL;
    }
    if (!it_new->it_value.tv_sec && !it_new->it_value.tv_nsec)
        return 0;
    g_timer_event = ns3::MakeEvent(dc_ns3_timer_trig, fd);
    ns3::Simulator::ScheduleWithContext(
        g_simulation_id,
        MAX(t - ns3::Now(), ns3::Time(0)),
        g_timer_event
    );
    return 0;
}

extern "C" int __wrap_clock_gettime(clock_t clockid, struct timespec *tp)
{
    ns3::Time now = ns3::Now();
    tp->tv_sec  = now.GetSeconds();
    tp->tv_nsec = now.GetNanoSeconds() % 1000000000;
    return 0;
}