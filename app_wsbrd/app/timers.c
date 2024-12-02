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
#include <sys/timerfd.h>
#include <inttypes.h>

#include "common/capture.h"
#include "common/log.h"

#include "net/timers.h"

#include "timers.h"
#include "wsbrd.h"

void wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    int ret;
    struct itimerspec parms = {
        .it_value.tv_nsec = WS_TIMER_GLOBAL_PERIOD_MS * 1000 * 1000,
        .it_interval.tv_nsec = WS_TIMER_GLOBAL_PERIOD_MS * 1000 * 1000,
    };

    ctxt->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    FATAL_ON(ctxt->timerfd < 0, 2, "timerfd_create: %m");
    ret = timerfd_settime(ctxt->timerfd, 0, &parms, NULL);
    FATAL_ON(ret < 0, 2, "timerfd_settime: %m");
}

void wsbr_common_timer_process(struct wsbr_ctxt *ctxt)
{
    uint64_t val;
    int ret;

    ret = xread(ctxt->timerfd, &val, sizeof(val));
    WARN_ON(ret < sizeof(val), "cancelled timer?");
    WARN_ON(val != 1, "missing timers: %"PRIu64, val - 1);
    ws_timer_global_tick();
}
