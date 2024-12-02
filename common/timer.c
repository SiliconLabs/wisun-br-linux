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
#define _GNU_SOURCE
#include <sys/timerfd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "common/log.h"
#include "common/sys_queue_extra.h"
#include "common/time_extra.h"

#include "timer.h"

// Declare struct timer_group_list
SLIST_HEAD(timer_group_list, timer_group);

struct timer_ctxt {
    int fd;
    struct timer_group_list groups;
    struct timer_group group_default;
} g_timer_ctxt = {
    .fd = -1,
};

static struct timer_ctxt *timer_ctxt(void)
{
    struct timer_ctxt *ctxt = &g_timer_ctxt;

    if (ctxt->fd >= 0)
        return ctxt;
    ctxt->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    FATAL_ON(ctxt->fd < 0, 2, "timerfd_create: %m");
    SLIST_INIT(&ctxt->groups);
    timer_group_init(&ctxt->group_default);
    return ctxt;
}

int timer_fd(void)
{
    struct timer_ctxt *ctxt = timer_ctxt();

    return ctxt->fd;
}

struct timer_entry *timer_next(void)
{
    struct timer_ctxt *ctxt = timer_ctxt();
    struct timer_entry *cur, *nxt = NULL;
    struct timer_group *group;

    SLIST_FOREACH(group, &ctxt->groups, link) {
        cur = SLIST_FIRST(&group->timers);
        if (!cur)
            continue;
        if (nxt && cur->expire_ms >= nxt->expire_ms)
            continue;
        nxt = cur;
    }
    return nxt;
}

static void timer_schedule(void)
{
    struct itimerspec itp = { };
    struct timer_entry *timer;
    int ret;

    timer = timer_next();
    if (!timer)
        return;
    itp.it_value.tv_sec = timer->expire_ms / 1000;
    itp.it_value.tv_nsec = (timer->expire_ms % 1000) * 1000000;
    ret = timerfd_settime(timer_fd(), TFD_TIMER_ABSTIME, &itp, NULL);
    FATAL_ON(ret < 0, 2, "timerfd_settime: %m");
}

// Returns true if timer_schedule() should be called.
static bool timer_start(struct timer_group *group, struct timer_entry *timer, uint64_t expire_ms)
{
    struct timer_ctxt *ctxt = timer_ctxt();
    struct timer_entry *cur, *prev;

    timer->start_ms = time_now_ms(CLOCK_MONOTONIC);

    if (!group)
        group = &ctxt->group_default;
    prev = NULL;
    SLIST_FOREACH(cur, &group->timers, link) {
        if (expire_ms <= cur->expire_ms)
            break;
        prev = cur;
    }
    timer->expire_ms = expire_ms;
    if (prev)
        SLIST_INSERT_AFTER(prev, timer, link);
    else
        SLIST_INSERT_HEAD(&group->timers, timer, link);

    return !prev;
}

static void timer_reset(struct timer_entry *timer)
{
    timer->start_ms  = 0;
    timer->expire_ms = 0;
}

void timer_process(void)
{
    struct timer_ctxt *ctxt = timer_ctxt();
    uint64_t now_ms = time_now_ms(CLOCK_MONOTONIC);
    struct timer_entry *timer, *tmp;
    struct timer_list trig_list;
    struct timer_group *group;
    uint64_t val;
    ssize_t ret;

    ret = read(ctxt->fd, &val, sizeof(val));
    FATAL_ON(ret != 8, 2, "read timer: %m");
    WARN_ON(val != 1);

    SLIST_INIT(&trig_list);
    SLIST_FOREACH(group, &ctxt->groups, link) {
        SLIST_FOREACH_SAFE(timer, &group->timers, link, tmp) {
            if (timer->expire_ms > now_ms)
                break;
            SLIST_REMOVE_HEAD(&group->timers, link);
            SLIST_INSERT_HEAD(&trig_list, timer, link);
        }
        SLIST_FOREACH_SAFE(timer, &trig_list, link, tmp) {
            SLIST_REMOVE_HEAD(&trig_list, link);
            if (timer->period_ms) {
                if (timer->expire_ms + timer->period_ms < now_ms)
                    WARN_ON("periodic timer overrun");
                timer_start(group, timer, timer->expire_ms + timer->period_ms);
            } else {
                timer_reset(timer);
            }
            // WARN: timer->callback() is allowed to free(timer)
            if (timer->callback)
                timer->callback(group == &ctxt->group_default ? NULL : group, timer);
        }
    }
    timer_schedule();
}

void timer_group_init(struct timer_group *group)
{
    struct timer_ctxt *ctxt = timer_ctxt();

    SLIST_INIT(&group->timers);
    SLIST_INSERT_HEAD(&ctxt->groups, group, link);
}

void timer_start_abs(struct timer_group *group, struct timer_entry *timer, uint64_t expire_ms)
{
    timer_stop(group, timer);
    if (timer_start(group, timer, expire_ms))
        timer_schedule();
}

void timer_start_rel(struct timer_group *group, struct timer_entry *timer, uint64_t offset_ms)
{
    uint64_t start_ms = time_now_ms(CLOCK_MONOTONIC);

    timer_start_abs(group, timer, start_ms + offset_ms);
    // More accurate than what is set by timer_start_abs()
    timer->start_ms = start_ms;
}

void timer_stop(struct timer_group *group, struct timer_entry *timer)
{
    struct timer_ctxt *ctxt = timer_ctxt();
    bool reschedule;

    if (!timer->expire_ms)
        return;
    if (!group)
        group = &ctxt->group_default;
    reschedule = (timer == SLIST_FIRST(&group->timers));
    SLIST_REMOVE(&group->timers, timer, timer_entry, link);
    timer_reset(timer);
    if (reschedule)
        timer_schedule();
}
