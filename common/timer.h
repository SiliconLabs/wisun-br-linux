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
#ifndef COMMON_TIMER_H
#define COMMON_TIMER_H

#include <sys/queue.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Timer module backed by a single timerfd. A sorted list of timers is
 * maintained and the timerfd is always set to expire at the shortest timeout.
 *
 * Timer updates occur by calling timer_process() when the timer_fd() is ready,
 * which is typically queried using select() or poll().
 *
 * To use a timer, set timer.callback and call one of the timer_start_xxx()
 * functions. Timer structures are typically included as a member of a bigger
 * structure, which can be retrieved using container_of() when timer.callback()
 * is invoked.
 *
 * Timers are generally used in different independent modules, which each have
 * their own context. Retrieving the module context from the struct timer is not
 * always possible using container_of(), typically when the module has a list
 * of entries with each their own timer. To handle this issue, modules must
 * register themselves with timer_group_init(), which allows to retrieve module
 * context using container_of() on the struct timer_group from the callback.
 * A default timer group can be used by passing group as NULL for modules that
 * do not need this feature.
 *
 * Periodic timers can be implemented by explicitly calling timer_start_rel()
 * from the callback function, but for convenience timer.period_ms provides an
 * automatic restart mechanism when set.
 */

// Declare struct timer_list
SLIST_HEAD(timer_list, timer_entry);

struct timer_group {
    struct timer_list timers;
    SLIST_ENTRY(timer_group) link;
};

struct timer_entry {
    uint64_t period_ms;
    void (*callback)(struct timer_group *group, struct timer_entry *timer);

    // Internal fields
    uint64_t expire_ms;
    SLIST_ENTRY(timer_entry) link;
};

// File descriptor indicating when a timer event is ready to be processed.
int timer_fd(void);

// Should be called when timer_fd() is ready.
void timer_process(void);

// Should be called once per project submodule to register a new timer group.
void timer_group_init(struct timer_group *group);

// Start a timer using an absolute monotonic time.
void timer_start_abs(struct timer_group *group, struct timer_entry *timer, uint64_t expire_ms);

// Start a timer relative to the current time.
void timer_start_rel(struct timer_group *group, struct timer_entry *timer, uint64_t offset_ms);

// Stop a timer.
void timer_stop(struct timer_group *group, struct timer_entry *timer);

static inline bool timer_stopped(const struct timer_entry *timer)
{
    return !timer->expire_ms;
}

#endif
