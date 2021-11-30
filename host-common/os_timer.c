/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <fcntl.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "os_timer.h"
#include "os_types.h"
#include "slist.h"
#include "log.h"

int8_t eventOS_callback_timer_register(void (*timer_interrupt_handler)(int8_t, uint16_t))
{
    struct callback_timer *item = calloc(1, sizeof(struct callback_timer));
    struct os_ctxt *ctxt = &g_os_ctxt;

    item->fn = timer_interrupt_handler;
    item->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    FATAL_ON(item->fd < 0, 2);
    FATAL_ON(item->fd > 255, 2);
    fcntl(item->fd, F_SETFL, O_NONBLOCK);
    slist_push(&ctxt->timers, &item->node);
    return item->fd;
}

int8_t eventOS_callback_timer_unregister(int8_t ns_timer_id)
{
    struct os_ctxt *ctxt = &g_os_ctxt;
    struct callback_timer *item;

    close(ns_timer_id);
    item = SLIST_REMOVE(ctxt->timers, item, node, item->fd == ns_timer_id);
    BUG_ON(!item);
    return item->fd;
}

int8_t eventOS_callback_timer_start(int8_t ns_timer_id, uint16_t slots)
{
    int ret;
    int slots_us = slots * 50;
    struct itimerspec timer = {
        .it_value.tv_sec = slots_us / 1000000,
        .it_value.tv_nsec = slots_us % 1000000 * 1000,
    };

    ret = timerfd_settime(ns_timer_id, 0, &timer, NULL);
    FATAL_ON(ret < 0, 2);
    return 0;
}

int8_t eventOS_callback_timer_stop(int8_t ns_timer_id)
{
    int ret;
    struct itimerspec timer = { };

    ret = timerfd_settime(ns_timer_id, 0, &timer, NULL);
    FATAL_ON(ret < 0, 2);
    return 0;
}
