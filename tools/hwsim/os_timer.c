/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "sl_wsrcp.h"
#include "common/os_types.h"
#include "common/slist.h"
#include "common/log.h"

#include "os_timer.h"

int os_timer_register(void (*timer_interrupt_handler)(int, uint16_t))
{
    struct callback_timer *item = calloc(1, sizeof(struct callback_timer));
    struct wsmac_ctxt *ctxt = &g_ctxt;

    item->fn = timer_interrupt_handler;
    item->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    FATAL_ON(item->fd < 0, 2);
    fcntl(item->fd, F_SETFL, O_NONBLOCK);
    slist_push(&ctxt->timers, &item->node);
    return item->fd;
}

int os_timer_unregister(int ns_timer_id)
{
    struct wsmac_ctxt *ctxt = &g_ctxt;
    struct callback_timer *item;

    close(ns_timer_id);
    item = SLIST_REMOVE(ctxt->timers, item, node, item->fd == ns_timer_id);
    BUG_ON(!item);
    return item->fd;
}

int os_timer_start(int ns_timer_id, uint16_t slots)
{
    int ret;
    int slots_us = 1000 * slots / TIMER_SLOTS_PER_MS;
    struct itimerspec timer = {
        .it_value.tv_sec = slots_us / 1000000,
        .it_value.tv_nsec = slots_us % 1000000 * 1000,
    };

    ret = timerfd_settime(ns_timer_id, 0, &timer, NULL);
    FATAL_ON(ret < 0, 2, "timerfd_settime: %m");
    return 0;
}

int os_timer_stop(int ns_timer_id)
{
    int ret;
    struct itimerspec timer = { };

    ret = timerfd_settime(ns_timer_id, 0, &timer, NULL);
    FATAL_ON(ret < 0, 2, "timerfd_settime: %m");
    return 0;
}
