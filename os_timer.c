/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <unistd.h>
#include <sys/timerfd.h>

#include "os_timer.h"

int8_t eventOS_callback_timer_register(void (*timer_interrupt_handler)(int8_t, uint16_t))
{
    return timerfd_create(CLOCK_MONOTONIC, 0);
}

int8_t eventOS_callback_timer_unregister(int8_t ns_timer_id)
{
    return close(ns_timer_id);
}

int8_t eventOS_callback_timer_start(int8_t ns_timer_id, uint16_t slots)
{
    int slots_us = slots * 50;
    struct itimerspec timer = {
        .it_value.tv_sec = slots_us / 1000000,
        .it_value.tv_nsec = slots_us % 1000000 * 1000,
    };

    timerfd_settime(ns_timer_id, 0, &timer, NULL);
    return 0;
}

int8_t eventOS_callback_timer_stop(int8_t ns_timer_id)
{
    struct itimerspec timer = { };

    timerfd_settime(ns_timer_id, 0, &timer, NULL);
    return 0;
}
