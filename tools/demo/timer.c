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
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <poll.h>

#include "common/log.h"
#include "common/memutils.h"
#include "common/timer.h"

struct module {
    uint64_t delay_ms;
    int      ticks;
    struct timer_entry *timer_tmp;
    struct timer_group timer_group;
};

static void timer_recursive(void *arg)
{
    /*
     * Linux typically has 8Mio of stack per process so a couple recusive calls
     * would normally create a stack overflow.
     */
    uint8_t buf[1024 * 1024];
    int *i = arg;

    if (*i < 0)
        return;

    buf[*i] = *i; // Use buf to prevent optimization
    printf("%s() %i\n", __func__, buf[*i]);

    *i = *i - 1;
    //timer_call(i);
    timer_call_later(timer_recursive, i, sizeof(int));
}

void timer_cb(struct timer_group *group, struct timer_entry *timer)
{
    printf("%s() %"PRIu64"ms\n", __func__, timer->period_ms);
}

void timer_cb_exp(struct timer_group *group, struct timer_entry *timer)
{
    struct module *mod = container_of(group, struct module, timer_group);

    printf("%s() %"PRIu64"ms\n", __func__, mod->delay_ms);
    timer_start_rel(group, timer, mod->delay_ms *= 2);
}

void timer_cb_rand(struct timer_group *group, struct timer_entry *timer)
{
    uint64_t offset_ms = ((double)rand() / RAND_MAX) * 5000;

    printf("%s() next in %"PRIu64"ms\n", __func__, offset_ms);
    timer_start_rel(group, timer, offset_ms);
}

void timer_cb_del(struct timer_group *group, struct timer_entry *timer)
{
    struct module *mod = container_of(group, struct module, timer_group);

    printf("%s()\n", __func__);
    free(timer);

    timer_stop(&mod->timer_group, mod->timer_tmp);
    free(mod->timer_tmp);
}

void timer_cb_del_ticks(struct timer_group *group, struct timer_entry *timer)
{
    struct module *mod = container_of(group, struct module, timer_group);

    mod->ticks++;
    printf("%s() ticks=%i\n", __func__, mod->ticks);

    if (mod->ticks == 10) {
        printf("%s() del\n", __func__);
        timer_stop(group, timer);
        free(timer);
    }
}

int main()
{
    struct module mod = {
        .delay_ms = 1,
    };
    struct pollfd pfd = { };
    struct timer_entry timer_500ms = {
        .period_ms = 500,
        .callback = timer_cb,
    };
    struct timer_entry timer_666ms = {
        .period_ms = 666,
        .callback = timer_cb,
    };
    struct timer_entry timer_exp = {
        .callback = timer_cb_exp,
    };
    struct timer_entry timer_rand = {
        .callback = timer_cb_rand,
    };
    struct timer_entry *timer_del;
    struct timer_entry *timer_del_ticks;
    int ret;

    srand(0);

    pfd.fd = timer_fd();
    pfd.events = POLLIN;

    timer_group_init(&mod.timer_group);

    timer_call_later(timer_recursive, (int[]){ 10 }, sizeof(int));

    timer_start_rel(NULL, &timer_500ms, timer_500ms.period_ms);
    timer_start_rel(NULL, &timer_666ms, timer_666ms.period_ms);
    timer_start_rel(&mod.timer_group, &timer_exp, 0);
    timer_start_rel(NULL, &timer_rand, 0);

    timer_del = zalloc(sizeof(struct timer_entry));
    timer_del->callback = timer_cb_del;
    timer_start_rel(&mod.timer_group, timer_del, 500);

    mod.timer_tmp = zalloc(sizeof(struct timer_entry));
    mod.timer_tmp->period_ms = 100;
    mod.timer_tmp->callback = timer_cb;
    timer_start_rel(&mod.timer_group, mod.timer_tmp, mod.timer_tmp->period_ms);

    timer_del_ticks = zalloc(sizeof(struct timer_entry));
    timer_del_ticks->period_ms = 200;
    timer_del_ticks->callback = timer_cb_del_ticks;
    timer_start_rel(&mod.timer_group, timer_del_ticks, timer_del_ticks->period_ms);

    while (1) {
        ret = poll(&pfd, 1, -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (pfd.revents & POLLIN)
            timer_process();
    }
}
