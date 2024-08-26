/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "common/ns_list.h"
#include "common/log.h"
#include "common/memutils.h"

#include "events_scheduler.h"

struct events_scheduler *g_event_scheduler;

static struct event_tasklet *event_tasklet_handler_get(uint8_t tasklet_id)
{
    struct events_scheduler *ctxt = g_event_scheduler;

    BUG_ON(!ctxt);
    ns_list_foreach(struct event_tasklet, cur, &ctxt->event_tasklet_list) {
        if (cur->id == tasklet_id) {
            return cur;
        }
    }
    return NULL;
}

static int8_t event_tasklet_get_free_id(void)
{
    /*(Note use of uint8_t to avoid overflow if we reach 0x7F)*/
    for (uint8_t i = 0; i <= INT8_MAX; i++) {
        if (!event_tasklet_handler_get(i)) {
            return i;
        }
    }
    return -1;
}

int8_t event_handler_create(void (*handler_func_ptr)(struct event_payload *))
{
    struct events_scheduler *ctxt = g_event_scheduler;
    struct event_tasklet *new = zalloc(sizeof(struct event_tasklet));

    BUG_ON(!ctxt);
    new->id = event_tasklet_get_free_id();
    new->func_ptr = handler_func_ptr;
    ns_list_add_to_end(&ctxt->event_tasklet_list, new);

    return new->id;
}

int8_t event_send(const struct event_payload *event)
{
    struct events_scheduler *ctxt = g_event_scheduler;
    struct event_payload *event_dup;

    BUG_ON(!ctxt);
    if (!event_tasklet_handler_get(event->receiver))
        return -1;

    event_dup = xalloc(sizeof(struct event_payload));
    memcpy(event_dup, event, sizeof(struct event_payload));
    ns_list_add_to_end(&ctxt->event_queue, event_dup);
    event_scheduler_signal();
    return 0;
}

bool event_scheduler_dispatch_event(void)
{
    struct events_scheduler *ctxt = g_event_scheduler;
    struct event_payload *event = ns_list_get_first(&ctxt->event_queue);
    struct event_tasklet *tasklet;

    BUG_ON(!ctxt);
    if (!event)
        return false;
    ns_list_remove(&ctxt->event_queue, event);
    tasklet = event_tasklet_handler_get(event->receiver);
    if (tasklet) {
        tasklet->func_ptr(event);
    } else {
        WARN();
    }
    free(event);

    return true;
}

void event_scheduler_run_until_idle(void)
{
    while (event_scheduler_dispatch_event());
}

void event_scheduler_signal()
{
    struct events_scheduler *ctxt = g_event_scheduler;
    uint64_t val = 'W';

    write(ctxt->event_fd[1], &val, sizeof(val));
}

void event_scheduler_init(struct events_scheduler *ctxt)
{
    int ret;

    g_event_scheduler = ctxt;
    ret = pipe(ctxt->event_fd);
    FATAL_ON(ret < 0, 2,  "%s: pipe: %m", __func__);

    fcntl(ctxt->event_fd[1], F_SETPIPE_SZ, sizeof(uint64_t) * 2);
    fcntl(ctxt->event_fd[1], F_SETFL, O_NONBLOCK);

    ns_list_init(&ctxt->event_queue);
    ns_list_init(&ctxt->event_tasklet_list);
}
