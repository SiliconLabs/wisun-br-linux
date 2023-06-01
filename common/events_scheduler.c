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
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include "common/ns_list.h"
#include "common/log.h"

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

static void event_core_write(struct event_storage *event)
{
    struct events_scheduler *ctxt = g_event_scheduler;

    BUG_ON(!ctxt);
    event->state = ARM_LIB_EVENT_QUEUED;
    ns_list_foreach(struct event_storage, event_tmp, &ctxt->event_queue) {
        if (event_tmp->data.priority > event->data.priority) {
            ns_list_add_before(&ctxt->event_queue, event_tmp, event);
            event_scheduler_signal();
            return;
        }
    }
    ns_list_add_to_end(&ctxt->event_queue, event);
    event_scheduler_signal();
}

int8_t event_handler_create(void (*handler_func_ptr)(struct event_payload *), uint8_t init_event_type)
{
    struct events_scheduler *ctxt = g_event_scheduler;
    struct event_storage *event_tmp = malloc(sizeof(struct event_storage));
    struct event_tasklet *new = malloc(sizeof(struct event_tasklet));

    BUG_ON(!ctxt);
    new->id = event_tasklet_get_free_id();
    new->func_ptr = handler_func_ptr;
    ns_list_add_to_end(&ctxt->event_tasklet_list, new);

    event_tmp->allocator = ARM_LIB_EVENT_DYNAMIC;
    event_tmp->data.data_ptr = NULL;
    event_tmp->data.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    event_tmp->data.receiver = new->id;
    event_tmp->data.sender = 0;
    event_tmp->data.event_type = init_event_type;
    event_tmp->data.event_id = 0;
    event_tmp->data.event_data = 0;
    event_core_write(event_tmp);

    return new->id;
}

int8_t event_send(const struct event_payload *event)
{
    struct event_storage *event_tmp;

    if (!event_tasklet_handler_get(event->receiver))
        return -1;

    event_tmp = malloc(sizeof(struct event_storage));
    event_tmp->allocator = ARM_LIB_EVENT_DYNAMIC;
    memcpy(&event_tmp->data, event, sizeof(struct event_payload));
    event_core_write(event_tmp);
    return 0;
}

void event_send_user_allocated(struct event_storage *event)
{
    event->allocator = ARM_LIB_EVENT_USER;
    event_core_write(event);
}

void event_cancel(struct event_storage *event)
{
    struct events_scheduler *ctxt = g_event_scheduler;

    BUG_ON(!ctxt);
    if (!event)
        return;

    /*
     * Remove event from the list,
     * Only queued can be removed, unqued are either timers or stale pointers
     * RUNNING cannot be removed, we are currenly "in" that event.
     */
    if (event->state == ARM_LIB_EVENT_QUEUED)
        ns_list_remove(&ctxt->event_queue, event);

    if (event->state != ARM_LIB_EVENT_RUNNING)
        if (event->allocator ==  ARM_LIB_EVENT_DYNAMIC)
            free(event);
}

int8_t event_scheduler_get_active_tasklet(void)
{
    struct events_scheduler *ctxt = g_event_scheduler;

    return ctxt->curr_tasklet;
}

void event_scheduler_set_active_tasklet(int8_t tasklet)
{
    struct events_scheduler *ctxt = g_event_scheduler;

    ctxt->curr_tasklet = tasklet;
}

bool event_scheduler_dispatch_event(void)
{
    struct events_scheduler *ctxt = g_event_scheduler;
    struct event_storage *event = ns_list_get_first(&ctxt->event_queue);
    struct event_tasklet *tasklet;

    BUG_ON(!ctxt);
    ctxt->curr_tasklet = 0;
    if (!event)
        return false;
    ns_list_remove(&ctxt->event_queue, event);
    ctxt->curr_tasklet = event->data.receiver;
    tasklet = event_tasklet_handler_get(ctxt->curr_tasklet);
    if (tasklet) {
        event->state = ARM_LIB_EVENT_RUNNING;
        tasklet->func_ptr(&event->data);
    } else {
        WARN();
    }
    event->state = ARM_LIB_EVENT_UNQUEUED;
    if (event->allocator == ARM_LIB_EVENT_DYNAMIC)
        free(event);
    ctxt->curr_tasklet = 0;

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
    g_event_scheduler = ctxt;
    pipe(ctxt->event_fd);
    fcntl(ctxt->event_fd[1], F_SETPIPE_SZ, sizeof(uint64_t) * 2);
    fcntl(ctxt->event_fd[1], F_SETFL, O_NONBLOCK);

    ns_list_init(&ctxt->event_queue);
    ns_list_init(&ctxt->event_tasklet_list);
}
