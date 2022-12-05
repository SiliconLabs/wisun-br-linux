/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include "common/hal_interrupt.h"
#include "common/ns_list.h"

#include "os_scheduler.h"
#include "os_types.h"
#include "log.h"

typedef struct arm_core_tasklet {
    int8_t id; /**< Event handler Tasklet ID */
    void (*func_ptr)(arm_event_t *);
    ns_list_link_t link;
} arm_core_tasklet_t;

static NS_LIST_DEFINE(arm_core_tasklet_list, arm_core_tasklet_t, link);
static NS_LIST_DEFINE(event_queue_active, arm_event_storage_t, link);

/** Curr_tasklet tell to core and platform which task_let is active, Core Update this automatic when switch Tasklet. */
int8_t curr_tasklet = 0;


static void event_core_write(arm_event_storage_t *event);

static arm_core_tasklet_t *event_tasklet_handler_get(uint8_t tasklet_id)
{
    ns_list_foreach(arm_core_tasklet_t, cur, &arm_core_tasklet_list) {
        if (cur->id == tasklet_id) {
            return cur;
        }
    }
    return NULL;
}

bool event_tasklet_handler_id_valid(uint8_t tasklet_id)
{
    return event_tasklet_handler_get(tasklet_id);
}

// XXX this can return 0, but 0 seems to mean "none" elsewhere? Or at least
// curr_tasklet is reset to 0 in various places.
static int8_t tasklet_get_free_id(void)
{
    /*(Note use of uint8_t to avoid overflow if we reach 0x7F)*/
    for (uint8_t i = 0; i <= INT8_MAX; i++) {
        if (!event_tasklet_handler_get(i)) {
            return i;
        }
    }
    return -1;
}


int8_t eventOS_event_handler_create(void (*handler_func_ptr)(arm_event_t *), uint8_t init_event_type)
{
    arm_event_storage_t *event_tmp = malloc(sizeof(arm_event_storage_t));
    arm_core_tasklet_t *new = malloc(sizeof(arm_core_tasklet_t));

    new->id = tasklet_get_free_id();
    new->func_ptr = handler_func_ptr;
    ns_list_add_to_end(&arm_core_tasklet_list, new);

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

int8_t eventOS_event_send(const arm_event_t *event)
{
    arm_event_storage_t *event_tmp;

    if (!event_tasklet_handler_get(event->receiver))
        return -1;

    event_tmp = malloc(sizeof(arm_event_storage_t));
    event_tmp->allocator = ARM_LIB_EVENT_DYNAMIC;
    memcpy(&event_tmp->data, event, sizeof(arm_event_t));
    event_core_write(event_tmp);
    return 0;
}

void eventOS_event_send_user_allocated(arm_event_storage_t *event)
{
    event->allocator = ARM_LIB_EVENT_USER;
    event_core_write(event);
}

void eventOS_event_cancel(arm_event_storage_t *event)
{
    if (!event) {
        return;
    }

    platform_enter_critical();

    /*
     * Remove event from the list,
     * Only queued can be removed, unqued are either timers or stale pointers
     * RUNNING cannot be removed, we are currenly "in" that event.
     */
    if (event->state == ARM_LIB_EVENT_QUEUED)
        ns_list_remove(&event_queue_active, event);

    if (event->state != ARM_LIB_EVENT_RUNNING)
        if (event->allocator ==  ARM_LIB_EVENT_DYNAMIC)
            free(event);

    platform_exit_critical();
}

void event_core_write(arm_event_storage_t *event)
{
    platform_enter_critical();
    bool added = false;
    ns_list_foreach(arm_event_storage_t, event_tmp, &event_queue_active) {
        // note enum ordering means we're checking if event_tmp is LOWER priority than event
        if (event_tmp->data.priority > event->data.priority) {
            ns_list_add_before(&event_queue_active, event_tmp, event);
            added = true;
            break;
        }
    }
    if (!added) {
        ns_list_add_to_end(&event_queue_active, event);
    }
    event->state = ARM_LIB_EVENT_QUEUED;

    /* Wake From Idle */
    platform_exit_critical();
    eventOS_scheduler_signal();
}

// Requires lock to be held
arm_event_storage_t *eventOS_event_find_by_id_critical(uint8_t tasklet_id, uint8_t event_id)
{
    ns_list_foreach(arm_event_storage_t, cur, &event_queue_active) {
        if (cur->data.receiver == tasklet_id && cur->data.event_id == event_id) {
            return cur;
        }
    }

    return NULL;
}

int8_t eventOS_scheduler_get_active_tasklet(void)
{
    return curr_tasklet;
}

void eventOS_scheduler_set_active_tasklet(int8_t tasklet)
{
    curr_tasklet = tasklet;
}

/**
 *
 * \brief Infinite Event Read Loop.
 *
 * Function Read and handle Cores Event and switch/enable tasklet which are event receiver. WhenEvent queue is empty it goes to sleep
 *
 */
bool eventOS_scheduler_dispatch_event(void)
{
    arm_event_storage_t *cur_event = ns_list_get_first(&event_queue_active);
    curr_tasklet = 0;

    if (!cur_event)
        return false;

    ns_list_remove(&event_queue_active, cur_event);
    curr_tasklet = cur_event->data.receiver;

    arm_core_tasklet_t *tasklet = event_tasklet_handler_get(curr_tasklet);
    /* Do not bother with check for NULL - tasklets cannot be deleted,
     * and user-facing API eventOS_event_send() has already checked the tasklet
     * exists, so there is no possible issue there.
     *
     * For eventOS_event_send_user_allocated(), it would be a non-recoverable
     * error to not deliver the message - we have to have a receiver to pass
     * ownership to. If the lookup fails, let it crash. We want the send call
     * itself to return void to simplify logic.
     */

    cur_event->state = ARM_LIB_EVENT_RUNNING;
    /* Tasklet Scheduler Call */
    tasklet->func_ptr(&cur_event->data);
    if (cur_event->allocator == ARM_LIB_EVENT_DYNAMIC)
        free(cur_event);

    /* Set Current Tasklet to Idle state */
    curr_tasklet = 0;

    return true;
}

void eventOS_scheduler_run_until_idle(void)
{
    while (eventOS_scheduler_dispatch_event());
}

void eventOS_scheduler_signal(void)
{
    struct os_ctxt *ctxt = &g_os_ctxt;
    uint64_t val = 'W';

    write(ctxt->event_fd[1], &val, sizeof(val));
}

void eventOS_scheduler_init(struct os_ctxt *ctxt)
{
    pipe(ctxt->event_fd);
    fcntl(ctxt->event_fd[1], F_SETPIPE_SZ, sizeof(uint64_t) * 2);
    fcntl(ctxt->event_fd[1], F_SETFL, O_NONBLOCK);

    ns_list_init(&event_queue_active);
    ns_list_init(&arm_core_tasklet_list);

    /* Set Tasklett switcher to Idle */
    curr_tasklet = 0;
}
