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
#ifndef EVENTS_SCHEDULER_H
#define EVENTS_SCHEDULER_H
#include <stdbool.h>
#include <stdint.h>

#include "common/ns_list.h"

struct event_payload {
    int8_t receiver;    /* Tasklet ID */
    uint8_t event_id;
    void *data_ptr;
    ns_list_link_t link;
};

struct event_tasklet {
    int8_t id;
    void (*func_ptr)(struct event_payload *);
    ns_list_link_t link;
};

struct events_scheduler {
    int event_fd[2];
    NS_LIST_HEAD(struct event_tasklet, link) event_tasklet_list;
    NS_LIST_HEAD(struct event_payload, link) event_queue;
};

/**
 * \brief Initialise event scheduler.
 *
 */
void event_scheduler_init(struct events_scheduler *ctxt);

/**
 * Process one event from event queue.
 * Do not call this directly from application. Requires to be public so that simulator can call this.
 * Use event_scheduler_run() or event_scheduler_run_until_idle().
 * \return true If there was event processed, false if the event queue was empty.
 */
bool event_scheduler_dispatch_event(void);

/**
 * \brief Process events until no more events to process.
 */
void event_scheduler_run_until_idle(void);

/**
 * \brief This function will be called when stack receives an event.
 */
void event_scheduler_signal(void);

/**
 * \brief Send event to event scheduler.
 *
 * \param event pointer to pushed event.
 *
 * Event data is copied by the call, and this copy persists until the
 * recipient's callback function returns. The callback function is passed
 * a pointer to a copy of the data, not the original pointer.
 *
 * \return 0 Event push OK
 * \return -1 Memory allocation Fail
 */
int8_t event_send(const struct event_payload *event);

/**
 * \brief Event handler callback register
 *
 * Function will register and allocate unique event id handler
 *
 * \param handler_func_ptr function pointer for event handler
 * \param init_event_type generated event type for init purpose
 *
 * \return >= 0 Unique event ID for this handler
 * \return < 0 Register fail
 *
 * */
int8_t event_handler_create(void (*handler_func_ptr)(struct event_payload *));

#endif
