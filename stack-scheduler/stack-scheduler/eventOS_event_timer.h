/*
 * Copyright (c) 2014-2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef EVENTOS_EVENT_TIMER_H_
#define EVENTOS_EVENT_TIMER_H_
#include <stdint.h>
#include "stack-scheduler/eventOS_event.h"

/**
 * \file eventOS_event_timer.h
 * \ingroup nanostack-eventloop
 * \brief Functions for sending delayed events.
 */

struct arm_event_s;

/* Comparison macros handling wrap efficiently (assuming a conventional compiler
 * which converts 0x80000000 to 0xFFFFFFFF to negative when casting to int32_t).
 */
#define TICKS_AFTER(a, b) ((int32_t) ((a)-(b)) > 0)
#define TICKS_BEFORE(a, b) ((int32_t) ((a)-(b)) < 0)
#define TICKS_AFTER_OR_AT(a, b) ((int32_t) ((a)-(b)) >= 0)
#define TICKS_BEFORE_OR_AT(a, b) ((int32_t) ((a)-(b)) <= 0)

/**
 * Send an event after time expired (in milliseconds)
 *
 * Note that the current implementation has the "feature" that rounding
 * varies depending on the precise timing requested:
 *     0-20 ms => 2 x 10ms tick
 *    21-29 ms => 3 x 10ms tick
 *    30-39 ms => 4 x 10ms tick
 *    40-49 ms => 5 x 10ms tick
 *    ... etc
 *
 * \param event_id event_id for event
 * \param event_type event_type for event
 * \param tasklet_id receiver for event
 * \param time time to sleep in milliseconds
 *
 * \return 0 on success
 * \return -1 on error (invalid tasklet_id or allocation failure)
 *
 * */
int8_t eventOS_event_timer_request(uint8_t event_id, uint8_t event_type, int8_t tasklet_id, uint32_t time);

/**
 * Send an event periodically
 *
 * The event will be sent repeatedly using the specified ticks period.
 *
 * The first call is sent at
 *
 *          eventOS_event_timer_ticks() +  ticks
 *
 * Subsequent events will be sent at N*ticks from the initial time.
 *
 * Period will be maintained while the device is awake, regardless of delays to
 * event scheduling. If an event has not been delivered and completed by the
 * next scheduled time, the next event will be sent immediately when it
 * finishes. This could cause a continuous stream of events if unable to keep
 * up with the period.
 *
 * Can also be invoked using the eventOS_event_send_every() macro in eventOS_event.h
 *
 * \param event event to send
 * \param period period for event
 *
 * \return pointer to timer structure on success
 * \return NULL on error (invalid tasklet_id or allocation failure)
 *
 */
arm_event_storage_t *eventOS_event_timer_request_every(const struct arm_event_s *event, int32_t period);


#endif
