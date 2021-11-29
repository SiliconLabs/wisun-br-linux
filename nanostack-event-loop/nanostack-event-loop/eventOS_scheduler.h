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
#ifndef EVENTOS_SCHEDULER_H_
#define EVENTOS_SCHEDULER_H_
#include <stdint.h>
#include <stdbool.h>

/**
 * \file eventOS_scheduler.h
 * \ingroup nanostack-eventloop
 * \brief Event scheduler's control functions.
 */

/* Compatibility with older ns_types.h */
#ifndef NS_NORETURN
#define NS_NORETURN
#endif

/**
 * \brief Initialise event scheduler.
 *
 */
extern void eventOS_scheduler_init(void);

/**
 * Process one event from event queue.
 * Do not call this directly from application. Requires to be public so that simulator can call this.
 * Use eventOS_scheduler_run() or eventOS_scheduler_run_until_idle().
 * \return true If there was event processed, false if the event queue was empty.
 */
bool eventOS_scheduler_dispatch_event(void);

/**
 * \brief Process events until no more events to process.
 */
extern void eventOS_scheduler_run_until_idle(void);

/**
 * \brief Read current active Tasklet ID
 *
 * This function not return valid information called inside interrupt
 *
 * \return curret active tasklet id
 *
 * */
extern int8_t eventOS_scheduler_get_active_tasklet(void);

/**
 * \brief Set manually Active Tasklet ID
 *
 * \param tasklet requested tasklet ID
 *
 * */
extern  void eventOS_scheduler_set_active_tasklet(int8_t tasklet);

/**
 * \brief This function will be called when stack receives an event.
 */
extern void eventOS_scheduler_signal(void);

#endif /* EVENTOS_SCHEDULER_H_ */
