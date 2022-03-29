/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef OS_TIMER_H
#define OS_TIMER_H

#include <stdint.h>
#include "slist.h"

int eventOS_callback_timer_register(void (*timer_interrupt_handler)(int, uint16_t));
int eventOS_callback_timer_unregister(int ns_timer_id);

int eventOS_callback_timer_stop(int ns_timer_id);
int eventOS_callback_timer_start(int ns_timer_id, uint16_t slots);

// Must be a part of g_ctxt (see eventOS_callback_timer_register())
// FIXME: it is a bit ugly
struct callback_timer {
    int fd;
    void (*fn)(int, uint16_t);
    struct slist node;
};

#endif
