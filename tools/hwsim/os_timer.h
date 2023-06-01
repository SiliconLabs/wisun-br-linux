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
#ifndef OS_TIMER_H
#define OS_TIMER_H

#include <stdint.h>
#include "common/slist.h"

#define TIMER_SLOTS_PER_MS 20

int os_timer_register(void (*timer_interrupt_handler)(int, uint16_t));
int os_timer_unregister(int ns_timer_id);

int os_timer_stop(int ns_timer_id);
int os_timer_start(int ns_timer_id, uint16_t slots);

// Must be a part of g_ctxt (see os_timer_register())
// FIXME: it is a bit ugly
struct callback_timer {
    int fd;
    void (*fn)(int, uint16_t);
    struct slist node;
};

#endif
