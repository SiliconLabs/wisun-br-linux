/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SYS_QUEUE_EXTRA_H
#define SYS_QUEUE_EXTRA_H

#include <sys/queue.h>

/*
 * Provide some non-standard extensions to sys/queue.h.
 *
 * These functions keep the same name and call conventions as sys/queue.h.
 */

#define SLIST_POP(head, field) ({                     \
    typeof(SLIST_FIRST(head)) _e = SLIST_FIRST(head); \
                                                      \
    if (_e)                                           \
        SLIST_REMOVE_HEAD((head), field);             \
    _e;                                               \
})

#endif
