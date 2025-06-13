/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <stddef.h>

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

#define SLIST_FIND(var, head, field, cond) ({         \
    SLIST_FOREACH(var, head, field)                   \
        if (cond)                                     \
            break;                                    \
    var;                                              \
})

// SLIST_REMOVE() segfaults if the element does not exist in the list.
#define SLIST_REMOVE_SAFE(head, elm, field) do {      \
    typeof(SLIST_FIRST(head)) _prev, _it;             \
                                                      \
    for (_prev = NULL, _it = SLIST_FIRST(head); _it;  \
         _prev = _it, _it = SLIST_NEXT(_it, field))   \
        if (_it == (elm))                             \
            break;                                    \
    if (_it) {                                        \
        if (_prev)                                    \
            SLIST_NEXT(_prev, field) = SLIST_NEXT(_it, field); \
        else                                          \
            SLIST_REMOVE_HEAD(head, field);           \
    }                                                 \
} while (0)

#define SLIST_SIZE(head, field) ({                    \
    typeof(SLIST_FIRST(head)) _e;                     \
    size_t _c = 0;                                    \
                                                      \
    SLIST_FOREACH(_e, (head), field)                  \
        _c++;                                         \
    _c;                                               \
})

// This macro is provided by BSD but not glibc
#ifndef SLIST_FOREACH_SAFE
#define SLIST_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = SLIST_FIRST((head));                     \
         (var) && ((tvar) = SLIST_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

#endif
