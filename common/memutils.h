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
#ifndef MEMUTILS_H
#define MEMUTILS_H
#include <stddef.h>
#include "common/log.h"
/*
 * Common functions related to the memory management.
 */


/*
 * Commonly used macro that return number elements in a array.
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))


/*
 * Allow to retrieve the address to the outer structure from the address of one
 * field. Among the usages, it can be wisely used with callbacks:
 *
 *   module.h:
 *
 *       struct module {
 *           void (*callback)(struct module *);
 *       };
 *
 *   main.c:
 *
 *       #include "module.h"
 *
 *       struct main {
 *           struct module field;
 *       };
 *
 *       void my_callback(struct module *arg)
 *       {
 *           struct main *main_struct = container_of(arg, struct main, field);
 *           [...]
 *       }
 *
 * Thus, main_callback() can nicely retrieve main_struct and module.h does not
 * have any knowledge about struct main.
 */
#define container_of(ptr, type, member) ({ \
    const typeof(((type *)0)->member) * _mptr = (ptr);   \
    (type *)((uintptr_t)_mptr - offsetof(type, member)); \
})

#endif
