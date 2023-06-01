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
#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#include <stddef.h>

#define MIN(x, y) ({ \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x < _y ? _x : _y;  \
})

#define MAX(x, y) ({ \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x > _y ? _x : _y;  \
})

#define roundup(x, y) ({ \
    const typeof(y) __y = y;         \
    (((x) + (__y - 1)) / __y) * __y; \
})

#define rounddown(x, y) ({ \
    typeof(x) __x = (x); \
    __x - (__x % (y));   \
})

#define container_of(ptr, type, member) ({ \
   const typeof(((type *)0)->member) * _mptr = (ptr);   \
   (type *)((uintptr_t)_mptr - offsetof(type, member)); \
})

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif
