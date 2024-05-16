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
#ifndef MATHUTILS_H
#define MATHUTILS_H
#include <stdint.h>
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

#define POW2(n) (1ul << (n))

// 32bit addition with saturation
static inline uint32_t add32sat(uint32_t a, uint32_t b)
{
    uint32_t sum = a + b;

    return sum < a ? UINT32_MAX : sum;
}

#endif
