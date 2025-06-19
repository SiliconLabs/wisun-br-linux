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

/*
 * Simple extra math operators. As for C operators, they return the same type
 * than their arguments (this is the reason why they are implemented with
 * macros). Names are usually self-describing.
 */

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

/*
 * Divide x by y and round to the upper integer (ceiling operation). Intended
 * for positive integer inputs. divdown() is the standard division operator on
 * integers.
 *   divup(3, 2) == 2
 *   divup(3, 3) == 1
 *   divup(3, 4) == 1
 */
#define divup(x, y) ({ \
    const typeof(y) __y = y; \
    ((x) + (__y - 1)) / __y; \
})

#define POW2(n) (1ul << (n))

// 32bit addition with saturation
static inline uint32_t add32sat(uint32_t a, uint32_t b)
{
    uint32_t sum = a + b;

    return sum < a ? UINT32_MAX : sum;
}

// 16bit addition with saturation
static inline uint16_t add16sat(uint16_t a, uint16_t b)
{
    uint16_t sum = a + b;

    return sum < a ? UINT16_MAX : sum;
}

#endif
