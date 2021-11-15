/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define min(x, y) ({ \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x < _y ? _x : _y;  \
})

#define max(x, y) ({ \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    _x > _y ? _x : _y;  \
})

#define container_of(ptr, type, member)  (type *)((uintptr_t)(ptr) - ((uintptr_t)(&((type *)0)->member)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __bf_shf(mask))
#define FIELD_PREP(mask, val) (((val) << __bf_shf(mask)) & (mask))

#endif
