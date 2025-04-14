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
#ifndef RPL_LOLLIPOP_H
#define RPL_LOLLIPOP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "common/seqno.h"
#include "common/mathutils.h"
#include "common/memutils.h"

/*
 * RFC 6550 7.2. describes a special type of sequence number often described as
 * a "lollipop" counter. These are decomposed into an initial "linear" space,
 * followed by a "circular" space. This is meant to ease handling of device
 * reboots as they'll always end up in the linear part after a restart.
 *
 * The RPL specification uses a "unsigned" convention for lollipop counters:
 * - values in [128, 256) are in the linear region
 * - values in [0, 128) are in the circular region
 * But it is more convenient and clear to use a signed representation:
 * - values in [-128, 0) are in the linear region
 * - values in [0, 128) are in the circular region
 */

#define RPL_SEQUENCE_WINDOW 16
#define RPL_LOLLIPOP_INIT ((uint8_t)(-RPL_SEQUENCE_WINDOW))

// Sequence counter comparison, as defined in RFC 6550 section 7.2.
// Desynchonization should be verified beforehand using rpl_lollipop_desync().
//   <0 if a < b
//    0 if a = b
//   >0 if a > b
static inline int rpl_lollipop_cmp(uint8_t a, uint8_t b)
{
    int8_t sa = a;
    int8_t sb = b;

    if (sa <  0 && sb <  0) // Linear region
        return sa - sb;
    if (sa >= 0 && sb >= 0) // Circular region
        return seqno_cmp7(sa, sb);
    if (sa <  0 && sb >= 0) // Mixed
        return sb - sa <= RPL_SEQUENCE_WINDOW ? -1 :  1;
    else
        return sa - sb <= RPL_SEQUENCE_WINDOW ?  1 : -1;
}

static inline bool rpl_lollipop_desync(uint8_t a, uint8_t b)
{
    uint8_t distance;
    int8_t sa = a;
    int8_t sb = b;

    if ((sa < 0) != (sb < 0))
        return false;
    distance = abs(sb - sa);
    if (sa < 0 && sb < 0) // Linear region
        return distance > RPL_SEQUENCE_WINDOW;
    else                  // Circular region
        return MIN(distance, 128 - distance) > RPL_SEQUENCE_WINDOW;
}

static inline uint8_t rpl_lollipop_inc(uint8_t val)
{
    int8_t sval = val;

    return sval == INT8_MAX ? 0 : sval + 1;
}

#endif
