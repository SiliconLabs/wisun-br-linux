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
#include <stdint.h>
#include <string.h>

#include "common/mathutils.h"

#include "bits.h"

void *bitfill(void *dst, bool val, size_t start, size_t end)
{
    uint8_t *dst8 = dst;
    int i;

    for (i = start; i <= end; i++)
        if (val)
            bitset(dst8, i);
        else
            bitclr(dst8, i);
    return dst;
}

void *bitcpy(void *dst, const void *src, size_t len)
{
    const uint8_t *src8 = src;
    uint8_t *dst8 = dst;
    int nb_bytes = len / 8;
    int nb_bits = len % 8;
    uint8_t mask = POW2(nb_bits) - 1;

    memcpy(dst8, src8, nb_bytes);
    if (!nb_bits)
        return dst;

    dst8 += nb_bytes;
    src8 += nb_bytes;
    *dst8 &= ~mask;
    *dst8 |= mask & *src8;
    return dst;
}

int bitcmp(const void *s1, const void *s2, size_t len)
{
    const uint8_t *s1_8 = s1;
    const uint8_t *s2_8 = s2;
    int nb_bytes = len / 8;
    int nb_bits = len % 8;
    uint8_t mask = POW2(nb_bits) - 1;
    int ret;

    ret = memcmp(s1, s2, nb_bytes);
    if (!nb_bits)
        return ret;
    if (nb_bytes && ret)
        return ret;

    s1_8 += nb_bytes;
    s2_8 += nb_bytes;
    return ((int) (*s1_8 & mask)) - ((int) (*s2_8 & mask));
}

bool bitcmp0(const void *s1, size_t len)
{
    const uint8_t *s1_8 = s1;
    int nb_bytes = len / 8;
    int nb_bits = len % 8;
    uint8_t mask = POW2(nb_bits) - 1;
    int i;

    for (i = 0; i < nb_bytes; i++)
        if (s1_8[i])
            return false;
    s1_8 += nb_bytes;
    if (*s1_8 & mask)
        return false;
    return true;
}

void bitand(uint8_t *dst, const uint8_t *src, int nbits)
{
    int nbytes = nbits / 8;

    for (int i = 0; i < nbytes; i++)
        dst[i] &= src[i];
}

bool bittest(const uint8_t *bits, int i)
{
    return bits[i / 8] & BIT(i % 8);
}

void bitset(uint8_t *bits, int i)
{
    bits[i / 8] |= BIT(i % 8);
}

void bitclr(uint8_t *bits, int i)
{
    bits[i / 8] &= ~BIT(i % 8);
}
