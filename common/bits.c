/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdint.h>
#include <string.h>
#include "bits.h"

void *bitfill(void *dst, bool val, size_t start, size_t end)
{
    uint8_t *dst8 = dst;
    int i;

    for (i = start; i <= end; i++)
        if (val)
            dst8[i / 8] |= 1u << (i % 8);
        else
            dst8[i / 8] &= ~(1u << (i % 8));
    return dst;
}

void *bitcpy(void *dst, const void *src, size_t len)
{
    const uint8_t *src8 = src;
    uint8_t *dst8 = dst;
    int nb_bytes = len / 8;
    int nb_bits = len % 8;
    uint8_t mask = (1u << nb_bits) - 1;

    memcpy(dst8, src8, nb_bytes);
    if (!nb_bits)
        return dst;

    dst8 += nb_bytes;
    src8 += nb_bytes;
    *dst8 &= ~mask;
    *dst8 |= mask & *src8;
    return dst;
}

void *bitcpy0(void *dst, const void *src, size_t len)
{
    const uint8_t *src8 = src;
    uint8_t *dst8 = dst;
    int nb_bytes = len / 8;
    int nb_bits = len % 8;
    uint8_t mask = (1u << nb_bits) - 1;

    memcpy(dst8, src8, nb_bytes);
    if (!nb_bits)
        return dst;

    dst8 += nb_bytes;
    src8 += nb_bytes;
    *dst8 = mask & *src8;
    return dst;
}

int bitcmp(const void *s1, const void *s2, size_t len)
{
    const uint8_t *s1_8 = s1;
    const uint8_t *s2_8 = s2;
    int nb_bytes = len / 8;
    int nb_bits = len % 8;
    uint8_t mask = (1u << nb_bits) - 1;
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
