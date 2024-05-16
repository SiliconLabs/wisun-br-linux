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
#ifndef COMMON_BITS_H
#define COMMON_BITS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Provide in fact two different APIs:
 *   - FIELD_*()
 *   - bit*()
 */

/*
 * FIELD_GET() and FIELD_PREP() are macros make access to bit fields easy. The
 * caller just provide the mask. The macros automatically compute the necessary
 * shift. This makes the definition of bit fields more terse.
 *
 * There is no FIELD_SET() macro (a macro that change it arguments lead to
 * questions during when developer read the code). The proposed way to set bits
 * are:
 *
 *   var &= ~MASK;
 *   var |= FIELD_PREP(val, mask);
 *
 * or (more usual finally):
 *
 *   var = 0;
 *   var |= FIELD_PREP(val1, mask2);
 *   var |= FIELD_PREP(val2, mask2);
 */
#define __CTZ(value) __builtin_ctz(value)
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __CTZ(mask))
#define FIELD_PREP(mask, val) (((val) << __CTZ(mask)) & (mask))
#define FIELD_MAX(mask) ((mask) >> __CTZ(mask))

#define BIT(n) (1ul << (n))

/*
 * Functions bit*() allow to work on array of bytes. So they can work on bits
 * > 64. In these functions, start, end, i, etc... are always expressed as a
 * number of bits (1 bytes == 8 bits).
 *
 * No boundary check are not done by these functions. Some of them take
 * the number of bit as argument, but only because they need it.
 * bitcpy() and bitcmp() mimics the behavior of memcpy() and memcmp().
 */
void *bitfill(void *dst, bool val, size_t start, size_t end);
void *bitcpy(void *dst, const void *src, size_t nbits);
void *bitcpy0(void *dst, const void *src, size_t nbits);
int bitcmp(const void *s1, const void *s2, size_t nbits);
bool bitcmp0(const void *s1, size_t len);
void bitand(uint8_t *dst, const uint8_t *src, int nbits);
bool bittest(const uint8_t *bits, int i);
void bitset(uint8_t *bits, int i);
void bitclr(uint8_t *bits, int i);

#endif
