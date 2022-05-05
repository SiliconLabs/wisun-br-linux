/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef BITS_H
#define BITS_H

#include  <stddef.h>

#define __CTZ(value) __builtin_ctz(value)
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __CTZ(mask))
#define FIELD_PREP(mask, val) (((val) << __CTZ(mask)) & (mask))

void *bitset(void *dst, int c, size_t len);
void *bitcpy(void *dst, const void *src, size_t len);
void *bitcpy0(void *dst, const void *src, size_t len);
int bitcmp(const void *s1, const void *s2, size_t len);

#endif
