/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef BITS_H
#define BITS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define __CTZ(value) __builtin_ctz(value)
#define FIELD_GET(mask, reg) (((reg) & (mask)) >> __CTZ(mask))
#define FIELD_PREP(mask, val) (((val) << __CTZ(mask)) & (mask))

void *bitfill(void *dst, bool val, size_t start, size_t end);
void *bitcpy(void *dst, const void *src, size_t len);
void *bitcpy0(void *dst, const void *src, size_t len);
int bitcmp(const void *s1, const void *s2, size_t len);
bool bitcmp0(const void *s1, size_t len);
void bitand(uint8_t *dst, const uint8_t *src, int nbits);
int bitcnt(const uint8_t *bits, int nbits);
bool bittest(const uint8_t *bits, int i);
void bitset(uint8_t *bits, int i);
void bitclr(uint8_t *bits, int i);

#endif
