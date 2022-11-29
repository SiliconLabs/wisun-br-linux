/*
 * Copyright (c) 2014-2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef COMMON_FUNCTIONS_H_
#define COMMON_FUNCTIONS_H_
#include <stdint.h>
#include <stdbool.h>
#include "common/int24.h"

/*
 * Count bits in a byte
 *
 * \param value byte to inspect
 *
 * \return number of 1-bits in byte
 */
inline uint_fast8_t common_count_bits(uint8_t value);

/*
 * Count leading zeros in a byte
 *
 * \deprecated Use common_count_leading_zeros_8
 *
 * \param value byte to inspect
 *
 * \return number of leading zeros in byte (0-8)
 */
inline uint_fast8_t common_count_leading_zeros(uint8_t value);

/*
 * Count leading zeros in a byte
 *
 * \param value byte to inspect
 *
 * \return number of leading zeros in byte (0-8)
 */
inline uint_fast8_t common_count_leading_zeros_8(uint8_t value);

/*
 * Count leading zeros in a 16-bit value
 *
 * \param value value to inspect
 *
 * \return number of leading zeros in byte (0-16)
 */
inline uint_fast8_t common_count_leading_zeros_16(uint16_t value);

/*
 * Count leading zeros in a 32-bit value
 *
 * \param value value to inspect
 *
 * \return number of leading zeros in byte (0-32)
 */
inline uint_fast8_t common_count_leading_zeros_32(uint32_t value);

/*
 * Compare 8-bit serial numbers
 *
 * Compare two 8-bit serial numbers, according to RFC 1982 Serial Number
 * Arithmetic.
 *
 * \param s1 first serial number
 * \param s2 second serial number
 *
 * \return true if s1 > s2
 * \return false if s1 <= s2, or the comparison is undefined
 */
inline bool common_serial_number_greater_8(uint8_t s1, uint8_t s2);

/*
 * Compare 16-bit serial numbers
 *
 * Compare two 16-bit serial numbers, according to RFC 1982 Serial Number
 * Arithmetic.
 *
 * \param s1 first serial number
 * \param s2 second serial number
 *
 * \return true if s1 > s2
 * \return false if s1 <= s2, or the comparison is undefined
 */
inline bool common_serial_number_greater_16(uint16_t s1, uint16_t s2);

/*
 * Compare 32-bit serial numbers
 *
 * Compare two 32-bit serial numbers, according to RFC 1982 Serial Number
 * Arithmetic.
 *
 * \param s1 first serial number
 * \param s2 second serial number
 *
 * \return true if s1 > s2
 * \return false if s1 <= s2, or the comparison is undefined
 */
inline bool common_serial_number_greater_32(uint32_t s1, uint32_t s2);

/* Provide definitions, either for inlining, or for common_functions.c */
#ifndef COMMON_FUNCTIONS_FN
#define COMMON_FUNCTIONS_FN inline
#endif

COMMON_FUNCTIONS_FN uint_fast8_t common_count_bits(uint8_t value)
{
    /* First step sets each bit pair to be count of bits (00,01,10) */
    /* [00-00 = 00, 01-00 = 01, 10-01 = 01, 11-01 = 10] */
    uint_fast8_t count = value - ((value >> 1) & 0x55);
    /* Add bit pairs to make each nibble contain count of bits (0-4) */
    count = (count & 0x33) + ((count >> 2) & 0x33);
    /* Final result is sum of nibbles (0-8) */
    count = (count >> 4) + (count & 0x0F);
    return count;
}

COMMON_FUNCTIONS_FN uint_fast8_t common_count_leading_zeros(uint8_t value)
{
    return common_count_leading_zeros_8(value);
}

COMMON_FUNCTIONS_FN uint_fast8_t common_count_leading_zeros_8(uint8_t value)
{
#if defined __GNUC__
    return value ? __builtin_clz((unsigned int) value << 24) : 8;
#else
    uint_fast8_t cnt = 0;
    if (value == 0) {
        return 8;
    }
    if ((value & 0xF0) == 0) {
        value <<= 4;
        cnt += 4;
    }
    if ((value & 0xC0) == 0) {
        value <<= 2;
        cnt += 2;
    }
    if ((value & 0x80) == 0) {
        cnt += 1;
    }

    return cnt;
#endif
}

COMMON_FUNCTIONS_FN uint_fast8_t common_count_leading_zeros_16(uint16_t value)
{
#if defined __GNUC__
    return value ? __builtin_clz((unsigned int) value << 16) : 16;
#else
    uint_fast8_t cnt = 0;
    if (value == 0) {
        return 16;
    }
    if ((value & 0xFF00) == 0) {
        value <<= 8;
        cnt += 8;
    }
    if ((value & 0xF000) == 0) {
        value <<= 4;
        cnt += 4;
    }
    if ((value & 0xC000) == 0) {
        value <<= 2;
        cnt += 2;
    }
    if ((value & 0x8000) == 0) {
        cnt += 1;
    }

    return cnt;
#endif
}

COMMON_FUNCTIONS_FN uint_fast8_t common_count_leading_zeros_32(uint32_t value)
{
#if defined __GNUC__
    return value ? __builtin_clz(value) : 32;
#else
    uint_fast8_t cnt = 0;
    if (value == 0) {
        return 32;
    }
    if ((value & 0xFFFF0000) == 0) {
        value <<= 16;
        cnt += 16;
    }
    if ((value & 0xFF000000) == 0) {
        value <<= 8;
        cnt += 8;
    }
    if ((value & 0xF0000000) == 0) {
        value <<= 4;
        cnt += 4;
    }
    if ((value & 0xC0000000) == 0) {
        value <<= 2;
        cnt += 2;
    }
    if ((value & 0x80000000) == 0) {
        cnt += 1;
    }

    return cnt;
#endif
}

COMMON_FUNCTIONS_FN bool common_serial_number_greater_8(uint8_t s1, uint8_t s2)
{
    return (s1 > s2 && s1 - s2 < UINT8_C(0x80)) || (s1 < s2 && s2 - s1 > UINT8_C(0x80));
}

COMMON_FUNCTIONS_FN bool common_serial_number_greater_16(uint16_t s1, uint16_t s2)
{
    return (s1 > s2 && s1 - s2 < UINT16_C(0x8000)) || (s1 < s2 && s2 - s1 > UINT16_C(0x8000));
}

COMMON_FUNCTIONS_FN bool common_serial_number_greater_32(uint32_t s1, uint32_t s2)
{
    return (s1 > s2 && s1 - s2 < UINT32_C(0x80000000)) || (s1 < s2 && s2 - s1 > UINT32_C(0x80000000));
}

#endif /*__COMMON_FUNCTIONS_H_*/
