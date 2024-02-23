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
#include <stdint.h>
#include <stdio.h>
#include <limits.h>

#include "common/capture.h"
#include "common/log.h"

#include "rand.h"

uint8_t rand_get_8bit(void)
{
    uint8_t result;

    rand_get_n_bytes_random(&result, sizeof(result));
    return result;
}

uint16_t rand_get_16bit(void)
{
    uint16_t result;

    rand_get_n_bytes_random(&result, sizeof(result));
    return result;
}

uint32_t rand_get_32bit(void)
{
    uint32_t result;

    rand_get_n_bytes_random(&result, sizeof(result));
    return result;
}

uint64_t rand_get_64bit(void)
{
    uint64_t result;

    rand_get_n_bytes_random(&result, sizeof(result));
    return result;
}

void rand_get_n_bytes_random(void *ptr, uint8_t count)
{
    int ret;

    ret = xgetrandom(ptr, count, 0);
    FATAL_ON(ret != count, 2);
}

uint16_t rand_get_random_in_range(uint16_t min, uint16_t max)
{
    /* We get rand_max values from rand16 or 32() in the range [0..rand_max-1], and
     * need to divvy them up into the number of values we need. And reroll any
     * odd values off the end as we insist every value having equal chance.
     *
     * Using the range [0..rand_max-1] saves long division on the band
     * calculation - it means rand_max ends up always being rerolled.
     *
     * Eg, range(1,2), rand_max = 0xFFFF:
     * We have 2 bands of size 0x7FFF (0xFFFF/2).
     *
     * We roll: 0x0000..0x7FFE -> 1
     *          0x7FFF..0xFFFD -> 2
     *          0xFFFE..0xFFFF -> reroll
     * (calculating band size as 0x10000/2 would have avoided the reroll cases)
     *
     * Eg, range(1,3), rand_max = 0xFFFFFFFF:
     * We have 3 bands of size 0x55555555 (0xFFFFFFFF/3).
     *
     * We roll: 0x00000000..0x555555554 -> 1
     *          0x55555555..0xAAAAAAAA9 -> 2
     *          0xAAAAAAAA..0xFFFFFFFFE -> 3
     *          0xFFFFFFFF              -> reroll
     *
     * (Bias problem clearly pretty insignificant there, but gets worse as
     * range increases).
     */
    const unsigned int values_needed = max + 1 - min;
    const unsigned int band_size = UINT32_MAX / values_needed;
    const unsigned int top_of_bands = band_size * values_needed;
    unsigned int result;

    /* Obvious special case */
    if (min == max)
        return min;

    do {
        result = rand_get_32bit();
    } while (result >= top_of_bands);

    return min + (uint16_t)(result / band_size);
}

uint32_t rand_randomise_base(uint32_t base, uint16_t min_factor, uint16_t max_factor)
{
    uint16_t random_factor = rand_get_random_in_range(min_factor, max_factor);
    /* 32x16-bit long multiplication, to get 48-bit result */
    uint32_t hi = (base >> 16) * random_factor;
    uint32_t lo = (base & 0xFFFF) * random_factor;
    /* Add halves, and take top 32 bits of 48-bit result */
    uint32_t res = hi + (lo >> 16);

    /* Randomisation factor is *2^15, so need to shift up 1 more bit, avoiding overflow */
    if (res & 0x80000000)
        res = 0xFFFFFFFF;
    else
        res = (res << 1) | ((lo >> 15) & 1);

    return res;
}
