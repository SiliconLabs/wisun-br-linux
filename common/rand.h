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
#ifndef COMMON_RAND_H
#define COMMON_RAND_H
#include <stdint.h>

#include "common/int24.h"

/*
 * Helpers around getrandom().
 */

uint8_t rand_get_8bit(void);
uint16_t rand_get_16bit(void);
uint24_t rand_get_24bit(void);
uint32_t rand_get_32bit(void);
uint64_t rand_get_64bit(void);
void rand_get_n_bytes_random(void *data_ptr, uint8_t count);
uint16_t rand_get_random_in_range(uint16_t min, uint16_t max);

float randf_uniform(void);               // float in [0, 1]
float randf_range(float min, float max); // float in [min, max]

/*
 * Randomise a base 32-bit number by a jitter factor
 *
 * The result is linearly distributed in the jitter range, which is expressed as
 * fixed-point unsigned 1.15 values. For example, to produce a number in the
 * range [0.75 * base, 1.25 * base], set min_factor to 0x6000 and max_factor to
 * 0xA000.
 *
 * Result is clamped to 0xFFFFFFFF if it overflows.
 */
uint32_t rand_randomise_base(uint32_t base, uint16_t min_factor, uint16_t max_factor);

#endif
