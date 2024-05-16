/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SEQNO_H
#define SEQNO_H
#include <stdint.h>

/*
 * RFC 1982 [1] defines a way to work with sequence numbers that can wrap.
 * Comparison functions return:
 *   <0 if a < b
 *    0 if a = b
 *   >0 if a > b
 *
 * Wikipedia [2] provides a simple way of comparing numbers using 2s complement
 * integer representation.
 *
 * [1]: https://www.rfc-editor.org/rfc/rfc1982
 * [2]: https://en.wikipedia.org/wiki/Serial_number_arithmetic#General_solution
 */

static inline int seqno_cmp7(uint8_t a, uint8_t b)
{
    return (int8_t)((a << 1) - (b << 1));
}

static inline int seqno_cmp8(uint8_t a, uint8_t b)
{
    return (int8_t)(a - b);
}

#endif
