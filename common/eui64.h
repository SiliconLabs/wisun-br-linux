/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef EUI64_H
#define EUI64_H

#include <stdbool.h>
#include <string.h>

#include "common/endian.h"

struct eui64 {
    union {
        uint8_t u8[8];
        be64_t  be64;
    };
};

#define EUI64_BC (struct eui64){ .be64 = UINT64_MAX }

/*
 * Casting a unaligned uint8_t[8] to a struct eui64 * can cause a SIGBUS if the
 * CPU does not support unaligned memory access. This macro creates a copy of
 * the EUI-64, with proper alignement.
 *
 * TODO: Remove this macro when struct eui64 has conquered the codebase.
 */
#define EUI64_FROM_BUF(buf) (struct eui64){ .u8 = { \
    (buf)[0], (buf)[1], (buf)[2], (buf)[3], (buf)[4], (buf)[5], (buf)[6], (buf)[7] \
} }

static inline bool eui64_eq(const struct eui64 *a, const struct eui64 *b)
{
    return a->be64 == b->be64;
}

static inline bool eui64_is_bc(const struct eui64 *eui64)
{
    return eui64->be64 == UINT64_MAX;
}

#endif
