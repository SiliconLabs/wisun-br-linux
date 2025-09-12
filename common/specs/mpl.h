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
#ifndef SPECS_MPL_H
#define SPECS_MPL_H
#include <netinet/ip6.h>
#include <assert.h>
#include <stdint.h>

// RFC 7731 6.1. MPL Option
struct mpl_opt {
    uint8_t flags;
#define MPL_MASK_S 0xc0
#define MPL_MASK_M 0x20
#define MPL_MASK_V 0x10
    uint8_t seq;
    uint8_t seed_id[];
} __attribute__((packed));

enum {
    MPL_S_SRC = 0,
    MPL_S_16  = 1,
    MPL_S_64  = 2,
    MPL_S_128 = 3,
};

#endif
