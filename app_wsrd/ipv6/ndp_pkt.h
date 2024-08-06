/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSRD_NDP_PKT_H
#define WSRD_NDP_PKT_H

#include <asm/byteorder.h>
#include <stdint.h>

#include "common/endian.h"

struct ndp_opt {
    uint8_t type;
    uint8_t len;
} __attribute__((packed));

// RFC 6778 4.1. Address Registration Option
// RFC 8505 4.1. Extended Address Registration Option (EARO)
// draft-ietf-6lo-multicast-registration-18 7.1. Placing the New P-Field in the EARO
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-adress-registration-option-flags
struct ndp_opt_earo {
    uint8_t type; // 33
    uint8_t len;  // 2 for ARO, variable for EARO (unsupported)
    uint8_t status;
    uint8_t opaque;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t t: 1, // TID used
            r: 1, // Router
            i: 1, // Opaque Field Hint
            p: 2, // Address Type
             : 2; // Reserved
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint8_t  : 2, // Reserved
            p: 2, // Address Type
            i: 1, // Opaque Field Hint
            r: 1, // Router
            t: 1; // TID used
#else
#error "Please fix <asm/byteorder.h>"
#endif
    uint8_t tid; // Transaction ID
    be16_t  lifetime_minutes;
    uint8_t eui64[8]; // Unsupported variable size ROVR
} __attribute__((packed));

#endif
