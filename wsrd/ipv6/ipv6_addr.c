/*
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
#include <string.h>

#include "ipv6_addr.h"

struct in6_addr ipv6_prefix_linklocal = { .s6_addr = { 0xfe, 0x80 } }; // fe80::

// RFC 4291 Appendix A: Creating Modified EUI-64 Format Interface Identifiers
void ipv6_addr_conv_iid_eui64(uint8_t out[8], const uint8_t in[8])
{
    memcpy(out, in, 8);
    out[0] ^= 0x02;
}
