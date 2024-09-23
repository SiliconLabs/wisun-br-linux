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
#ifndef IPV6_CKSUM_H
#define IPV6_CKSUM_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>

#include "common/endian.h"

// RFC 8200 8.1. Upper-Layer Checksums
// RFC 4443 2.3. Message Checksum Calculation
// RFC 768 User Datagram Protocol
// RFC 1071 Computing the Internet Checksum
static inline be16_t ipv6_cksum(const struct in6_addr *src, const struct in6_addr *dst,
                                uint8_t nxthdr, const void *buf, uint16_t buf_len)
{
    const uint16_t *buf16 = buf;
    const uint8_t *buf8 = buf;
    uint32_t sum = 0;

    for (unsigned int i = 0; i < 8; i++)
        sum += src->s6_addr16[i];
    for (unsigned int i = 0; i < 8; i++)
        sum += dst->s6_addr16[i];
    sum += htons(buf_len);
    sum += htons(nxthdr);
    for (unsigned int i = 0; i < buf_len / 2; i++)
        sum += buf16[i];
    if (buf_len % 2 != 0)
        sum += htons(buf8[buf_len - 1] << 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

#endif
