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
#ifndef NETINET_IN_EXTRA_H
#define NETINET_IN_EXTRA_H
#include <netinet/in.h>
#include <string.h>

/*
 * Provide some non-standard extensions to netinet/in.h.
 *
 * These functions keep the same name and call conventions as netinet/in.h.
 */

// IN6_ARE_ADDR_EQUAL() expects addresses to be memory aligned
#define IN6_ARE_ADDR_EQUAL_SAFE(a, b) !memcmp(a, b, sizeof(struct in6_addr))

// RFC 4291 - 2.4. Address Type Identification
#define IN6_IS_ADDR_UC_GLOBAL(a) ( \
    !IN6_IS_ADDR_UNSPECIFIED(a) && \
    !IN6_IS_ADDR_LOOPBACK(a)    && \
    !IN6_IS_ADDR_MULTICAST(a)   && \
    !IN6_IS_ADDR_LINKLOCAL(a)      \
)
// RFC 4291 2.7. Multicast Addresses
#define IN6_ADDR_MC_SCOPE(a) ((a)->s6_addr[1] & 0x0f)

// RFC 7346 2. Definition of IPv6 Multicast Address Scopes
enum {
    IN6_ADDR_MC_SCOPE_IFACE  = 0x01,
    IN6_ADDR_MC_SCOPE_LINK   = 0x02,
    IN6_ADDR_MC_SCOPE_REALM  = 0x03,
    IN6_ADDR_MC_SCOPE_ADMIN  = 0x04,
    IN6_ADDR_MC_SCOPE_SITE   = 0x05,
    IN6_ADDR_MC_SCOPE_ORG    = 0x08,
    IN6_ADDR_MC_SCOPE_GLOBAL = 0x0e,
};

#ifndef IPPORT_ECHO // Provided by glibc but not musl
#define IPPORT_ECHO 7
#endif

#endif
