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

#ifndef DHCPV6_H
#define DHCPV6_H

#include <netinet/in.h>

#include "common/endian.h"

// RFC3315 - Section 5.2
// https://datatracker.ietf.org/doc/html/rfc3315#section-5.2
enum {
    DHCPV6_CLIENT_UDP_PORT = 546,
    DHCPV6_SERVER_UDP_PORT = 547,
};

// RFC3315 - Section 5.6
// https://datatracker.ietf.org/doc/html/rfc3315#section-5.6
#define DHCPV6_LIFETIME_INFINITE 0xffffffff

// RFC3315 - Section 24.2
// https://datatracker.ietf.org/doc/html/rfc3315#section-24.2
enum {
    DHCPV6_MSG_SOLICIT      = 1,
    DHCPV6_MSG_ADVERT       = 2,  /* Unused */
    DHCPV6_MSG_REQUEST      = 3,  /* Unused */
    DHCPV6_MSG_CONFIRM      = 4,  /* Unused */
    DHCPV6_MSG_RENEW        = 5,  /* Unused */
    DHCPV6_MSG_REBIND       = 6,  /* Unused */
    DHCPV6_MSG_REPLY        = 7,
    DHCPV6_MSG_RELEASE      = 8,  /* Unused */
    DHCPV6_MSG_DECLINE      = 9,  /* Unused */
    DHCPV6_MSG_RECONFIGURE  = 10, /* Unused */
    DHCPV6_MSG_INFO_REQUEST = 11, /* Unused */
    DHCPV6_MSG_RELAY_FWD    = 12,
    DHCPV6_MSG_RELAY_REPLY  = 13,
};

// RFC3315 - Section 24.3
// https://datatracker.ietf.org/doc/html/rfc3315#section-24.3
enum {
    DHCPV6_OPT_CLIENT_ID       = 1,
    DHCPV6_OPT_SERVER_ID       = 2,
    DHCPV6_OPT_IA_NA           = 3,
    DHCPV6_OPT_IA_TA           = 4,  /* Unused */
    DHCPV6_OPT_IA_ADDRESS      = 5,
    DHCPV6_OPT_ORO             = 6,  /* Unused */
    DHCPV6_OPT_PREFERENCE      = 7,  /* Unused */
    DHCPV6_OPT_ELAPSED_TIME    = 8,
    DHCPV6_OPT_RELAY           = 9,
    DHCPV6_OPT_RESERVED1       = 10, /* Unused */
    DHCPV6_OPT_AUTH            = 11, /* Unused */
    DHCPV6_OPT_UNICAST         = 12, /* Unused */
    DHCPV6_OPT_STATUS_CODE     = 13,
    DHCPV6_OPT_RAPID_COMMIT    = 14,
    DHCPV6_OPT_USER_CLASS      = 15, /* Unused */
    DHCPV6_OPT_VENDOR_CLASS    = 16, /* Unused */
    DHCPV6_OPT_VENDOR_SPECIFIC = 17, /* Unused */
    DHCPV6_OPT_INTERFACE_ID    = 18,
    DHCPV6_OPT_RECONF_MSG      = 19, /* Unused */
    DHCPV6_OPT_RECONF_ACCEPT   = 20, /* Unused */
};

// RFC3315 - Section 24.5
// https://datatracker.ietf.org/doc/html/rfc3315#section-24.5
enum {
    DHCPV6_DUID_TYPE_LINK_LAYER_PLUS_TIME = 1, /* Unused */
    DHCPV6_DUID_TYPE_EN                   = 2, /* Unused */
    DHCPV6_DUID_TYPE_LINK_LAYER           = 3,
    DHCPV6_DUID_TYPE_UUID                 = 4, /* Unused */
};

// Address Resolution Protocol (ARP) Parameters
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
enum {
    DHCPV6_DUID_HW_TYPE_IEEE802 = 6,
    DHCPV6_DUID_HW_TYPE_EUI64   = 27,
};

// RFC 8415 Figure 3: Relay Agent/Server Message Format
struct dhcpv6_relay_hdr {
    uint8_t type;
    uint8_t hops;
    struct in6_addr link;
    struct in6_addr peer;
} __attribute__((packed));

// RFC 8415 21.1. Format of DHCP Options
struct dhcpv6_opt {
    be16_t code;
    be16_t len;
} __attribute__((packed));

#endif
