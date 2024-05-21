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

#ifndef DHCPV6_H
#define DHCPV6_H

// RFC3315 - Section 5.2
// https://datatracker.ietf.org/doc/html/rfc3315#section-5.2
#define DHCPV6_CLIENT_UDP_PORT 546
#define DHCPV6_SERVER_UDP_PORT 547

// RFC3315 - Section 24.2
// https://datatracker.ietf.org/doc/html/rfc3315#section-24.2
#define DHCPV6_MSG_SOLICIT      1
#define DHCPV6_MSG_ADVERT       2  /* Unused */
#define DHCPV6_MSG_REQUEST      3  /* Unused */
#define DHCPV6_MSG_CONFIRM      4  /* Unused */
#define DHCPV6_MSG_RENEW        5  /* Unused */
#define DHCPV6_MSG_REBIND       6  /* Unused */
#define DHCPV6_MSG_REPLY        7
#define DHCPV6_MSG_RELEASE      8  /* Unused */
#define DHCPV6_MSG_DECLINE      9  /* Unused */
#define DHCPV6_MSG_RECONFIGURE  10 /* Unused */
#define DHCPV6_MSG_INFO_REQUEST 11 /* Unused */
#define DHCPV6_MSG_RELAY_FWD    12
#define DHCPV6_MSG_RELAY_REPLY  13

// RFC3315 - Section 24.3
// https://datatracker.ietf.org/doc/html/rfc3315#section-24.3
#define DHCPV6_OPT_CLIENT_ID                  1
#define DHCPV6_OPT_SERVER_ID                  2
#define DHCPV6_OPT_IA_NA                      3
#define DHCPV6_OPT_IA_TA                      4  /* Unused */
#define DHCPV6_OPT_IA_ADDRESS                 5
#define DHCPV6_OPT_ORO                        6  /* Unused */
#define DHCPV6_OPT_PREFERENCE                 7  /* Unused */
#define DHCPV6_OPT_ELAPSED_TIME               8
#define DHCPV6_OPT_RELAY                      9
#define DHCPV6_OPT_RESERVED1                  10 /* Unused */
#define DHCPV6_OPT_AUTH                       11 /* Unused */
#define DHCPV6_OPT_UNICAST                    12 /* Unused */
#define DHCPV6_OPT_STATUS_CODE                13
#define DHCPV6_OPT_RAPID_COMMIT               14
#define DHCPV6_OPT_USER_CLASS                 15 /* Unused */
#define DHCPV6_OPT_VENDOR_CLASS               16 /* Unused */
#define DHCPV6_OPT_VENDOR_SPECIFIC            17 /* Unused */
#define DHCPV6_OPT_INTERFACE_ID               18
#define DHCPV6_OPT_RECONF_MSG                 19 /* Unused */
#define DHCPV6_OPT_RECONF_ACCEPT              20 /* Unused */

// RFC3315 - Section 24.5
// https://datatracker.ietf.org/doc/html/rfc3315#section-24.5
#define DHCPV6_DUID_TYPE_LINK_LAYER_PLUS_TIME 1 /* Unused */
#define DHCPV6_DUID_TYPE_EN                   2 /* Unused */
#define DHCPV6_DUID_TYPE_LINK_LAYER           3
#define DHCPV6_DUID_TYPE_UUID                 4 /* Unused */

// Address Resolution Protocol (ARP) Parameters
// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
#define DHCPV6_DUID_HW_TYPE_IEEE802           6
#define DHCPV6_DUID_HW_TYPE_EUI64             27

#endif
