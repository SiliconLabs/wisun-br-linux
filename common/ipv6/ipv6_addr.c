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
#include <netinet/in.h>
#include <string.h>

struct in6_addr ipv6_prefix_linklocal = { .s6_addr = { 0xfe, 0x80 } }; // fe80::

struct in6_addr ipv6_addr_all_nodes_link     = { .s6_addr = { 0xff, 0x02, [15] = 0x01 } }; // ff02::1
struct in6_addr ipv6_addr_all_routers_link   = { .s6_addr = { 0xff, 0x02, [15] = 0x02 } }; // ff02::2
struct in6_addr ipv6_addr_all_rpl_nodes_link = { .s6_addr = { 0xff, 0x02, [15] = 0x1a } }; // ff02::1a
struct in6_addr ipv6_addr_all_nodes_realm    = { .s6_addr = { 0xff, 0x03, [15] = 0x01 } }; // ff03::1
struct in6_addr ipv6_addr_all_routers_realm  = { .s6_addr = { 0xff, 0x03, [15] = 0x02 } }; // ff03::2
struct in6_addr ipv6_addr_all_mpl_fwd_realm  = { .s6_addr = { 0xff, 0x03, [15] = 0xfc } }; // ff03::fc

// RFC 4291 Appendix A: Creating Modified EUI-64 Format Interface Identifiers
void ipv6_addr_conv_iid_eui64(uint8_t out[8], const uint8_t in[8])
{
    memcpy(out, in, 8);
    out[0] ^= 0x02;
}
