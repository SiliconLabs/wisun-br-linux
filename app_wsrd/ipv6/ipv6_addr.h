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
#ifndef WSRD_IPV6_ADDR_H
#define WSRD_IPV6_ADDR_H

#include <netinet/in.h>
#include <stdbool.h>

struct ipv6_ctx;

extern struct in6_addr ipv6_prefix_linklocal; // fe80::

extern struct in6_addr ipv6_addr_all_nodes_link;     // ff02::1
extern struct in6_addr ipv6_addr_all_routers_link;   // ff02::2
extern struct in6_addr ipv6_addr_all_rpl_nodes_link; // ff02::1a
extern struct in6_addr ipv6_addr_all_nodes_realm;    // ff03::1
extern struct in6_addr ipv6_addr_all_routers_realm;  // ff03::2
extern struct in6_addr ipv6_addr_all_mpl_fwd_realm;  // ff03::fc

void ipv6_addr_conv_iid_eui64(uint8_t out[8], const uint8_t in[8]);

bool ipv6_addr_has_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr);
int ipv6_addr_add_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr);
int ipv6_addr_del_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr);

#endif
