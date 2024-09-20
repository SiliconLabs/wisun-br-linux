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
#ifndef IPV6_MC_ADDR_H
#define IPV6_MC_ADDR_H

#include <netinet/in.h>
#include <stdbool.h>

struct ipv6_ctx;

bool ipv6_addr_has_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr);
int ipv6_addr_add_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr);
int ipv6_addr_del_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr);

#endif
