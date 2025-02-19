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
#ifndef RPL_RPI_H
#define RPL_RPI_H

struct ip6_opt;
struct ipv6_ctx;

/*
 * Process the RPL Packet Information (RPI) option in the IPv6 hop-by-hop
 * options header. Update the rank and flags as necessary.
 * Returns 0 on success or a negative errno on failure.
 */
int rpl_rpi_process(struct ipv6_ctx *ipv6, struct ip6_opt *rpi);

#endif
