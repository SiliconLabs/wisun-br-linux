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
#ifndef RPL_SRH_H
#define RPL_SRH_H

struct ip6_hdr;
struct ipv6_ctx;
struct pktbuf;

/*
 * Decompress a RPL Source Routing Header, swap the next hop with the
 * destination address, and recompress the header. The payload length
 * is updated accordingly in the IPv6 header.
 * Returns 0 on success or a negative errno on failure.
 */
int rpl_srh_process(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, struct ip6_hdr *hdr);

#endif
