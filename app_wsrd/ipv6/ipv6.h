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
#ifndef WSRD_IPV6_H
#define WSRD_IPV6_H

#include "app_wsrd/ipv6/ndp.h"
#include "app_wsrd/ipv6/rpl.h"
#include "common/dhcp_client.h"
#include "common/timer.h"
#include "common/tun.h"

struct in6_addr;
struct pktbuf;

struct ipv6_ctx {
    struct tun_ctx tun;
    struct dhcp_client dhcp;
    struct in6_addr *addr_list_mc;
    int addr_list_mc_len;

    int reach_base_ms;  // BaseReachableTime
    int probe_delay_ms; // RetransDelay
    uint64_t aro_lifetime_ms;
    struct ipv6_neigh_cache neigh_cache;
    uint8_t eui64[8];

    struct timer_group timer_group;
    struct rpl_ctx rpl;

    int (*sendto_mac)(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const uint8_t dst[8]);
};

void ipv6_recvfrom_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf);
void ipv6_recvfrom_tun(struct ipv6_ctx *ipv6);

int ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf,
                    uint8_t ipproto, uint8_t hlim,
                    const struct in6_addr *src, const struct in6_addr *dst);

#endif
