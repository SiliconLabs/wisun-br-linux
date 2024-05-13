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
#ifndef WSRD_IPV6_H
#define WSRD_IPV6_H

#include <netinet/in.h>

#include "wsrd/ipv6/ndp.h"
#include "wsrd/ipv6/rpl.h"
#include "common/timer.h"
#include "common/tun.h"

struct pktbuf;

struct ipv6_ctx {
    struct tun_ctx tun;
    struct in6_addr addr_linklocal;
    struct in6_addr addr_uc_global;
    struct in6_addr *addr_list_mc;
    int addr_list_mc_len;

    int reach_base_ms;  // BaseReachableTime
    int probe_delay_ms; // RetransDelay
    struct ipv6_neigh_cache neigh_cache;
    uint8_t eui64[8];

    struct timer_group timer_group;
    struct rpl_ctx rpl;
};

void ipv6_init(struct ipv6_ctx *ipv6, struct timer_ctxt *timer_ctx, const uint8_t eui64[8]);

void ipv6_recvfrom_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf);

#endif
