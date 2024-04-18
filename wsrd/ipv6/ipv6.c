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
#include <string.h>

#include "wsrd/ipv6/ipv6_addr.h"
#include "ipv6.h"

void ipv6_init(struct ipv6_ctx *ipv6, const uint8_t eui64[8])
{
    tun_init(&ipv6->tun, true);
    tun_sysctl_set("/proc/sys/net/ipv6/conf", ipv6->tun.ifname, "accept_ra", '0');

    memcpy(ipv6->eui64, eui64, 8);
    memcpy(ipv6->addr_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
    ipv6_addr_conv_iid_eui64(ipv6->addr_linklocal.s6_addr + 8, eui64);
    tun_addr_add(&ipv6->tun, &ipv6->addr_linklocal, 64);
}
