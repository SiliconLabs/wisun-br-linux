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
#include "ipv6.h"

void ipv6_init(struct ipv6_ctx *ipv6)
{
    tun_init(&ipv6->tun, true);
    tun_sysctl_set("/proc/sys/net/ipv6/conf", ipv6->tun.ifname, "accept_ra", '0');
}
