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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common/log.h"
#include "app_wsrd/ipv6/ipv6.h"

#include "ipv6_addr.h"

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

static int ipv6_addr_idx_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr)
{
    BUG_ON(!IN6_IS_ADDR_MULTICAST(addr));
    for (int i = 0; i < ipv6->addr_list_mc_len; i++)
        if (IN6_ARE_ADDR_EQUAL(addr, &ipv6->addr_list_mc[i]))
            return i;
    return -ENODEV;
}

bool ipv6_addr_has_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr)
{
    return ipv6_addr_idx_mc(ipv6, addr) >= 0;
}

int ipv6_addr_add_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr)
{
    int ret;

    if (ipv6_addr_has_mc(ipv6, addr))
        return -EEXIST;

    ipv6->addr_list_mc_len++;
    ipv6->addr_list_mc = realloc(ipv6->addr_list_mc,
                                 ipv6->addr_list_mc_len * sizeof(*ipv6->addr_list_mc));
    FATAL_ON(!ipv6->addr_list_mc, 2, "%s: realloc: %m", __func__);
    ipv6->addr_list_mc[ipv6->addr_list_mc_len - 1] = *addr;

    ret = tun_addr_add_mc(&ipv6->tun, addr);
    WARN_ON(ret < 0, "tun_addr_add_mc %s %s", tr_ipv6(addr->s6_addr), strerror(-ret));
    return ret;
}

int ipv6_addr_del_mc(struct ipv6_ctx *ipv6, const struct in6_addr *addr)
{
    int ret, i;

    i = ipv6_addr_idx_mc(ipv6, addr);
    if (i < 0)
        return i;

    memmove(ipv6->addr_list_mc + i,
            ipv6->addr_list_mc + i + 1,
            ipv6->addr_list_mc_len - i);
    ipv6->addr_list_mc_len--;

    ret = tun_addr_del_mc(&ipv6->tun, addr);
    WARN_ON(ret < 0, "tun_addr_del_mc %s %s", tr_ipv6(addr->s6_addr), strerror(-ret));
    return ret;
}
