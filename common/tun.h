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
#ifndef WSRD_TUN_H
#define WSRD_TUN_H

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>

struct nl_sock;
struct in6_addr;

struct tun_ctx {
    char ifname[IF_NAMESIZE];
    int  ifindex;
    int  fd;
    int  mc_sockfd;
    struct nl_sock *nlsock;
};

// ip tuntap add dev [tun->ifname] mode tun
// if (autoconf)
//     ip link set dev [tun->ifname] mtu 1280 txqueuelen 10 addrgenmode none
//     ip link set dev [tun->ifname] up
void tun_init(struct tun_ctx *tun, bool autoconf);

// ip addr add dev [tun->ifname] [addr]/[prefix_len]
void tun_addr_add(struct tun_ctx *tun, const struct in6_addr *addr, uint8_t prefix_len);
// ip addr del dev [tun->ifname] [addr]/[prefix_len]
void tun_addr_del(struct tun_ctx *tun, const struct in6_addr *addr, uint8_t prefix_len);

// ip -6 addr show dev [tun->ifname] scope link
int tun_addr_get_linklocal(struct tun_ctx *tun, struct in6_addr *addr);
// ip -6 addr show dev [tun->ifname] scope global
int tun_addr_get_uc_global(struct tun_ctx *tun, struct in6_addr *addr);

int tun_addr_add_mc(struct tun_ctx *tun, const struct in6_addr *addr);
int tun_addr_del_mc(struct tun_ctx *tun, const struct in6_addr *addr);

// sysctl [dir]/[ifname]/key=[val]
void tun_sysctl_set(const char *dir, const char *ifname, const char *key, char val);

#endif
