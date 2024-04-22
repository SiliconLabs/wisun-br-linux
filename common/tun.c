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
#define _GNU_SOURCE
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include <netlink/addr.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/inet6.h>

#include "common/log.h"

#include "tun.h"

// ip tuntap add dev [tun->ifname] mode tun
static void tun_open(struct tun_ctx *tun)
{
    struct ifreq ifr = { };
    int ret;

    tun->fd = open("/dev/net/tun", O_RDWR);
    FATAL_ON(tun->fd < 0, 2, "open /dev/net/tun: %m");

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, tun->ifname);
    ret = ioctl(tun->fd, TUNSETIFF, &ifr);
    FATAL_ON(ret < 0, 2, "ioctl TUNSETIFF: %m");

    strcpy(tun->ifname, ifr.ifr_name);
    tun->ifindex = if_nametoindex(tun->ifname);
    FATAL_ON(!tun->ifindex, 2, "if_nametoindex %s: %m", tun->ifname);
}

// ip link set dev [tun->ifname] mtu 1280 txqueuelen 10 addrgenmode none up
static void tun_link_init(struct tun_ctx *tun)
{
    struct rtnl_link *link;
    int ret;

    link = rtnl_link_alloc();
    FATAL_ON(!link, 2, "rtnl_link_alloc: %s", strerror(ENOMEM));

    rtnl_link_set_ifindex(link, tun->ifindex);
    rtnl_link_set_mtu(link, 1280);
    rtnl_link_set_txqlen(link, 10);
    ret = rtnl_link_inet6_set_addr_gen_mode(link, rtnl_link_inet6_str2addrgenmode("none"));
    FATAL_ON(ret < 0, 2, "rtnl_link_inet6_set_addr_gen_mode: %s", nl_geterror(ret));
    rtnl_link_set_flags(link, IFF_UP);

    ret = rtnl_link_add(tun->nlsock, link, NLM_F_CREATE);
    FATAL_ON(ret < 0, 2, "rtnl_link_add: %s", nl_geterror(ret));

    rtnl_link_put(link);
}

static void tun_link_check(struct tun_ctx *tun)
{
    struct rtnl_link *link;
    uint8_t addrgenmode;
    int ret;

    ret = rtnl_link_get_kernel(tun->nlsock, tun->ifindex, NULL, &link);
    FATAL_ON(ret < 0, 2, "rtnl_link_get_kernel %s: %s", tun->ifname, nl_geterror(ret));

    if (!(rtnl_link_get_flags(link) & IFF_UP))
        FATAL(2, "%s: interface not up", tun->ifname);

    ret = rtnl_link_inet6_get_addr_gen_mode(link, &addrgenmode);
    if (ret < 0 || addrgenmode != rtnl_link_inet6_str2addrgenmode("none"))
        WARN("%s: unexpected addrgenmode", tun->ifname);
    if (rtnl_link_get_mtu(link) > 1280)
        WARN("%s: mtu > 1280", tun->ifname);
    if (rtnl_link_get_txqlen(link) > 10)
        WARN("%s: txqlen > 10", tun->ifname);

    rtnl_link_put(link);
}

// ip addr add dev [tun->ifname] [addr]/[prefix_len]
void tun_addr_add(struct tun_ctx *tun, const struct in6_addr *addr, uint8_t prefix_len)
{
    struct rtnl_addr *rtnladdr;
    struct nl_addr *nladdr;
    int ret;

    nladdr = nl_addr_build(AF_INET6, addr, sizeof(*addr));
    FATAL_ON(!nladdr, 2, "nl_addr_build: %s", strerror(ENOMEM));

    rtnladdr = rtnl_addr_alloc();
    FATAL_ON(!rtnladdr, 2, "rtnl_addr_alloc: %s", strerror(ENOMEM));
    ret = rtnl_addr_set_local(rtnladdr, nladdr);
    FATAL_ON(ret < 0, 2, "rtnl_addr_set_local %s: %s", tr_ipv6(addr->s6_addr), nl_geterror(ret));
    rtnl_addr_set_prefixlen(rtnladdr, prefix_len);
    rtnl_addr_set_ifindex(rtnladdr, tun->ifindex);

    ret = rtnl_addr_add(tun->nlsock, rtnladdr, 0);
    if (ret < 0) {
        if (ret == -NLE_EXIST)
            WARN("rtnl_addr_add %s: %s", tr_ipv6(addr->s6_addr), nl_geterror(ret));
        else
            FATAL(2, "rtnl_addr_add %s: %s", tr_ipv6(addr->s6_addr), nl_geterror(ret));
    }

    rtnl_addr_put(rtnladdr);
    nl_addr_put(nladdr);
}

static int tun_addr_set_mc(struct tun_ctx *tun, const struct in6_addr *addr, int opt)
{
    struct ipv6_mreq mreq = {
        .ipv6mr_multiaddr = *addr,
        .ipv6mr_interface = tun->ifindex,
    };
    int ret;

    ret = setsockopt(tun->mc_sockfd, SOL_IPV6, opt, &mreq, sizeof(mreq));
    return ret < 0 ? -errno : 0;
}

int tun_addr_add_mc(struct tun_ctx *tun, const struct in6_addr *addr)
{
    return tun_addr_set_mc(tun, addr, IPV6_JOIN_GROUP);
}

int tun_addr_del_mc(struct tun_ctx *tun, const struct in6_addr *addr)
{
    return tun_addr_set_mc(tun, addr, IPV6_LEAVE_GROUP);
}

// sysctl [dir]/[ifname]/key=[val]
void tun_sysctl_set(const char *dir, const char *ifname, const char *key, char val)
{
    char path[PATH_MAX];
    char val_cur;
    ssize_t ret;
    int fd;

    snprintf(path, sizeof(path), "%s/%s/%s", dir, ifname, key);

    fd = open(path, O_RDONLY);
    FATAL_ON(fd < 0, 2, "open %s: %m", path);
    ret = read(fd, &val_cur, sizeof(val_cur));
    FATAL_ON(ret != sizeof(val_cur), 2, "read %s: %m", path);
    close(fd);

    if (val == val_cur)
        return;

    fd = open(path, O_WRONLY);
    FATAL_ON(fd < 0, 2, "open %s: %m", path);
    ret = write(fd, &val, sizeof(val));
    FATAL_ON(ret != sizeof(val), 2, "write %s %c: %m", path, val);
    close(fd);
}

void tun_init(struct tun_ctx *tun, bool autoconf)
{
    int ret;

    tun_open(tun);

    tun->nlsock = nl_socket_alloc();
    FATAL_ON(!tun->nlsock, 2, "nl_socket: %s", strerror(ENOMEM));
    ret = nl_connect(tun->nlsock, NETLINK_ROUTE);
    FATAL_ON(ret < 0, 2, "nl_connect NETLINK_ROUTE: %s", nl_geterror(ret));

    if (autoconf)
        tun_link_init(tun);
    else
        tun_link_check(tun);

    tun->mc_sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);
    FATAL_ON(tun->mc_sockfd < 0, 2, "socket AF_INET6 SOCK_RAW IPPROTO_IPV6: %m");
}