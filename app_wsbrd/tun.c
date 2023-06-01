/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <ifaddrs.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/link/inet6.h>
#include <arpa/inet.h>
#include "common/bits.h"
#include "common/dhcp_server.h"
#include "common/log.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common_protocols/icmpv6.h"
#include "stack/mac/platform/arm_hal_phy.h"

#include "stack/source/6lowpan/lowpan_adaptation_interface.h"
#include "stack/source/nwk_interface/protocol.h"

#include "tun.h"
#include "wsbr.h"

// IPv6 header (RFC8200 section 3)
#define IPV6_VERSION_MASK       0b11110000000000000000000000000000
#define IPV6_TRAFFIC_CLASS_MASK 0b00001111111100000000000000000000
#define IPV6_FLOW_LABEL_MASK    0b00000000000011111111111111111111

ssize_t wsbr_tun_write(uint8_t *buf, uint16_t len)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    ssize_t ret;

    ret = write(ctxt->tun_fd, buf, len);
    if (ret < 0)
        WARN("%s: write: %m", __func__);
    else if (ret != len)
        WARN("%s: write: Short write: %zd < %d", __func__, ret, len);
    return ret;
}

static int tun_addr_get(const char *if_name, uint8_t ip[static 16], bool gua)
{
    struct sockaddr_in6 *ipv6;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) < 0) {
        WARN("getifaddrs: %m");
        freeifaddrs(ifaddr);
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        if (strcmp(ifa->ifa_name, if_name))
            continue;

        ipv6 = (struct sockaddr_in6 *)ifa->ifa_addr;

        if (gua == IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr))
            continue;

        memcpy(ip, ipv6->sin6_addr.s6_addr, 16);
        freeifaddrs(ifaddr);
        return 0;
    }

    freeifaddrs(ifaddr);
    return -2;
}

int tun_addr_get_link_local(const char *if_name, uint8_t ip[static 16])
{
    return tun_addr_get(if_name, ip, false);
}

int tun_addr_get_global_unicast(const char *if_name, uint8_t ip[static 16])
{
    return tun_addr_get(if_name, ip, true);
}

void tun_add_node_to_proxy_neightbl(struct net_if *if_entry, const uint8_t address[16])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    char ipv6_addr_to_str[128] = { };
    struct rtnl_neigh *nl_neigh;
    struct rtnl_link *link;
    struct nl_addr *src_ipv6_nl_addr;
    struct nl_cache *cache;
    struct nl_sock *sock;
    int ifindex, err;

    if (strlen(ctxt->config.neighbor_proxy) == 0)
        return;

    inet_ntop(AF_INET6, address, ipv6_addr_to_str, INET6_ADDRSTRLEN);

    sock = nl_socket_alloc();
    BUG_ON(!sock);
    err = nl_connect(sock, NETLINK_ROUTE);
    FATAL_ON(err < 0, 2, "nl_connect: %s", nl_geterror(err));
    err = rtnl_link_get_kernel(sock, 0, ctxt->config.neighbor_proxy, &link);
    if (err < 0) {
        ERROR("rtnl_link_get_kernel %s: %s", ctxt->config.neighbor_proxy, nl_geterror(err));
        goto ret_free_sock;
    }
    ifindex = rtnl_link_get_ifindex(link);
    rtnl_link_put(link);

    err = rtnl_neigh_alloc_cache(sock, &cache);
    FATAL_ON(err < 0, 2, "rtnl_neigh_alloc_cache: %s", nl_geterror(err));
    err = nl_addr_parse(ipv6_addr_to_str, AF_INET6, &src_ipv6_nl_addr);
    FATAL_ON(err < 0, 2, "nl_addr_parse: %s", nl_geterror(err));
    nl_neigh = rtnl_neigh_get(cache, ifindex, src_ipv6_nl_addr);
    if (nl_neigh)
        goto ret_free_addr;
    nl_neigh = rtnl_neigh_alloc();
    BUG_ON(!nl_neigh);

    rtnl_neigh_set_ifindex(nl_neigh, ifindex);
    rtnl_neigh_set_dst(nl_neigh, src_ipv6_nl_addr);
    rtnl_neigh_set_flags(nl_neigh, NTF_PROXY);
    rtnl_neigh_set_flags(nl_neigh, NTF_ROUTER);
    err = rtnl_neigh_add(sock, nl_neigh, NLM_F_CREATE);
    FATAL_ON(err < 0, 2, "rtnl_neigh_add: %s", nl_geterror(err));

    rtnl_neigh_put(nl_neigh);
ret_free_addr:
    nl_addr_put(src_ipv6_nl_addr);
ret_free_sock:
    nl_socket_free(sock);
}

void tun_add_ipv6_direct_route(struct net_if *if_entry, const uint8_t address[16])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    char ipv6_addr_to_str[128] = { };
    struct rtnl_nexthop* nl_nexthop;
    struct rtnl_route *nl_route;
    struct rtnl_link *link;
    struct nl_addr *ipv6_nl_addr;
    struct nl_sock *sock;
    int ifindex, err;

    if (strlen(ctxt->config.neighbor_proxy) == 0)
        return;

    inet_ntop(AF_INET6, address, ipv6_addr_to_str, INET6_ADDRSTRLEN);

    sock = nl_socket_alloc();
    BUG_ON(!sock);
    err = nl_connect(sock, NETLINK_ROUTE);
    FATAL_ON(err < 0, 2, "nl_connect: %s", nl_geterror(err));
    err = rtnl_link_get_kernel(sock, 0, ctxt->config.tun_dev, &link);
    if (err) {
        ERROR("rtnl_link_get_kernel %s: %s", ctxt->config.tun_dev, nl_geterror(err));
        goto ret_free_sock;
    }
    ifindex = rtnl_link_get_ifindex(link);
    rtnl_link_put(link);

    err = nl_addr_parse(ipv6_addr_to_str, AF_INET6, &ipv6_nl_addr);
    FATAL_ON(err < 0, 2, "nl_addr_parse: %s", nl_geterror(err));
    nl_route = rtnl_route_alloc();
    BUG_ON(!nl_route);
    nl_nexthop = rtnl_route_nh_alloc();
    BUG_ON(!nl_nexthop);

    rtnl_route_set_iif(nl_route, AF_INET6);
    err = rtnl_route_set_dst(nl_route, ipv6_nl_addr);
    FATAL_ON(err < 0, 2, "rtnl_route_set_dst: %s", nl_geterror(err));
    rtnl_route_nh_set_ifindex(nl_nexthop, ifindex);
    rtnl_route_add_nexthop(nl_route, nl_nexthop);
    err = rtnl_route_add(sock, nl_route, 0);
    if (err < 0 && err != -NLE_EXIST)
        FATAL(2, "rtnl_route_add: %s", nl_geterror(err));

    rtnl_route_put(nl_route);
    nl_addr_put(ipv6_nl_addr);
ret_free_sock:
    nl_socket_free(sock);
}

static void tun_addr_add(struct nl_sock *sock, int ifindex, const uint8_t ipv6_prefix[static 8], const uint8_t hw_mac_addr[static 8], bool register_proxy_ndp)
{
    int err = 0;
    char ipv6_addr_str[128] = { };
    uint8_t ipv6_addr_buf[16] = { };
    struct rtnl_addr *ipv6_addr = NULL;
    struct nl_addr* lo_ipv6_addr = NULL;

    memcpy(ipv6_addr_buf, ipv6_prefix, 8);
    memcpy(ipv6_addr_buf + 8, hw_mac_addr, 8);
    inet_ntop(AF_INET6, ipv6_addr_buf, ipv6_addr_str, INET6_ADDRSTRLEN);
    if (register_proxy_ndp) {
        tun_add_node_to_proxy_neightbl(NULL, ipv6_addr_buf);
        strcat(ipv6_addr_str, "/128");
    } else {
        strcat(ipv6_addr_str, "/64");
    }
    err = nl_addr_parse(ipv6_addr_str, AF_INET6, &lo_ipv6_addr);
    FATAL_ON(err < 0, 2, "nl_addr_parse %s: %s", ipv6_addr_str, nl_geterror(err));
    ipv6_addr = rtnl_addr_alloc();
    err = rtnl_addr_set_local(ipv6_addr, lo_ipv6_addr);
    FATAL_ON(err < 0, 2, "rtnl_addr_set_local %s: %s", ipv6_addr_str, nl_geterror(err));
    rtnl_addr_set_ifindex(ipv6_addr, ifindex);
    rtnl_addr_set_flags(ipv6_addr, IN6_ADDR_GEN_MODE_EUI64);
    err = rtnl_addr_add(sock, ipv6_addr, 0);
    if (err < 0 && err != -NLE_EXIST)
        FATAL(2, "rtnl_addr_add %s: %s", ipv6_addr_str, nl_geterror(err));
    nl_addr_put(lo_ipv6_addr);
    rtnl_addr_put(ipv6_addr);
}

static int wsbr_tun_open(char *devname, const uint8_t hw_mac[static 8], uint8_t ipv6_prefix[static 16], bool tun_autoconf, bool register_proxy_ndp)
{
    struct rtnl_link *link;
    struct nl_sock *sock;
    struct ifreq ifr = {
        .ifr_flags = IFF_TUN | IFF_NO_PI,
    };
    int fd, ifindex;
    uint8_t hw_mac_slaac[8];
    bool is_user_configured;
    uint8_t mode;
    int err;

    memcpy(hw_mac_slaac, hw_mac, 8);
    hw_mac_slaac[0] ^= 2;

    if (devname && *devname)
        strcpy(ifr.ifr_name, devname);
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        FATAL(2, "tun open: %m");
    if (ioctl(fd, TUNSETIFF, &ifr))
        FATAL(2, "tun ioctl: %m");
    if (devname)
        strcpy(devname, ifr.ifr_name);
    sock = nl_socket_alloc();
    if (nl_connect(sock, NETLINK_ROUTE))
        FATAL(2, "nl_connect");

    if (rtnl_link_get_kernel(sock, 0, ifr.ifr_name, &link))
        FATAL(2, "rtnl_link_get_kernel %s", ifr.ifr_name);
    is_user_configured = (rtnl_link_get_operstate(link) == IF_OPER_UP) && (rtnl_link_get_flags(link) & IFF_UP);
    ifindex = rtnl_link_get_ifindex(link);
    if (is_user_configured) {
        err = rtnl_link_inet6_get_addr_gen_mode(link, &mode);
        if (err < 0 || mode != 1)
            WARN("%s: unexpected addr_gen_mode", devname);
        if (rtnl_link_get_mtu(link) > 1280)
            WARN("%s: mtu is above 1280 (not 15.4 compliant)", devname);
        if (rtnl_link_get_txqlen(link) > 10)
            WARN("%s: txqlen is above 10", devname);
    }
    rtnl_link_put(link);

    link = rtnl_link_alloc();
    rtnl_link_set_ifindex(link, ifindex);
    if (!is_user_configured) {
        rtnl_link_set_mtu(link, 1280);
        rtnl_link_set_txqlen(link, 10);
        rtnl_link_inet6_set_addr_gen_mode(link, rtnl_link_inet6_str2addrgenmode("none"));
        err = rtnl_link_add(sock, link, NLM_F_CREATE);
        FATAL_ON(err < 0, 2, "rtnl_link_add %s: %s", ifr.ifr_name, nl_geterror(err));
    }
    // Addresses must be set after set_addr_gen_mode() and before IFF_UP.
    if (tun_autoconf) {
        tun_addr_add(sock, ifindex, ADDR_LINK_LOCAL_PREFIX, hw_mac_slaac, false);
        tun_addr_add(sock, ifindex, ipv6_prefix, hw_mac_slaac, register_proxy_ndp);
    }
    if (!is_user_configured) {
        rtnl_link_set_operstate(link, IF_OPER_UP);
        rtnl_link_set_flags(link, IFF_UP);
        err = rtnl_link_add(sock, link, NLM_F_CREATE);
        FATAL_ON(err < 0, 2, "rtnl_link_add %s: %s", ifr.ifr_name, nl_geterror(err));
    }
    rtnl_link_put(link);

    nl_socket_free(sock);
    return fd;
}

static void wsbr_sysctl_set(const char *path, const char *devname, const char *option, char wanted_value)
{
    char buf[256];
    char content;
    int fd;

    BUG_ON(!path || !option);

    if (devname)
        snprintf(buf, sizeof(buf), "%s/%s/%s", path, devname, option);
    else
        snprintf(buf, sizeof(buf), "%s/%s", path, option);
    fd = open(buf, O_RDONLY);
    if (fd < 0)
        FATAL(2, "open %s: %m", buf);
    if (read(fd, &content, 1) <= 0)
        FATAL(2, "read %s: %m", buf);
    close(fd);
    // Don't try to write the file if not necessary so wsrbd can launched
    // without root permissions.
    if (content != wanted_value) {
        fd = open(buf, O_WRONLY);
        if (fd < 0) {
            WARN("%s: cannot set %s to %c (%m)", devname ? devname : "ipv6", option, wanted_value);
            close(fd);
            return;
        }
        if (write(fd, &wanted_value, 1) <= 0)
            FATAL(2, "write %s: %m", buf);
        close(fd);
    }
}

static void wsbr_tun_mcast_init(int * sock_ptr, const char * if_name)
{
    *sock_ptr = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (*sock_ptr < 0)
        FATAL(1, "%s: socket: %m", __func__);
    // ff02::1 and ff02::2 are automatically joined by Linux when the interface is brought up
    wsbr_tun_join_mcast_group(*sock_ptr, if_name, ADDR_LINK_LOCAL_ALL_RPL_NODES);   // ff02::1a
    wsbr_tun_join_mcast_group(*sock_ptr, if_name, ADDR_REALM_LOCAL_ALL_NODES);      // ff03::1
    wsbr_tun_join_mcast_group(*sock_ptr, if_name, ADDR_REALM_LOCAL_ALL_ROUTERS);    // ff03::2
    wsbr_tun_join_mcast_group(*sock_ptr, if_name, ADDR_ALL_MPL_FORWARDERS);         // ff03::fc
}

int wsbr_tun_join_mcast_group(int sock_mcast, const char *if_name, const uint8_t mcast_group[16])
{
    struct ipv6_mreq mreq;
    int ret;

    mreq.ipv6mr_interface = if_nametoindex(if_name);
    memcpy(&mreq.ipv6mr_multiaddr, mcast_group, 16);
    ret = setsockopt(sock_mcast, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
    WARN_ON(ret < 0, "ipv6 join group \"%s\": %m", tr_ipv6(mcast_group));
    return ret;
}

int wsbr_tun_leave_mcast_group(int sock_mcast, const char *if_name, const uint8_t mcast_group[16])
{
    struct ipv6_mreq mreq;
    int ret;

    mreq.ipv6mr_interface = if_nametoindex(if_name);
    memcpy(&mreq.ipv6mr_multiaddr, mcast_group, 16);
    ret = setsockopt(sock_mcast, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq));
    WARN_ON(ret < 0, "ipv6 leave group \"%s\": %m", tr_ipv6(mcast_group));
    return ret;
}

void wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    ctxt->tun_fd = wsbr_tun_open(ctxt->config.tun_dev, ctxt->rcp.eui64,
                                 ctxt->config.ipv6_prefix, ctxt->config.tun_autoconf,
                                 strlen(ctxt->config.neighbor_proxy));
    // It is also possible to use Netlink interface through DEVCONF_ACCEPT_RA
    // but this API is not mapped in libnl-route.
    wsbr_sysctl_set("/proc/sys/net/ipv6/conf", ctxt->config.tun_dev, "accept_ra", '0');
    if (strlen(ctxt->config.neighbor_proxy)) {
        wsbr_sysctl_set("/proc/sys/net/ipv6/conf", ctxt->config.neighbor_proxy, "proxy_ndp", '1');
        wsbr_sysctl_set("/proc/sys/net/ipv6/neigh", ctxt->config.neighbor_proxy, "proxy_delay", '0');
    }
    wsbr_tun_mcast_init(&ctxt->sock_mcast, ctxt->config.tun_dev);
}

static bool is_icmpv6_type_supported_by_wisun(uint8_t iv6t)
{
    // ICMPv6 error messages, see RFC 4443
    // ICMPv6 informational messages, see RFC 4443 (Ping, Echo Request and Reply)
    // Neighbor Soliciation and Neighbor Advertisement, see RFC 6775
    // RPL, see RFC 6550 and 9010
    // The rest is not supported by Wi-SUN
    if ((iv6t >= ICMPV6_TYPE_ERROR_DESTINATION_UNREACH && iv6t <= ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM) ||
         iv6t == ICMPV6_TYPE_INFO_ECHO_REQUEST ||
         iv6t == ICMPV6_TYPE_INFO_ECHO_REPLY ||
         iv6t == ICMPV6_TYPE_INFO_RPL_CONTROL)
        return true;
    else
        return false;
}

void wsbr_tun_read(struct wsbr_ctxt *ctxt)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    uint8_t buf[1504]; // Max ethernet frame size + TUN header
    struct iobuf_read iobuf = { .data = buf };
    uint8_t ip_version, nxthdr;
    buffer_t *buf_6lowpan;
    const uint8_t *eui64;
    const uint8_t *ipv6;

    if (lowpan_adaptation_queue_size(ctxt->rcp_if_id) > 2)
        return;
    iobuf.data_size = read(ctxt->tun_fd, buf, sizeof(buf));

    ip_version = FIELD_GET(IPV6_VERSION_MASK, iobuf_pop_be32(&iobuf));
    if (ip_version != 6) {
        WARN("tun-rx: unsupported ip version %d", ip_version);
        return;
    }

    buf_6lowpan = buffer_get_minimal(iobuf.data_size);
    if (!buf_6lowpan)
        FATAL(1,"could not allocate tun buffer_t");
    buf_6lowpan->interface = cur;
    buffer_data_add(buf_6lowpan, iobuf.data, iobuf.data_size);

    buf_6lowpan->payload_length    = iobuf_pop_be16(&iobuf);
    nxthdr                         = iobuf_pop_u8(&iobuf);
    buf_6lowpan->options.hop_limit = iobuf_pop_u8(&iobuf);
    buf_6lowpan->src_sa.addr_type = ADDR_IPV6;
    iobuf_pop_data(&iobuf, buf_6lowpan->src_sa.address, 16);
    buf_6lowpan->dst_sa.addr_type = ADDR_IPV6;
    iobuf_pop_data(&iobuf, buf_6lowpan->dst_sa.address, 16);

    if (addr_is_ipv6_multicast(buf_6lowpan->dst_sa.address)) {
        if(!addr_am_group_member_on_interface(cur, buf_6lowpan->dst_sa.address)) {
            buffer_free(buf_6lowpan);
            return;
        }
        if (!memcmp(buf_6lowpan->dst_sa.address, ADDR_ALL_MPL_FORWARDERS, 16))
            buf_6lowpan->options.mpl_fwd_workaround = true;
    }

    if (nxthdr == SOL_TCP || nxthdr == SOL_UDP) {
        buf_6lowpan->src_sa.port = iobuf_pop_be16(&iobuf);
        buf_6lowpan->dst_sa.port = iobuf_pop_be16(&iobuf);
        // Inspect DHCP packets to maintain a table for EUI-64/IPv6 association
        if (nxthdr == SOL_UDP && buf_6lowpan->src_sa.port == DHCPV6_SERVER_PORT) {
            iobuf_pop_be16(&iobuf); // Length
            iobuf_pop_be16(&iobuf); // Checksum
            if (!dhcp_dpi_get_lease(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf), &eui64, &ipv6))
                wsbr_dhcp_lease_update(ctxt, eui64, ipv6);
        }
    } else if (nxthdr == SOL_ICMPV6) {
        if (!is_icmpv6_type_supported_by_wisun(iobuf_pop_u8(&iobuf))) {
            buffer_free(buf_6lowpan);
            return;
        }
    }

    buf_6lowpan->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6_FWD);
    protocol_push(buf_6lowpan);
}
