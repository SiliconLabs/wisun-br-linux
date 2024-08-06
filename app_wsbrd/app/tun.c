/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <errno.h>
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
#include "common/capture.h"
#include "common/log.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common/netinet_in_extra.h"
#include "common/tun.h"
#include "common/specs/ipv6.h"
#include "common/specs/icmpv6.h"

#include "6lowpan/lowpan_adaptation_interface.h"
#include "net/protocol.h"
#include "net/netaddr_types.h"
#include "net/ns_buffer.h"
#include "tun.h"
#include "wsbrd.h"

ssize_t wsbr_tun_write(uint8_t *buf, uint16_t len)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    ssize_t ret;

    ret = xwrite(ctxt->tun.fd, buf, len);
    TRACE(TR_TUN, "tx-tun: %u bytes", len);
    if (ret < 0)
        WARN("%s: write: %m", __func__);
    else if (ret != len)
        WARN("%s: write: Short write: %zd < %d", __func__, ret, len);
    return ret;
}

void tun_add_node_to_proxy_neightbl(struct net_if *if_entry, const uint8_t address[16])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct rtnl_neigh *nl_neigh;
    struct nl_addr *src_ipv6_nl_addr;
    struct nl_cache *cache;
    struct nl_sock *sock;
    int err;

    if (strlen(ctxt->config.neighbor_proxy) == 0)
        return;

    sock = nl_socket_alloc();
    BUG_ON(!sock);
    err = nl_connect(sock, NETLINK_ROUTE);
    FATAL_ON(err < 0, 2, "nl_connect: %s", nl_geterror(err));

    err = rtnl_neigh_alloc_cache(sock, &cache);
    FATAL_ON(err < 0, 2, "rtnl_neigh_alloc_cache: %s", nl_geterror(err));
    src_ipv6_nl_addr = nl_addr_build(AF_INET6, address, 16);
    FATAL_ON(!src_ipv6_nl_addr, 2, "nl_addr_build: %s", strerror(ENOMEM));
    nl_neigh = rtnl_neigh_get(cache, ctxt->tun.ifindex, src_ipv6_nl_addr);
    if (nl_neigh)
        goto ret_free_addr;
    nl_neigh = rtnl_neigh_alloc();
    BUG_ON(!nl_neigh);

    rtnl_neigh_set_ifindex(nl_neigh, ctxt->tun.ifindex);
    rtnl_neigh_set_dst(nl_neigh, src_ipv6_nl_addr);
    rtnl_neigh_set_flags(nl_neigh, NTF_PROXY);
    rtnl_neigh_set_flags(nl_neigh, NTF_ROUTER);
    err = rtnl_neigh_add(sock, nl_neigh, NLM_F_CREATE);
    FATAL_ON(err < 0, 2, "rtnl_neigh_add: %s", nl_geterror(err));

    rtnl_neigh_put(nl_neigh);
ret_free_addr:
    nl_addr_put(src_ipv6_nl_addr);
    nl_socket_free(sock);
}

void tun_add_ipv6_direct_route(struct net_if *if_entry, const uint8_t address[16])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct rtnl_nexthop* nl_nexthop;
    struct rtnl_route *nl_route;
    struct nl_addr *ipv6_nl_addr;
    struct nl_sock *sock;
    int err;

    if (strlen(ctxt->config.neighbor_proxy) == 0)
        return;

    sock = nl_socket_alloc();
    BUG_ON(!sock);
    err = nl_connect(sock, NETLINK_ROUTE);
    FATAL_ON(err < 0, 2, "nl_connect: %s", nl_geterror(err));

    ipv6_nl_addr = nl_addr_build(AF_INET6, address, 16);
    FATAL_ON(!ipv6_nl_addr, 2, "nl_addr_build: %s", strerror(ENOMEM));
    nl_route = rtnl_route_alloc();
    BUG_ON(!nl_route);
    nl_nexthop = rtnl_route_nh_alloc();
    BUG_ON(!nl_nexthop);

    rtnl_route_set_iif(nl_route, AF_INET6);
    err = rtnl_route_set_dst(nl_route, ipv6_nl_addr);
    FATAL_ON(err < 0, 2, "rtnl_route_set_dst: %s", nl_geterror(err));
    rtnl_route_nh_set_ifindex(nl_nexthop, ctxt->tun.ifindex);
    rtnl_route_add_nexthop(nl_route, nl_nexthop);
    err = rtnl_route_add(sock, nl_route, 0);
    if (err < 0 && err != -NLE_EXIST)
        FATAL(2, "rtnl_route_add: %s", nl_geterror(err));

    rtnl_route_put(nl_route);
    nl_addr_put(ipv6_nl_addr);
    nl_socket_free(sock);
}

void wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    struct in6_addr addr;
    int ret;

    strcpy(ctxt->tun.ifname, ctxt->config.tun_dev);
    tun_init(&ctxt->tun, ctxt->config.tun_autoconf);
    capture_register_netfd(ctxt->tun.fd);

    if (ctxt->config.tun_autoconf) {
        memcpy(addr.s6_addr + 8, ctxt->rcp.eui64, 8);
        addr.s6_addr[8] ^= 0x02;

        memcpy(addr.s6_addr, ADDR_LINK_LOCAL_PREFIX, 8);
        tun_addr_add(&ctxt->tun, &addr, ctxt->config.neighbor_proxy[0] ? 128 : 64);
        if (ctxt->config.neighbor_proxy[0])
            tun_add_node_to_proxy_neightbl(NULL, addr.s6_addr);

        memcpy(addr.s6_addr, ctxt->config.ipv6_prefix, 8);
        tun_addr_add(&ctxt->tun, &addr, ctxt->config.neighbor_proxy[0] ? 128 : 64);
        if (ctxt->config.neighbor_proxy[0])
            tun_add_node_to_proxy_neightbl(NULL, addr.s6_addr);
    }

    // It is also possible to use Netlink interface through DEVCONF_ACCEPT_RA
    // but this API is not mapped in libnl-route.
    tun_sysctl_set("/proc/sys/net/ipv6/conf", ctxt->tun.ifname, "accept_ra", '0');
    if (strlen(ctxt->config.neighbor_proxy)) {
        tun_sysctl_set("/proc/sys/net/ipv6/conf", ctxt->config.neighbor_proxy, "proxy_ndp", '1');
        tun_sysctl_set("/proc/sys/net/ipv6/neigh", ctxt->config.neighbor_proxy, "proxy_delay", '0');
    }

    // ff02::1 and ff02::2 are automatically joined by Linux when the interface is brought up
    ret = tun_addr_add_mc(&ctxt->tun, (const struct in6_addr *)ADDR_LINK_LOCAL_ALL_RPL_NODES); // ff02::1a
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_LINK_LOCAL_ALL_RPL_NODES), strerror(-ret));
    ret = tun_addr_add_mc(&ctxt->tun, (const struct in6_addr *)ADDR_REALM_LOCAL_ALL_NODES);    // ff03::1
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_REALM_LOCAL_ALL_NODES), strerror(-ret));
    ret = tun_addr_add_mc(&ctxt->tun, (const struct in6_addr *)ADDR_REALM_LOCAL_ALL_ROUTERS);  // ff03::2
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_REALM_LOCAL_ALL_ROUTERS), strerror(-ret));
    ret = tun_addr_add_mc(&ctxt->tun, (const struct in6_addr *)ADDR_ALL_MPL_FORWARDERS);       // ff03::fc
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_ALL_MPL_FORWARDERS), strerror(-ret));
}

static bool is_icmpv6_type_supported_by_wisun(uint8_t iv6t)
{
    // ICMPv6 error messages, see RFC 4443
    // ICMPv6 informational messages, see RFC 4443 (Ping, Echo Request and Reply)
    // Neighbor Soliciation and Neighbor Advertisement, see RFC 6775
    // RPL, see RFC 6550 and 9010
    // The rest is not supported by Wi-SUN
    if ((iv6t >= ICMPV6_TYPE_ERROR_DESTINATION_UNREACH && iv6t <= ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM) ||
         iv6t == ICMPV6_TYPE_ECHO_REQUEST ||
         iv6t == ICMPV6_TYPE_ECHO_REPLY ||
         iv6t == ICMPV6_TYPE_RPL)
        return true;
    else
        return false;
}

void wsbr_tun_read(struct wsbr_ctxt *ctxt)
{
    uint8_t buf[1504]; // Max ethernet frame size + TUN header
    struct iobuf_read iobuf = { .data = buf };
    uint8_t ip_version, nxthdr;
    buffer_t *buf_6lowpan;
    uint8_t type;

    iobuf.data_size = xread(ctxt->tun.fd, buf, sizeof(buf));
    if (iobuf.data_size < 0) {
        WARN("%s: read: %m", __func__);
        return;
    }
    TRACE(TR_TUN, "rx-tun: %i bytes", iobuf.data_size);

    ip_version = FIELD_GET(IPV6_MASK_VERSION, iobuf_pop_be32(&iobuf));
    if (ip_version != 6) {
        TRACE(TR_DROP, "drop %-9s: unsupported IPv%u", "tun", ip_version);
        return;
    }

    buf_6lowpan = buffer_get_minimal(iobuf.data_size);
    if (!buf_6lowpan)
        FATAL(1,"could not allocate tun buffer_t");
    buf_6lowpan->interface = &ctxt->net_if;
    buffer_data_add(buf_6lowpan, iobuf.data, iobuf.data_size);

    iobuf_pop_be16(&iobuf); /* Payload length */
    nxthdr                         = iobuf_pop_u8(&iobuf);
    buf_6lowpan->options.hop_limit = iobuf_pop_u8(&iobuf);
    buf_6lowpan->src_sa.addr_type = ADDR_IPV6;
    iobuf_pop_data(&iobuf, buf_6lowpan->src_sa.address, 16);
    buf_6lowpan->dst_sa.addr_type = ADDR_IPV6;
    iobuf_pop_data(&iobuf, buf_6lowpan->dst_sa.address, 16);

    if (addr_is_ipv6_multicast(buf_6lowpan->dst_sa.address)) {
        if(!addr_am_group_member_on_interface(&ctxt->net_if, buf_6lowpan->dst_sa.address)) {
            TRACE(TR_DROP, "drop %-9s: unsupported dst=%s", "tun", tr_ipv6(buf_6lowpan->dst_sa.address));
            buffer_free(buf_6lowpan);
            return;
        }
        if (!memcmp(buf_6lowpan->dst_sa.address, ADDR_ALL_MPL_FORWARDERS, 16))
            buf_6lowpan->options.mpl_fwd_workaround = true;
    }

    if (nxthdr == SOL_TCP || nxthdr == SOL_UDP) {
        buf_6lowpan->src_sa.port = iobuf_pop_be16(&iobuf);
        buf_6lowpan->dst_sa.port = iobuf_pop_be16(&iobuf);
    } else if (nxthdr == SOL_ICMPV6) {
        type = iobuf_pop_u8(&iobuf);
        if (!is_icmpv6_type_supported_by_wisun(type)) {
            TRACE(TR_DROP, "drop %-9s: unsupported ICMPv6 type %u", "tun", type);
            buffer_free(buf_6lowpan);
            return;
        }
    }

    buf_6lowpan->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6_FWD);
    protocol_push(buf_6lowpan);
}
