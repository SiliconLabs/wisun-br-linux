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
#include "common/pktbuf.h"
#include "common/netinet_in_extra.h"
#include "common/tun.h"
#include "common/specs/ipv6.h"
#include "ipv6/ipv6.h"
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

    ret = xwrite(ctxt->net_if.tun.fd, buf, len);
    TRACE(TR_TUN, "tx-tun: %u bytes", len);
    if (ret < 0)
        WARN("%s: write: %m", __func__);
    else if (ret != len)
        WARN("%s: write: Short write: %zd < %d", __func__, ret, len);
    return ret;
}

void wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    struct in6_addr addr;
    int ret;

    strcpy(ctxt->net_if.tun.ifname, ctxt->config.tun_dev);
    tun_init(&ctxt->net_if.tun, ctxt->config.tun_autoconf);
    if (ctxt->config.neighbor_proxy[0]) {
        ctxt->net_if.ndp_proxy_ifindex = if_nametoindex(ctxt->config.neighbor_proxy);
        FATAL_ON(!ctxt->net_if.ndp_proxy_ifindex, 2,
                 "if_nametoindex %s: %m", ctxt->config.neighbor_proxy);
    }
    capture_register_netfd(ctxt->net_if.tun.fd);

    if (ctxt->config.tun_autoconf) {
        memcpy(addr.s6_addr + 8, &ctxt->rcp.eui64, 8);
        addr.s6_addr[8] ^= 0x02;

        memcpy(addr.s6_addr, ADDR_LINK_LOCAL_PREFIX, 8);
        tun_addr_add(&ctxt->net_if.tun, &addr, 64);

        memcpy(addr.s6_addr, &ctxt->config.ipv6_prefix, 8);
        tun_addr_add(&ctxt->net_if.tun, &addr, ctxt->config.neighbor_proxy[0] ? 128 : 64);
        if (ctxt->config.neighbor_proxy[0])
            tun_neigh_add_proxy(&ctxt->net_if.tun, &addr, ctxt->net_if.ndp_proxy_ifindex);
    }

    // It is also possible to use Netlink interface through DEVCONF_ACCEPT_RA
    // but this API is not mapped in libnl-route.
    tun_sysctl_set("/proc/sys/net/ipv6/conf", ctxt->net_if.tun.ifname, "accept_ra", "0");
    if (strlen(ctxt->config.neighbor_proxy)) {
        tun_sysctl_set("/proc/sys/net/ipv6/conf", ctxt->config.neighbor_proxy, "proxy_ndp", "1");
        tun_sysctl_set("/proc/sys/net/ipv6/neigh", ctxt->config.neighbor_proxy, "proxy_delay", "0");
    }

    // ff02::1 and ff02::2 are automatically joined by Linux when the interface is brought up
    ret = tun_addr_add_mc(&ctxt->net_if.tun, (const struct in6_addr *)ADDR_LINK_LOCAL_ALL_RPL_NODES); // ff02::1a
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_LINK_LOCAL_ALL_RPL_NODES), strerror(-ret));
    ret = tun_addr_add_mc(&ctxt->net_if.tun, (const struct in6_addr *)ADDR_REALM_LOCAL_ALL_NODES);    // ff03::1
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_REALM_LOCAL_ALL_NODES), strerror(-ret));
    ret = tun_addr_add_mc(&ctxt->net_if.tun, (const struct in6_addr *)ADDR_REALM_LOCAL_ALL_ROUTERS);  // ff03::2
    if (ret < 0 && ret != -EADDRINUSE)
        FATAL(2, "tun_addr_add_mc %s %s", tr_ipv6(ADDR_REALM_LOCAL_ALL_ROUTERS), strerror(-ret));
    ret = tun_addr_add_mc(&ctxt->net_if.tun, (const struct in6_addr *)ADDR_ALL_MPL_FORWARDERS);       // ff03::fc
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
    buffer_t *buf_6lowpan = NULL;
    struct pktbuf pktbuf = { };
    uint8_t ip_version, nxthdr;
    ssize_t read_len;
    uint8_t type;

    pktbuf_push_tail(&pktbuf, NULL, 1504); // Max ethernet frame size + TUN header
    read_len = xread(ctxt->net_if.tun.fd, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    if (read_len < 0) {
        WARN("%s: read: %m", __func__);
        goto cleanup;
    }
    pktbuf.offset_tail = read_len;
    TRACE(TR_TUN, "rx-tun: %zd bytes", read_len);

    ip_version = FIELD_GET(IPV6_MASK_VERSION, pktbuf_pop_head_be32(&pktbuf));
    if (ip_version != 6) {
        TRACE(TR_DROP, "drop %-9s: unsupported IPv%u", "tun", ip_version);
        goto cleanup;
    }

    buf_6lowpan = buffer_get_minimal(read_len);
    if (!buf_6lowpan)
        FATAL(1,"could not allocate tun buffer_t");
    buf_6lowpan->interface = &ctxt->net_if;
    buffer_data_add(buf_6lowpan, pktbuf.buf, read_len);

    pktbuf_pop_head_be16(&pktbuf); /* Payload length */
    nxthdr                         = pktbuf_pop_head_u8(&pktbuf);
    buf_6lowpan->options.hop_limit = pktbuf_pop_head_u8(&pktbuf);
    buf_6lowpan->src_sa.addr_type = ADDR_IPV6;
    pktbuf_pop_head(&pktbuf, buf_6lowpan->src_sa.address, 16);
    buf_6lowpan->dst_sa.addr_type = ADDR_IPV6;
    pktbuf_pop_head(&pktbuf, buf_6lowpan->dst_sa.address, 16);

    if (addr_is_ipv6_multicast(buf_6lowpan->dst_sa.address)) {
        if(!addr_am_group_member_on_interface(&ctxt->net_if, buf_6lowpan->dst_sa.address)) {
            TRACE(TR_DROP, "drop %-9s: unsupported dst=%s", "tun", tr_ipv6(buf_6lowpan->dst_sa.address));
            goto cleanup;
        }
        ipv6_consider_forwarding_multicast_packet_to_lfn(buf_6lowpan, true);
        if (addr_ipv6_scope(buf_6lowpan->dst_sa.address) > IPV6_SCOPE_LINK_LOCAL) {
            pktbuf.offset_head = 0;
            mpl_msg_gen(&ctxt->net_if.mpl, (struct in6_addr *)buf_6lowpan->src_sa.address, &pktbuf);
            goto cleanup;
        }
    }

    if (nxthdr == SOL_TCP || nxthdr == SOL_UDP) {
        buf_6lowpan->src_sa.port = pktbuf_pop_head_be16(&pktbuf);
        buf_6lowpan->dst_sa.port = pktbuf_pop_head_be16(&pktbuf);
    } else if (nxthdr == SOL_ICMPV6) {
        type = pktbuf_pop_head_u8(&pktbuf);
        if (!is_icmpv6_type_supported_by_wisun(type)) {
            TRACE(TR_DROP, "drop %-9s: unsupported ICMPv6 type %u", "tun", type);
            goto cleanup;
        }
    }

    buf_6lowpan->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6_FWD);
    protocol_push(buf_6lowpan);
    pktbuf_free(&pktbuf);
    return;

cleanup:
    if (buf_6lowpan)
        buffer_free(buf_6lowpan);
    pktbuf_free(&pktbuf);
}
