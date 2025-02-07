/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/specs/dhcpv6.h"
#include "common/dhcp_common.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/netinet_in_extra.h"

#include "dhcp_relay.h"

void dhcp_relay_start(struct dhcp_relay *relay)
{
    struct sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(DHCPV6_SERVER_UDP_PORT),
    };
    int ret;

    BUG_ON(!relay->hop_limit);
    BUG_ON(IN6_IS_ADDR_UNSPECIFIED(&relay->link_addr));
    BUG_ON(IN6_IS_ADDR_UNSPECIFIED(&relay->server_addr));

    relay->fd = socket(AF_INET6, SOCK_DGRAM, 0);
    FATAL_ON(relay->fd < 0, 1, "%s: socket: %m", __func__);
    ret = bind(relay->fd, (struct sockaddr *)&sin6, sizeof(sin6));
    FATAL_ON(ret < 0, 1, "%s: bind: %m", __func__);
}

void dhcp_relay_stop(struct dhcp_relay *relay)
{
    close(relay->fd);
    relay->fd = -1;
}

// RFC 8415 19.1. Relaying a Client Message or a Relay-forward Message
static void dhcp_relay_fwd(const struct dhcp_relay *relay,
                           const void *buf, size_t buf_len,
                           const struct sockaddr_in6 *peer, uint8_t hops)
{
    const bool has_ifindex = IN6_IS_ADDR_LINKLOCAL(&peer->sin6_addr);
    struct dhcpv6_relay_hdr hdr = {
        .type = DHCPV6_MSG_RELAY_FWD,
        .hops = hops,
        .link = IN6_IS_ADDR_UC_GLOBAL(&peer->sin6_addr) ? in6addr_any : relay->link_addr,
        .peer = peer->sin6_addr,
    };
    struct dhcpv6_opt opt_ifindex = {
        .code = htons(DHCPV6_OPT_INTERFACE_ID),
        .len  = htons(sizeof(peer->sin6_scope_id)),
    };
    struct dhcpv6_opt opt_relay = {
        .code = htons(DHCPV6_OPT_RELAY),
        .len  = htons(buf_len),
    };
    struct iovec iov[] = {
        { &hdr,                         sizeof(hdr) },
        { &opt_ifindex,                 has_ifindex ? sizeof(opt_ifindex) : 0 },
        { (void *)&peer->sin6_scope_id, has_ifindex ? sizeof(peer->sin6_scope_id) : 0 },
        { &opt_relay,                   sizeof(opt_relay) },
        { (void *)buf,                  buf_len },
    };
    struct sockaddr_in6 dst = {
        .sin6_family = AF_INET6,
        .sin6_addr = relay->server_addr,
        .sin6_port = htons(DHCPV6_SERVER_UDP_PORT),
    };
    struct msghdr msg = {
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
        .msg_name    = &dst,
        .msg_namelen = sizeof(dst),
    };
    ssize_t ret;

    dhcp_trace_tx(&hdr, sizeof(hdr), &dst.sin6_addr);
    ret = sendmsg(relay->fd, &msg, 0);
    WARN_ON(ret < 0, "%s: sendmsg: %m", __func__);
}

// RFC 8415 19.2. Relaying a Relay-reply Message
static void dhcp_relay_reply(const struct dhcp_relay *relay,
                             const void *buf, size_t buf_len)
{
    const struct dhcpv6_relay_hdr *hdr;
    struct sockaddr_in6 dst = { };
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };
    struct iobuf_read opt;
    ssize_t len;

    hdr = iobuf_pop_data_ptr(&iobuf, sizeof(*hdr));
    len = dhcp_get_option(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf),
                          DHCPV6_OPT_INTERFACE_ID, &opt);
    if (len >= 0)
        iobuf_pop_data(&opt, &dst.sin6_scope_id, sizeof(dst.sin6_scope_id));
    len = dhcp_get_option(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf),
                          DHCPV6_OPT_RELAY, &opt);
    if (len < 1) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "dhcp");
        return;
    }
    dst.sin6_family = AF_INET6;
    dst.sin6_addr = hdr->peer;
    dst.sin6_port = htons(opt.data[0] == DHCPV6_MSG_RELAY_REPLY ?
                          DHCPV6_SERVER_UDP_PORT : DHCPV6_CLIENT_UDP_PORT);
    dhcp_trace_tx(opt.data, opt.data_size, &dst.sin6_addr);
    len = sendto(relay->fd, opt.data, opt.data_size, 0,
                 (struct sockaddr *)&dst, sizeof(dst));
    WARN_ON(len < 0, "%s: sendto %s: %m", __func__, tr_ipv6(dst.sin6_addr.s6_addr));
}

// RFC 8415 19. Relay Agent Behavior
void dhcp_relay_recv(const struct dhcp_relay *relay)
{
    const struct dhcpv6_relay_hdr *hdr;
    struct sockaddr_in6 src;
    uint8_t buf[1500];
    ssize_t buf_len;

    buf_len = recvfrom(relay->fd, buf, sizeof(buf), 0,
                       (struct sockaddr *)&src, (socklen_t[1]){ sizeof(src) });
    if (buf_len < 0) {
        WARN("%s: recvfrom: %m", __func__);
        return;
    }
    dhcp_trace_rx(buf, buf_len, &src.sin6_addr);

    switch (buf_len >= 1 ? buf[0] : 0) {
    case DHCPV6_MSG_RELAY_FWD:
        if (buf_len < sizeof(*hdr)) {
            TRACE(TR_DROP, "drop %-9s: malformed packet", "dhcp");
            return;
        }
        hdr = (struct dhcpv6_relay_hdr *)buf;
        if (hdr->hops >= relay->hop_limit) {
            TRACE(TR_DROP, "drop %-9s: hop limit exceeded", "dhcp");
            return;
        }
        dhcp_relay_fwd(relay, buf, buf_len, &src, hdr->hops + 1);
        break;
    case DHCPV6_MSG_RELAY_REPLY:
        dhcp_relay_reply(relay, buf, buf_len);
        break;
    // RFC 7283 Handling Unknown DHCPv6 Messages
    default:
        dhcp_relay_fwd(relay, buf, buf_len, &src, 0);
        break;
    }
}
