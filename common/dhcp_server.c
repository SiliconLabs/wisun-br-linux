/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>

#include "common/capture.h"
#include "common/log.h"
#include "common/iobuf.h"
#include "common/dhcp_common.h"
#include "common/specs/dhcpv6.h"

#include "dhcp_server.h"

static int dhcp_handle_request(struct dhcp_server *dhcp,
                                struct iobuf_read *req, struct iobuf_write *reply);
static int dhcp_handle_request_fwd(struct dhcp_server *dhcp,
                                    struct iobuf_read *req, struct iobuf_write *reply);

static void dhcp_send_reply(struct dhcp_server *dhcp, struct sockaddr_in6 *dest,
                            struct iobuf_write *reply)
{
    int ret;

    dest->sin6_scope_id = dhcp->tun_if_id;
    dhcp_trace_tx(reply->data, reply->len, &dest->sin6_addr);
    ret = xsendto(dhcp->fd, reply->data, reply->len, 0,
                  (struct sockaddr *)dest, sizeof(struct sockaddr_in6));
    WARN_ON(ret < 0, "%s: sendmsg: %m", __func__);
}

static int dhcp_handle_request_fwd(struct dhcp_server *dhcp,
                                    struct iobuf_read *req, struct iobuf_write *reply)
{
    struct iobuf_read opt_interface_id, opt_relay;
    struct iobuf_write relay_reply = { };
    const uint8_t *linkaddr, *peeraddr;
    uint8_t hopcount;

    hopcount = iobuf_pop_u8(req);
    linkaddr = iobuf_pop_data_ptr(req, 16);
    peeraddr = iobuf_pop_data_ptr(req, 16);
    iobuf_push_u8(reply, DHCPV6_MSG_RELAY_REPLY);
    iobuf_push_u8(reply, hopcount);
    iobuf_push_data(reply, linkaddr, 16);
    iobuf_push_data(reply, peeraddr, 16);
    if (dhcp_get_option(iobuf_ptr(req), iobuf_remaining_size(req),
                        DHCPV6_OPT_INTERFACE_ID, &opt_interface_id) > 0) {
        iobuf_push_be16(reply, DHCPV6_OPT_INTERFACE_ID);
        iobuf_push_be16(reply, opt_interface_id.data_size);
        iobuf_push_data(reply, opt_interface_id.data, opt_interface_id.data_size);
    }
    if (dhcp_get_option(iobuf_ptr(req), iobuf_remaining_size(req),
                        DHCPV6_OPT_RELAY, &opt_relay) < 0) {
        TRACE(TR_DROP, "drop %-9s: missing relay option", "dhcp");
        return -EINVAL;
    }
    if (dhcp_handle_request(dhcp, &opt_relay, &relay_reply))
        return -EINVAL;
    iobuf_push_be16(reply, DHCPV6_OPT_RELAY);
    iobuf_push_be16(reply, relay_reply.len);
    iobuf_push_data(reply, relay_reply.data, relay_reply.len);
    iobuf_free(&relay_reply);
    return 0;
}

static int dhcp_handle_request(struct dhcp_server *dhcp,
                                struct iobuf_read *req, struct iobuf_write *reply)
{
    uint24_t transaction;
    uint8_t msg_type;
    uint32_t iaid;
    const uint8_t *hwaddr;
    uint8_t ipv6[16];
    int hwaddr_type;

    msg_type = iobuf_pop_u8(req);
    if (msg_type == DHCPV6_MSG_RELAY_FWD)
        return dhcp_handle_request_fwd(dhcp, req, reply);
    if (msg_type != DHCPV6_MSG_SOLICIT) {
        TRACE(TR_DROP, "drop %-9s: unsupported msg-type 0x%02x", "dhcp", msg_type);
        return -EINVAL;
    }

    transaction = iobuf_pop_be24(req);
    if (dhcp_check_status_code(iobuf_ptr(req), iobuf_remaining_size(req)))
        return -EINVAL;
    if (dhcp_check_rapid_commit(iobuf_ptr(req), iobuf_remaining_size(req)))
        return -EINVAL;
    if (dhcp_check_elapsed_time(iobuf_ptr(req), iobuf_remaining_size(req)))
        return -EINVAL;
    iaid = dhcp_get_identity_association_id(iobuf_ptr(req), iobuf_remaining_size(req));
    if (iaid == UINT32_MAX)
        return -EINVAL;
    hwaddr_type = dhcp_get_client_hwaddr(iobuf_ptr(req), iobuf_remaining_size(req), &hwaddr);
    if (hwaddr_type < 0)
        return -EINVAL;

    memcpy(ipv6, dhcp->prefix, 8);
    memcpy(ipv6 + 8, hwaddr, 8);
    ipv6[8] ^= 0x02;

    iobuf_push_u8(reply, DHCPV6_MSG_REPLY);
    iobuf_push_be24(reply, transaction);
    dhcp_fill_server_id(reply, dhcp->hwaddr);
    dhcp_fill_client_id(reply, hwaddr_type, hwaddr);
    dhcp_fill_identity_association(reply, iaid, ipv6, dhcp->preferred_lifetime, dhcp->valid_lifetime);
    dhcp_fill_rapid_commit(reply);
    return 0;
}

void dhcp_recv(struct dhcp_server *dhcp)
{
    socklen_t src_addr_len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 src_addr;
    struct iobuf_read req = { };
    struct iobuf_write reply = { };
    uint8_t buf[1024];

    req.data = buf;
    req.data_size = xrecvfrom(dhcp->fd, buf, sizeof(buf), 0,
                              (struct sockaddr *)&src_addr, &src_addr_len);
    if (src_addr.sin6_family != AF_INET6) {
        TRACE(TR_DROP, "drop %-9s: not IPv6", "dhcp");
        return;
    }
    dhcp_trace_rx(req.data, req.data_size, &src_addr.sin6_addr);
    if (!dhcp_handle_request(dhcp, &req, &reply))
        dhcp_send_reply(dhcp, &src_addr, &reply);
    iobuf_free(&reply);
}

void dhcp_start(struct dhcp_server *dhcp, const char *tun_dev, uint8_t *hwaddr, uint8_t *prefix)
{
    struct sockaddr_in6 sockaddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(DHCPV6_SERVER_UDP_PORT),
    };

    if (!dhcp->valid_lifetime)
        dhcp->valid_lifetime = 0xFFFFFFFF; // infinite
    if (!dhcp->preferred_lifetime && dhcp->valid_lifetime == 0xFFFFFFFF)
        dhcp->preferred_lifetime = 0xFFFFFFFF; // infinite
    if (!dhcp->preferred_lifetime)
        dhcp->preferred_lifetime = dhcp->valid_lifetime / 2;
    memcpy(dhcp->hwaddr, hwaddr, 8);
    memcpy(dhcp->prefix, prefix, 8);
    dhcp->tun_if_id = if_nametoindex(tun_dev);
    dhcp->fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (dhcp->fd < 0)
        FATAL(1, "%s: socket: %m", __func__);
    capture_register_netfd(dhcp->fd);
    if (setsockopt(dhcp->fd, SOL_SOCKET, SO_BINDTODEVICE, tun_dev, IF_NAMESIZE) < 0)
        FATAL(1, "%s: setsockopt: %m", __func__);
    if (bind(dhcp->fd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
        FATAL(1, "%s: bind: %m", __func__);
}
