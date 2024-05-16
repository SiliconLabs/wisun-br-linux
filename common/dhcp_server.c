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
#include "common/named_values.h"

#include "dhcp_server.h"

// Messages types (RFC3315, section 5.3)
#define DHCPV6_MSG_SOLICIT      1
#define DHCPV6_MSG_ADVERT       2  /* Unused */
#define DHCPV6_MSG_REQUEST      3  /* Unused */
#define DHCPV6_MSG_CONFIRM      4  /* Unused */
#define DHCPV6_MSG_RENEW        5  /* Unused */
#define DHCPV6_MSG_REBIND       6  /* Unused */
#define DHCPV6_MSG_REPLY        7
#define DHCPV6_MSG_RELEASE      8  /* Unused */
#define DHCPV6_MSG_DECLINE      9  /* Unused */
#define DHCPV6_MSG_RECONFIGURE  10 /* Unused */
#define DHCPV6_MSG_INFO_REQUEST 11 /* Unused */
#define DHCPV6_MSG_RELAY_FWD    12
#define DHCPV6_MSG_RELAY_REPLY  13

// Options IDs (RFC3315, section 24.3)
#define DHCPV6_OPT_CLIENT_ID                  0x0001
#define DHCPV6_OPT_SERVER_ID                  0x0002
#define DHCPV6_OPT_IA_NA                      0x0003
#define DHCPV6_OPT_IA_TA                      0x0004 /* Unused */
#define DHCPV6_OPT_IA_ADDRESS                 0x0005
#define DHCPV6_OPT_ORO                        0x0006 /* Unused */
#define DHCPV6_OPT_PREFERENCE                 0x0007 /* Unused */
#define DHCPV6_OPT_ELAPSED_TIME               0x0008
#define DHCPV6_OPT_RELAY                      0x0009
#define DHCPV6_OPT_RESERVED1                  0x000a /* Unused */
#define DHCPV6_OPT_AUTH                       0x000b /* Unused */
#define DHCPV6_OPT_UNICAST                    0x000c /* Unused */
#define DHCPV6_OPT_STATUS_CODE                0x000d
#define DHCPV6_OPT_RAPID_COMMIT               0x000e
#define DHCPV6_OPT_USER_CLASS                 0x000f /* Unused */
#define DHCPV6_OPT_VENDOR_CLASS               0x0010 /* Unused */
#define DHCPV6_OPT_VENDOR_SPECIFIC            0x0011 /* Unused */
#define DHCPV6_OPT_INTERFACE_ID               0x0012
#define DHCPV6_OPT_RECONF_MSG                 0x0013 /* Unused */
#define DHCPV6_OPT_RECONF_ACCEPT              0x0014 /* Unused */

#define DHCPV6_DUID_TYPE_LINK_LAYER_PLUS_TIME 0x0001 /* Unused */
#define DHCPV6_DUID_TYPE_EN                   0x0002 /* Unused */
#define DHCPV6_DUID_TYPE_LINK_LAYER           0x0003
#define DHCPV6_DUID_TYPE_UUID                 0x0004 /* Unused */

#define DHCPV6_DUID_HW_TYPE_EUI48             0x0001 /* Unused */
#define DHCPV6_DUID_HW_TYPE_IEEE802           0x0006
#define DHCPV6_DUID_HW_TYPE_EUI64             0x001b

static const struct name_value dhcp_frames[] = {
    { "sol",      DHCPV6_MSG_SOLICIT },
    { "adv",      DHCPV6_MSG_ADVERT },
    { "req",      DHCPV6_MSG_REQUEST },
    { "confirm",  DHCPV6_MSG_CONFIRM },
    { "renew",    DHCPV6_MSG_RENEW },
    { "rebind",   DHCPV6_MSG_REBIND },
    { "rply",     DHCPV6_MSG_REPLY },
    { "release",  DHCPV6_MSG_RELEASE },
    { "decline",  DHCPV6_MSG_DECLINE },
    { "reconfig", DHCPV6_MSG_RECONFIGURE },
    { "info-req", DHCPV6_MSG_INFO_REQUEST },
    { "rel-fwd",  DHCPV6_MSG_RELAY_FWD },
    { "rel-rply", DHCPV6_MSG_RELAY_REPLY },
    { NULL        },
};

static int dhcp_handle_request(struct dhcp_server *dhcp,
                                struct iobuf_read *req, struct iobuf_write *reply);
static int dhcp_handle_request_fwd(struct dhcp_server *dhcp,
                                    struct iobuf_read *req, struct iobuf_write *reply);

static int dhcp_get_option(const uint8_t *data, size_t len, uint16_t option, struct iobuf_read *option_payload)
{
    uint16_t opt_type, opt_len;
    struct iobuf_read input = {
        .data_size = len,
        .data = data,
    };

    memset(option_payload, 0, sizeof(struct iobuf_read));
    option_payload->err = true;
    while (iobuf_remaining_size(&input)) {
        opt_type = iobuf_pop_be16(&input);
        opt_len = iobuf_pop_be16(&input);
        if (opt_type == option) {
            option_payload->data = iobuf_pop_data_ptr(&input, opt_len);
            if (!option_payload->data)
                return -EINVAL;
            option_payload->err = false;
            option_payload->data_size = opt_len;
            return opt_len;
        }
        iobuf_pop_data_ptr(&input, opt_len);
    }
    return -ENOENT;
}

static int dhcp_get_client_hwaddr(const uint8_t *req, size_t req_len, const uint8_t **hwaddr)
{
    struct iobuf_read opt;
    uint16_t duid_type, ll_type;

    dhcp_get_option(req, req_len, DHCPV6_OPT_CLIENT_ID, &opt);
    if (opt.err)
        return -EINVAL;
    duid_type = iobuf_pop_be16(&opt);
    ll_type = iobuf_pop_be16(&opt);
    if (duid_type != DHCPV6_DUID_TYPE_LINK_LAYER ||
        (ll_type != DHCPV6_DUID_HW_TYPE_EUI64 && ll_type != DHCPV6_DUID_HW_TYPE_IEEE802)) {
        TRACE(TR_DROP, "drop %-9s: unsupported client ID option", "dhcp");
        return -ENOTSUP;
    }
    *hwaddr = iobuf_pop_data_ptr(&opt, 8);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: malformed client ID option", "dhcp");
        return -EINVAL;
    }
    return ll_type;
}

static uint32_t dhcp_get_identity_association_id(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;
    uint32_t ia_id;

    dhcp_get_option(req, req_len, DHCPV6_OPT_IA_NA, &opt);
    ia_id = iobuf_pop_be32(&opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing IA_NA option", "dhcp");
        return UINT32_MAX;
    }
    return ia_id;
}

static int dhcp_check_rapid_commit(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;

    dhcp_get_option(req, req_len, DHCPV6_OPT_RAPID_COMMIT, &opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing rapid commit option", "dhcp");
        return -ENOTSUP;
    }
    return 0;
}

static int dhcp_check_status_code(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;
    uint16_t status;

    dhcp_get_option(req, req_len, DHCPV6_OPT_STATUS_CODE, &opt);
    if (opt.err)
        return 0;
    status = iobuf_pop_be16(&opt);
    if (status) {
        TRACE(TR_DROP, "drop %-9s: status code %d", "dhcp", status);
        return -EFAULT;
    }
    return 0;
}

static int dhcp_check_elapsed_time(const uint8_t *req, size_t req_len)
{
    struct iobuf_read opt;

    dhcp_get_option(req, req_len, DHCPV6_OPT_ELAPSED_TIME, &opt);
    if (opt.err) {
        TRACE(TR_DROP, "drop %-9s: missing elapsed time option", "dhcp");
        return -EINVAL; // Elapsed Time option is mandatory
    }
    return 0;
}

static void dhcp_fill_server_id(struct dhcp_server *dhcp, struct iobuf_write *reply)
{
    iobuf_push_be16(reply, DHCPV6_OPT_SERVER_ID);
    iobuf_push_be16(reply, 2 + 2 + 8);
    iobuf_push_be16(reply, DHCPV6_DUID_TYPE_LINK_LAYER);
    iobuf_push_be16(reply, DHCPV6_DUID_HW_TYPE_EUI64);
    iobuf_push_data(reply, dhcp->hwaddr, 8);
}

static void dhcp_fill_client_id(struct dhcp_server *dhcp, struct iobuf_write *reply,
                                uint16_t hwaddr_type, const uint8_t *hwaddr)
{
    BUG_ON(!hwaddr);
    BUG_ON(hwaddr_type != DHCPV6_DUID_HW_TYPE_EUI64 &&
           hwaddr_type != DHCPV6_DUID_HW_TYPE_IEEE802);

    iobuf_push_be16(reply, DHCPV6_OPT_CLIENT_ID);
    iobuf_push_be16(reply, 2 + 2 + 8);
    iobuf_push_be16(reply, DHCPV6_DUID_TYPE_LINK_LAYER);
    iobuf_push_be16(reply, hwaddr_type);
    iobuf_push_data(reply, hwaddr, 8);
}

static void dhcp_fill_rapid_commit(struct dhcp_server *dhcp, struct iobuf_write *reply)
{
    iobuf_push_be16(reply, DHCPV6_OPT_RAPID_COMMIT);
    iobuf_push_be16(reply, 0);
}

static void dhcp_fill_identity_association(struct dhcp_server *dhcp, struct iobuf_write *reply,
                                           const uint8_t *hwaddr, uint32_t ia_id)
{
    uint8_t ipv6[16];

    BUG_ON(!hwaddr);
    memcpy(ipv6, dhcp->prefix, 8);
    memcpy(ipv6 + 8, hwaddr, 8);
    ipv6[8] ^= 0x02;
    iobuf_push_be16(reply, DHCPV6_OPT_IA_NA);
    iobuf_push_be16(reply, 4 + 4 + 4 + 2 + 2 + 16 + 4 + 4);
    iobuf_push_be32(reply, ia_id);
    iobuf_push_be32(reply, 0); // T1
    iobuf_push_be32(reply, 0); // T2
    iobuf_push_be16(reply, DHCPV6_OPT_IA_ADDRESS);
    iobuf_push_be16(reply, 16 + 4 + 4);
    iobuf_push_data(reply, ipv6, 16);
    iobuf_push_be32(reply, dhcp->preferred_lifetime);
    iobuf_push_be32(reply, dhcp->valid_lifetime);
}

static void dhcp_send_reply(struct dhcp_server *dhcp, struct sockaddr_in6 *dest,
                            struct iobuf_write *reply)
{
    int ret;

    dest->sin6_scope_id = dhcp->tun_if_id;
    TRACE(TR_DHCP, "tx-dhcp %-9s dst:%s",
          val_to_str(reply->data[0], dhcp_frames, "[UNK]"),
          tr_ipv6(dest->sin6_addr.s6_addr));
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

    iobuf_push_u8(reply, DHCPV6_MSG_REPLY);
    iobuf_push_be24(reply, transaction);
    dhcp_fill_server_id(dhcp, reply);
    dhcp_fill_client_id(dhcp, reply, hwaddr_type, hwaddr);
    dhcp_fill_identity_association(dhcp, reply, hwaddr, iaid);
    dhcp_fill_rapid_commit(dhcp, reply);
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
    TRACE(TR_DHCP, "rx-dhcp %-9s src:%s",
          val_to_str(req.data[0], dhcp_frames, "[UNK]"),
          tr_ipv6(src_addr.sin6_addr.s6_addr));
    if (!dhcp_handle_request(dhcp, &req, &reply))
        dhcp_send_reply(dhcp, &src_addr, &reply);
    iobuf_free(&reply);
}

void dhcp_start(struct dhcp_server *dhcp, const char *tun_dev, uint8_t *hwaddr, uint8_t *prefix)
{
    struct sockaddr_in6 sockaddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(DHCPV6_SERVER_PORT),
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
