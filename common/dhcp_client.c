/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2024 Silicon Laboratories Inc. (www.silabs.com)

 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections of
 * the MSLA applicable to Object Code, Source Code and Modified Open Source Code.
 * By using this software, you agree to the terms of the MSLA.

 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#define _DEFAULT_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>

#include "common/specs/dhcpv6.h"
#include "common/string_extra.h"
#include "common/dhcp_common.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/capture.h"
#include "common/iobuf.h"
#include "common/rand.h"
#include "common/log.h"
#include "common/tun.h"

#include "dhcp_client.h"

static void dhcp_client_send(struct dhcp_client *client, struct iobuf_write *buf)
{
    struct sockaddr_in6 dst = {
        .sin6_family = AF_INET6,
        .sin6_addr = client->get_dst(client),
        .sin6_port = htons(DHCPV6_SERVER_UDP_PORT),
        .sin6_scope_id = client->tun_if_id,
     };
    int ret;

    TRACE(TR_DHCP, "dhcp tx %s", val_to_str(buf->data[0], dhcp_frames, "[UNK]"));
    ret = xsendto(client->fd, buf->data, buf->len, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in6));
    WARN_ON(ret < 0, "%s: xsendto: %m", __func__);
}

static void dhcp_client_solicit(struct rfc8415_txalg *txalg)
{
    struct dhcp_client *client = container_of(txalg, struct dhcp_client, solicit_txalg);
    struct iobuf_write buf = { };

    iobuf_push_u8(&buf, DHCPV6_MSG_SOLICIT);
    iobuf_push_be24(&buf, client->tid);

    dhcp_fill_elapsed_time(&buf, &client->start_time);
    dhcp_fill_client_id(&buf, DHCPV6_DUID_HW_TYPE_IEEE802, client->eui64);
    dhcp_fill_rapid_commit(&buf);
    dhcp_fill_identity_association(&buf, 0, NULL, 0, 0);

    dhcp_client_send(client, &buf);

    iobuf_free(&buf);
}

static void dhcp_client_t1_expired(struct timer_group *group, struct timer_entry *timer)
{
    struct dhcp_client *client = container_of(timer, struct dhcp_client, t1_timer);

    rfc8415_txalg_start(&client->solicit_txalg);
}

static void dhcp_client_addr_expired(struct timer_group *group, struct timer_entry *timer)
{
    struct dhcp_client *client = container_of(timer, struct dhcp_client, iaaddr.valid_lifetime_timer);

    TRACE(TR_DHCP, "dhcp del %s", tr_ipv6(client->iaaddr.ipv6.s6_addr));

    if (client->on_addr_del)
        client->on_addr_del(client, &client->iaaddr.ipv6);
    memset(&client->iaaddr, 0, sizeof(struct dhcp_iaaddr));
}

static int dhcp_client_handle_iaaddr(struct dhcp_client *client, const uint8_t *buf, size_t buf_len)
{
    uint32_t preferred_lifetime_s;
    uint32_t valid_lifetime_s;
    struct iobuf_read opt_buf;
    struct in6_addr addr;

    dhcp_get_option(buf, buf_len, DHCPV6_OPT_IA_ADDRESS, &opt_buf);
    if (opt_buf.err) {
        TRACE(TR_DROP, "drop %-9s: missing iaaddr option", "dhcp");
        return -ENOTSUP;
    }

    iobuf_pop_data(&opt_buf, &addr, sizeof(addr));
    preferred_lifetime_s = iobuf_pop_be32(&opt_buf);
    valid_lifetime_s     = iobuf_pop_be32(&opt_buf);
    if (opt_buf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed iaaddr option", "dhcp");
        return -EINVAL;
    }

    /*
     *   RFC3315 - Section 22.6
     * A client discards any addresses for which the preferred lifetime is
     * greater than the valid lifetime.
     */
    if (preferred_lifetime_s > valid_lifetime_s) {
        TRACE(TR_DROP, "drop %-9s: invalid preferred lifetime (> valid lifetime)", "dhcp");
        return -EINVAL;
    }

    /*
     *   RFC3315 - Section 18.1.8
     * [...] the client updates the information it has recorded about IAs
     * from the IA options contained in the Reply message:
     *   [...]
     *   - Discard any addresses from the IA, as recorded by the client, that
     *     have a valid lifetime of 0 in the IA Address option.
     */
    if (!valid_lifetime_s) {
        if (!IN6_IS_ADDR_UNSPECIFIED(&client->iaaddr.ipv6) &&
            IN6_ARE_ADDR_EQUAL(&client->iaaddr.ipv6, &addr)) {
            timer_stop(NULL, &client->iaaddr.valid_lifetime_timer);
            dhcp_client_addr_expired(NULL, &client->iaaddr.valid_lifetime_timer);
        }
        return -EINVAL;
    }
    if (dhcp_check_status_code(iobuf_ptr(&opt_buf), iobuf_remaining_size(&opt_buf)))
        return -EFAULT;

    /*
     * This DHCPv6 client implementation only handles one IPv6.
     * When a new IPv6 is assigned, we make the old one expire.
     */
    if (!IN6_IS_ADDR_UNSPECIFIED(&client->iaaddr.ipv6) &&
        !IN6_ARE_ADDR_EQUAL(&client->iaaddr.ipv6, &addr)) {
        timer_stop(NULL, &client->iaaddr.valid_lifetime_timer);
        dhcp_client_addr_expired(NULL, &client->iaaddr.valid_lifetime_timer);
    }

    timer_stop(NULL, &client->iaaddr.valid_lifetime_timer);

    client->iaaddr.ipv6 = addr;
    client->iaaddr.preferred_lifetime_s = preferred_lifetime_s;
    client->iaaddr.valid_lifetime_timer.callback = dhcp_client_addr_expired;

    if (valid_lifetime_s != DHCPV6_LIFETIME_INFINITE) {
        TRACE(TR_DHCP, "dhcp iaaddr add %s lifetime:%ds",
              tr_ipv6(client->iaaddr.ipv6.s6_addr), valid_lifetime_s);
        timer_start_rel(NULL, &client->iaaddr.valid_lifetime_timer,
                        valid_lifetime_s * 1000);
    } else {
        TRACE(TR_DHCP, "dhcp iaaddr add %s lifetime:infinite", tr_ipv6(client->iaaddr.ipv6.s6_addr));
    }
    if (client->on_addr_add)
        client->on_addr_add(client, &client->iaaddr.ipv6);
    return 0;
}

static void dhcp_client_handle_ia_na(struct dhcp_client *client, const uint8_t *buf, size_t buf_len)
{
    struct iobuf_read opt_buf;
    uint32_t t1_s;

    dhcp_get_option(buf, buf_len, DHCPV6_OPT_IA_NA, &opt_buf);
    if (opt_buf.err) {
        TRACE(TR_DROP, "drop %-9s: missing ia_na option", "dhcp");
        return;
    }

    iobuf_pop_be32(&opt_buf); // IAID
    t1_s = iobuf_pop_be32(&opt_buf);
    iobuf_pop_be32(&opt_buf); // T2
    if (opt_buf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed ia_na option", "dhcp");
        return;
    }

    if (dhcp_check_status_code(iobuf_ptr(&opt_buf), iobuf_remaining_size(&opt_buf)))
        return;
    // TODO: WARN when several iaaddr options are given
    if (dhcp_client_handle_iaaddr(client, iobuf_ptr(&opt_buf), iobuf_remaining_size(&opt_buf)))
        return;

    rfc8415_txalg_stop(&client->solicit_txalg);

    /*
     *   RFC3315 - Section 22.4
     * If the time at which the addresses in an IA_NA are to be renewed is to
     * be left to the discretion of the client, the server sets T1 and T2 to 0.
     */
    if (!t1_s) {
        if (timer_stopped(&client->iaaddr.valid_lifetime_timer))
            t1_s = DHCPV6_LIFETIME_INFINITE;
        else
            t1_s = MIN(client->iaaddr.preferred_lifetime_s,
                       timer_duration_ms(&client->iaaddr.valid_lifetime_timer) / 1000 * 90 / 100);
    }

    /*
     *   Wi-SUN FAN 1.1v08 - 6.2.3.1.2.1.2 Global and Unique Local Addresses
     * The IA_NA’s value of T2 is not used.
     */
    if (t1_s != DHCPV6_LIFETIME_INFINITE) {
        TRACE(TR_DHCP, "dhcp ia_na t1:%ds", t1_s);
        timer_start_rel(NULL, &client->t1_timer, t1_s * 1000);
    } else {
        TRACE(TR_DHCP, "dhcp ia_na t1:infinite");
    }
}

static void dhcp_client_handle_reply(struct dhcp_client *client, struct iobuf_read *req)
{

    if (dhcp_check_rapid_commit(iobuf_ptr(req), iobuf_remaining_size(req)))
        return;
    if (dhcp_check_server_id(iobuf_ptr(req), iobuf_remaining_size(req)))
        return;
    if (dhcp_check_client_id(client->eui64, iobuf_ptr(req), iobuf_remaining_size(req)))
        return;
    if (dhcp_check_status_code(iobuf_ptr(req), iobuf_remaining_size(req)))
        return;
    // TODO: WARN when several ia_na options are given
    dhcp_client_handle_ia_na(client, iobuf_ptr(req), iobuf_remaining_size(req));
}

void dhcp_client_recv(struct dhcp_client *client)
{
    socklen_t src_addr_len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 src_addr;
    struct iobuf_read req = { };
    uint8_t buf[1024];
    uint8_t msg_type;
    uint24_t tid;

    req.data = buf;
    req.data_size = xrecvfrom(client->fd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &src_addr_len);
    if (src_addr.sin6_family != AF_INET6) {
        TRACE(TR_DROP, "drop %-9s: not IPv6", "dhcp");
        return;
    }

    TRACE(TR_DHCP, "dhcp rx %-9s src:%s", val_to_str(req.data[0], dhcp_frames, "[UNK]"),
          tr_ipv6(src_addr.sin6_addr.s6_addr));

    msg_type = iobuf_pop_u8(&req);
    if (msg_type != DHCPV6_MSG_REPLY) {
        TRACE(TR_DROP, "drop %-9s: unsupported msg-type 0x%02x", "dhcp", msg_type);
        return;
    }
    tid = iobuf_pop_be24(&req);
    if (tid != client->tid) {
        TRACE(TR_DROP, "drop %-9s: invalid transaction id %d", "dhcp", tid);
        return;
    }
    dhcp_client_handle_reply(client, &req);
}

void dhcp_client_stop(struct dhcp_client *client)
{
    rfc8415_txalg_stop(&client->solicit_txalg);
    timer_stop(NULL, &client->t1_timer);
    timer_stop(NULL, &client->iaaddr.valid_lifetime_timer);
    dhcp_client_addr_expired(NULL, &client->iaaddr.valid_lifetime_timer);
    client->running = false;
}

void dhcp_client_start(struct dhcp_client *client)
{
    BUG_ON(client->running);
    rfc8415_txalg_start(&client->solicit_txalg);
    client->running = true;
}

void dhcp_client_init(struct dhcp_client *client,
                      const struct tun_ctx *tun,
                      const uint8_t eui64[8])
{
    struct sockaddr_in6 sockaddr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(DHCPV6_CLIENT_UDP_PORT),
    };

    BUG_ON(!client->on_addr_add);
    BUG_ON(!client->on_addr_del);
    BUG_ON(!client->get_dst);
    client->tun_if_id = tun->ifindex;
    client->fd = socket(AF_INET6, SOCK_DGRAM, 0);
    FATAL_ON(client->fd < 0, 2, "%s: socket: %m", __func__);
    memcpy(client->eui64, eui64, sizeof(client->eui64));
    capture_register_netfd(client->fd);
    if (setsockopt(client->fd, SOL_SOCKET, SO_BINDTODEVICE, tun->ifname, IF_NAMESIZE) < 0)
        FATAL(1, "%s: setsockopt: %m", __func__);
    if (bind(client->fd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0)
        FATAL(1, "%s: bind: %m", __func__);

    client->t1_timer.callback = dhcp_client_t1_expired;
    client->solicit_txalg.tx  = dhcp_client_solicit;
    rfc8415_txalg_init(&client->solicit_txalg);
}
