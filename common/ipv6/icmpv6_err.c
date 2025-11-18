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
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/socket.h>

#include "common/ipv6/ipv6_cksum.h"
#include "common/named_values.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/log.h"

#include "icmpv6_err.h"

static void icmpv6_err_ratelimit_reset(struct timer_group *group, struct timer_entry *timer)
{
    struct icmpv6_err_ctx *ctx = container_of(timer, struct icmpv6_err_ctx, ratelimit_timer);

    // RFC 4443 2.4. Message Processing Rules
    ctx->tokens = 10;
}

void icmpv6_err_init(struct icmpv6_err_ctx *ctx, const char *ifname)
{
    struct icmp6_filter filter;
    int err;

    ctx->fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    FATAL_ON(ctx->fd < 0, 2, "socket AF_INET6 SOCK_RAW IPPROTO_ICMPV6: %m");
    err = setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IF_NAMESIZE);
    FATAL_ON(err < 0, 2, "setsockopt SO_BINDTODEVICE %s: %m", ifname);
    ICMP6_FILTER_SETBLOCKALL(&filter);
    err = setsockopt(ctx->fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    FATAL_ON(err < 0, 2, "setsockopt ICMP6_FILTER: %m");

    ctx->ratelimit_timer.callback = icmpv6_err_ratelimit_reset;
    icmpv6_err_ratelimit_reset(NULL, &ctx->ratelimit_timer);
}

static void icmpv6_err_trace(const struct icmp6_hdr *icmp)
{
    static const struct name_value table[] = {
        { "err-reach", ICMP6_DST_UNREACH },
        { "err-mtu",   ICMP6_PACKET_TOO_BIG },
        { "err-time",  ICMP6_TIME_EXCEEDED },
        { "err-param", ICMP6_PARAM_PROB },
        { 0 }
    };

    TRACE(TR_ICMP, "tx-icmp %-9s code=%u",
          val_to_str(icmp->icmp6_type, table, "err-???"), icmp->icmp6_code);
}

void icmpv6_err_send(struct icmpv6_err_ctx *ctx,
                     const void *buf, size_t buf_len,
                     uint8_t type, uint8_t code, uint32_t ptr)
{
    struct sockaddr_in6 dst = { .sin6_family = AF_INET6 };
    struct icmp6_hdr icmp = {
        .icmp6_type = type,
        .icmp6_code = code,
        .icmp6_cksum = 0, // Filled by kernel
        .icmp6_pptr = htonl(ptr),
    };
    struct iovec iov[] = {
        { &icmp,       sizeof(icmp) },
        { (void *)buf, MIN(buf_len, 1280 - sizeof(struct ip6_hdr) - sizeof(icmp)) },
    };
    struct msghdr msg = {
        .msg_name    = &dst,
        .msg_namelen = sizeof(dst),
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
    };
    const struct ip6_hdr *hdr;
    ssize_t ret;

    BUG_ON(buf_len < sizeof(struct ip6_hdr));
    hdr = buf;
    dst.sin6_addr = hdr->ip6_src;

    if (!ctx->tokens) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: rate limit exceeded", "icmp-err");
        return;
    }
    ctx->tokens--;
    if (timer_stopped(&ctx->ratelimit_timer))
        timer_start_rel(NULL, &ctx->ratelimit_timer, 1000);

    icmpv6_err_trace(&icmp);
    ret = sendmsg(ctx->fd, &msg, 0);
    if (ret < 0)
        WARN("%s: sendmsg %s: %m", __func__, tr_ipv6(dst.sin6_addr.s6_addr));
}
