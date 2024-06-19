/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <sys/socket.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "common/bits.h"
#include "common/dbus.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/named_values.h"
#include "common/netinet_in_extra.h"
#include "common/seqno.h"
#include "common/string_extra.h"
#include "common/sys_queue_extra.h"
#include "common/time_extra.h"
#include "common/memutils.h"
#include "common/specs/icmpv6.h"
#include "common/specs/rpl.h"
#include "app_wsrd/ipv6/rpl_mrhof.h"
#include "app_wsrd/ipv6/rpl_pkt.h"
#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/ipv6_addr.h"
#include "rpl.h"

static const struct name_value rpl_codes[] = {
    { "dis",     RPL_CODE_DIS },
    { "dio",     RPL_CODE_DIO },
    { "dao",     RPL_CODE_DAO },
    { "dao-ack", RPL_CODE_DAO_ACK },
    { 0 }
};

static const char *tr_icmp_rpl(uint8_t code)
{
    return val_to_str(code, rpl_codes, "unknown");
}

static void rpl_neigh_update(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce,
                             const struct rpl_dio_base *dio_base,
                             const struct rpl_opt_config *config,
                             const struct rpl_opt_prefix *prefix)
{
    bool update = nce->rpl->dio_base.rank != dio_base->rank;

    WARN_ON(nce->rpl->dio_base.instance_id != dio_base->instance_id);
    WARN_ON(!IN6_ARE_ADDR_EQUAL(nce->rpl->dio_base.dodag_id.s6_addr, &dio_base->dodag_id));
    WARN_ON(memcmp(&nce->rpl->config, config, sizeof(nce->rpl->config)));
    nce->rpl->dio_base = *dio_base;
    nce->rpl->config   = *config;
    // TODO: timer for prefix lifetime
    TRACE(TR_RPL, "rpl: neigh set %s rank=%u ",
          tr_ipv6(nce->gua.s6_addr), ntohs(dio_base->rank));
    if (update)
        rpl_mrhof_select_parent(ipv6);
}

static void rpl_neigh_add(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce,
                          const struct rpl_dio_base *dio_base,
                          const struct rpl_opt_config *config,
                          const struct rpl_opt_prefix *prefix)
{
    BUG_ON(nce->rpl);
    nce->rpl = zalloc(sizeof(struct rpl_neigh));
    nce->rpl->dio_base = *dio_base;
    nce->rpl->config   = *config;
    TRACE(TR_RPL, "rpl: neigh add %s", tr_ipv6(nce->gua.s6_addr));
    rpl_neigh_update(ipv6, nce, dio_base, config, prefix);
    rpl_mrhof_select_parent(ipv6);
}

void rpl_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce)
{
    TRACE(TR_RPL, "rpl: neigh del %s", tr_ipv6(nce->gua.s6_addr));
    if (nce->rpl->is_parent) {
        nce->rpl->dio_base.rank = RPL_RANK_INFINITE;
        rpl_mrhof_select_parent(ipv6);
    }
    free(nce->rpl);
    nce->rpl = NULL;
}

struct ipv6_neigh *rpl_neigh_pref_parent(struct ipv6_ctx *ipv6)
{
    struct ipv6_neigh *nce;

    return SLIST_FIND(nce, &ipv6->neigh_cache, link,
                      nce->rpl && nce->rpl->is_parent);
}

static void rpl_opt_push(struct iobuf_write *iobuf, uint8_t type,
                         const void *data, uint8_t len)
{
    struct rpl_opt opt = {
        .type = type,
        .len  = len,
    };

    iobuf_push_data(iobuf, &opt, sizeof(opt));
    iobuf_push_data(iobuf, data, len);
}

static void rpl_send(struct ipv6_ctx *ipv6, uint8_t code,
                     const uint8_t *buf, size_t buf_len,
                     const struct in6_addr *dst)
{
    uint8_t icmpv6_hdr[4] = { ICMPV6_TYPE_RPL, code }; // Checksum filled by kernel
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_addr   = *dst,
    };
    struct iovec iov[2] = {
        { .iov_base = icmpv6_hdr,  .iov_len = sizeof(icmpv6_hdr) },
        { .iov_base = (void *)buf, .iov_len = buf_len            },
    };
    struct msghdr msg = {
        .msg_name    = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
    };
    ssize_t ret;

    TRACE(TR_ICMP, "tx-icmp rpl-%-9s dst=%s", tr_icmp_rpl(code), tr_ipv6(dst->s6_addr));
    ret = sendmsg(ipv6->rpl.fd, &msg, 0);
    if (ret < sizeof(icmpv6_hdr) + buf_len)
        WARN("%s: sendto %s: %m", __func__, tr_ipv6(dst->s6_addr));
}

static void rpl_send_dao(struct rfc8415_txalg *txalg)
{
    struct ipv6_ctx *ipv6 = container_of(txalg, struct ipv6_ctx, rpl.dao_txalg);
    struct iobuf_write iobuf = { };
    struct rpl_opt_transit transit;
    struct rpl_opt_target target;
    struct rpl_dao_base dao_base;
    struct ipv6_neigh *parent;
    struct in6_addr dodag_id;

    parent = rpl_neigh_pref_parent(ipv6);
    BUG_ON(!parent || !parent->rpl);
    // Prevent GCC warning -Waddress-of-packed-member
    dodag_id = parent->rpl->dio_base.dodag_id;

    //   Wi-SUN FAN 1.1v08 6.2.3.1.6.4 Downward Route Formation
    memset(&dao_base, 0, sizeof(dao_base));
    dao_base.instance_id = parent->rpl->dio_base.instance_id;
    // The K flag MUST be set to 1.
    dao_base.flags |= RPL_MASK_DAO_K;
    dao_base.dao_seq = ipv6->rpl.dao_seq;
    iobuf_push_data(&iobuf, &dao_base, sizeof(dao_base));

    // A RPL Target option MUST be included and populated for each GUA/ULA to
    // be advertised to the DODAG root.
    memset(&target, 0, sizeof(target));
    target.prefix_len = 128;
    target.prefix     = ipv6->addr_uc_global;
    rpl_opt_push(&iobuf, RPL_OPT_TARGET, &target, sizeof(target));

    // A Transit Information Option MUST be included for each member of the
    // parent set, populated with the parent's GUA/ULA. The Path Control field
    // MUST be populated to correctly rank the priority of each Transit
    // Information Option (i.e., the preferred parent is indicated as the
    // single member of PC1, the first alternate parent set as the single
    // member of PC2, etc.).
    memset(&transit, 0, sizeof(transit));
    transit.path_ctl      = BIT(7);    // TODO: handle more than 1 parent
    transit.path_seq      = 0;         // TODO: handle PathSequence
    transit.path_lifetime = UINT8_MAX; // TODO: use default lifetime and renew DAO
    transit.parent_addr   = parent->gua;
    rpl_opt_push(&iobuf, RPL_OPT_TRANSIT, &transit, sizeof(transit));

    rpl_send(ipv6, RPL_CODE_DAO, iobuf.data, iobuf.len, &dodag_id);
    // TODO: handle renewal after lifetime expiration
    iobuf_free(&iobuf);
}

void rpl_start_dao(struct ipv6_ctx *ipv6)
{
    ipv6->rpl.dao_seq++;
    rfc8415_txalg_start(&ipv6->rpl.dao_txalg);
    // TODO: Figure out what to do in case of DAO failure.
}

static void rpl_recv_dio(struct ipv6_ctx *ipv6, const uint8_t *buf, size_t buf_len,
                         const struct in6_addr *src)
{
    const struct rpl_opt_config *config = NULL;
    const struct rpl_opt_prefix *prefix = NULL;
    const struct rpl_dio_base *dio_base;
    const struct rpl_opt *opt;
    struct ipv6_neigh *nce;
    struct in6_addr addr;
    uint8_t eui64[8];
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    if (!IN6_IS_ADDR_LINKLOCAL(src)) {
        TRACE(TR_DROP, "drop %-9s: invalid source address", "rpl-dio");
        return;
    }

    dio_base = (const struct rpl_dio_base *)iobuf_pop_data_ptr(&iobuf, sizeof(*dio_base));
    if (!dio_base)
        goto malformed;

    if (FIELD_GET(RPL_MASK_INSTANCE_ID_TYPE, dio_base->instance_id) == RPL_INSTANCE_ID_TYPE_LOCAL) {
        TRACE(TR_DROP, "drop %-9s: unsupported local RPL instance", "rpl-dio");
        goto drop_neigh;
    }
    if (!FIELD_GET(RPL_MASK_DIO_G, dio_base->g_mop_prf)) {
        TRACE(TR_DROP, "drop %-9s: unsupported floating DODAG", "rpl-dio");
        goto drop_neigh;
    }
    if (FIELD_GET(RPL_MASK_DIO_MOP, dio_base->g_mop_prf) != RPL_MOP_NON_STORING) {
        TRACE(TR_DROP, "drop %-9s: unsupported mode of operation", "rpl-dio");
        goto drop_neigh;
    }

    while (iobuf_remaining_size(&iobuf)) {
        opt = (const struct rpl_opt *)iobuf_ptr(&iobuf);
        if (opt->type == RPL_OPT_PAD1) {
            iobuf_pop_u8(&iobuf);
            continue;
        }
        if (!iobuf_pop_data_ptr(&iobuf, sizeof(*opt)))
            goto malformed;
        if (!iobuf_pop_data_ptr(&iobuf, opt->len))
            goto malformed;
        switch (opt->type) {
        case RPL_OPT_PADN:
            continue;
        case RPL_OPT_CONFIG:
            if (opt->len < sizeof(*config))
                goto malformed;
            config = (const struct rpl_opt_config *)(opt + 1);
            break;
        case RPL_OPT_PREFIX:
            if (opt->len < sizeof(*prefix))
                goto malformed;
            if (prefix)
                TRACE(TR_IGNORE, "ignore: rpl-dio multiple prefix options");
            prefix = (const struct rpl_opt_prefix *)(opt + 1);
            if (prefix->prefix_len > 128)
                goto malformed;
            if (!FIELD_GET(RPL_MASK_OPT_PREFIX_R, prefix->flags)) {
                TRACE(TR_DROP, "drop %-9s: unsupported prefix w/o router address", "rpl-dio");
                goto drop_neigh;
            }
            if (!IN6_IS_ADDR_UC_GLOBAL(&prefix->prefix)) {
                TRACE(TR_DROP, "drop %-9s: unsupported non-global unicast prefix", "rpl-dio");
                goto drop_neigh;
            }
            break;
        default:
            TRACE(TR_IGNORE, "ignore: rpl-dio unsupported option %u", opt->type);
            break;
        }
    }
    if (iobuf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "rpl-dio");
        goto drop_neigh;
    }
    if (!config) {
        TRACE(TR_DROP, "drop %-9s: missing DODAG configuration option", "rpl-dio");
        goto drop_neigh;
    }
    if (ntohs(config->ocp) != RPL_OCP_MRHOF) {
        TRACE(TR_DROP, "drop %-9s: unsupported objective function", "rpl-dio");
        goto drop_neigh;
    }
    if (!prefix) {
        TRACE(TR_DROP, "drop %-9s: missing prefix information option", "rpl-dio");
        goto drop_neigh;
    }

    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.4.1 FFN Neighbor Discovery
     * Router Solicitation/Router Advertisement is not used. Router discovery
     * is performed using DIO and DIS messaging.
     *
     * NOTE: Since a NCE is normally created on receipt of an RA packet, it is
     * being created here instead.
     */
    addr = prefix->prefix; // Prevent GCC warning -Waddress-of-packed-member
    ipv6_addr_conv_iid_eui64(eui64, src->s6_addr + 8);
    nce = ipv6_neigh_fetch(ipv6, &addr, eui64);

    if (!nce->rpl)
        rpl_neigh_add(ipv6, nce, dio_base, config, prefix);
    else
        rpl_neigh_update(ipv6, nce, dio_base, config, prefix);

    // TODO: filter candidate neighbors according to
    // Wi-SUN FAN 1.1v08 6.2.3.1.6.3 Upward Route Formation

    return;

malformed:
    TRACE(TR_DROP, "drop %-9s: malformed packet", "rpl-dio");
drop_neigh:
    addr = prefix->prefix; // Prevent GCC warning -Waddress-of-packed-member
    nce = ipv6_neigh_get_from_gua(ipv6, &addr);
    if (nce && nce->rpl)
        rpl_neigh_del(ipv6, nce);
}

static void rpl_recv_dao_ack(struct ipv6_ctx *ipv6,
                             const uint8_t *buf, size_t buf_len)
{
    const struct rpl_dao_ack_base *dao_ack;
    struct ipv6_neigh *parent, *nce;
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent) {
        TRACE(TR_DROP, "drop rpl-%-9s: no preferred parent", "dao-ack");
        return;
    }

    dao_ack = (struct rpl_dao_ack_base *)iobuf_pop_data_ptr(&iobuf, sizeof(*dao_ack));
    if (!dao_ack) {
        TRACE(TR_DROP, "drop rpl-%-9s: malformed packet", "dao-ack");
        return;
    }
    if (dao_ack->instance_id != parent->rpl->dio_base.instance_id) {
        TRACE(TR_DROP, "drop rpl-%-9s: InstanceID mismatch", "dao-ack");
        return;
    }
    if (dao_ack->flags & RPL_MASK_DAO_ACK_D) {
        TRACE(TR_DROP, "drop rpl-%-9s: unsupported DODAGID present", "dao-ack");
        return;
    }
    if (timer_stopped(&ipv6->rpl.dao_txalg.timer_rt) || dao_ack->dao_seq != ipv6->rpl.dao_seq) {
        TRACE(TR_DROP, "drop rpl-%-9s: unexpected DAOSequence", "dao-ack");
        return;
    }
    rfc8415_txalg_stop(&ipv6->rpl.dao_txalg);
    /*
     * FIXME: Ensure that the current preferred parent has not changed between
     * DAO send and DAO-ACK reception. This can be achieved by re-starting the
     * DAO schedule with rpl_start_dao() on every parent change, and refuse
     * DAO-ACKs for previously sent DAOs.
     */
    SLIST_FOREACH(nce, &ipv6->neigh_cache, link)
        if (nce->rpl)
            nce->rpl->dao_ack_received = false;
    parent->rpl->dao_ack_received = true;
    dbus_emit_change("PrimaryParent");
}

static void rpl_recv_dispatch(struct ipv6_ctx *ipv6, const uint8_t *pkt, size_t size,
                              const struct in6_addr *src, const struct in6_addr *dst)
{
    struct iobuf_read buf = {
        .data_size = size,
        .data      = pkt,
    };
    uint8_t type, code;

    type = iobuf_pop_u8(&buf);
    code = iobuf_pop_u8(&buf);
    iobuf_pop_be16(&buf); // Checksum verified by kernel
    BUG_ON(buf.err);
    BUG_ON(type != ICMPV6_TYPE_RPL);

    TRACE(TR_ICMP, "rx-icmp rpl-%-9s src=%s", tr_icmp_rpl(code), tr_ipv6(src->s6_addr));

    switch (code) {
    case RPL_CODE_DIO:
        rpl_recv_dio(ipv6, iobuf_ptr(&buf), iobuf_remaining_size(&buf), src);
        break;
    case RPL_CODE_DAO_ACK:
        rpl_recv_dao_ack(ipv6, iobuf_ptr(&buf), iobuf_remaining_size(&buf));
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported code %u", "rpl", code);
        break;
    }
}

void rpl_recv(struct ipv6_ctx *ipv6)
{
    uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct sockaddr_in6 src;
    uint8_t buf[1280];
    struct iovec iov = {
        .iov_base = buf,
        .iov_len  = sizeof(buf),
    };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_name       = &src,
        .msg_namelen    = sizeof(src),
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };
    struct in6_pktinfo *pktinfo;
    struct cmsghdr *cmsg;
    ssize_t size;

    size = recvmsg(ipv6->rpl.fd, &msg, 0);
    FATAL_ON(size < 0, 2, "%s: recvmsg: %m", __func__);
    if (msg.msg_namelen != sizeof(src) || src.sin6_family != AF_INET6) {
        TRACE(TR_DROP, "drop %-9s: source address not IPv6", "rpl");
        return;
    }
    cmsg = CMSG_FIRSTHDR(&msg);
    BUG_ON(!cmsg);
    BUG_ON(cmsg->cmsg_level != IPPROTO_IPV6);
    BUG_ON(cmsg->cmsg_type  != IPV6_PKTINFO);
    BUG_ON(cmsg->cmsg_len < sizeof(struct in6_pktinfo));
    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    rpl_recv_dispatch(ipv6, iov.iov_base, size,
                      &src.sin6_addr, &pktinfo->ipi6_addr);
}

void rpl_start(struct ipv6_ctx *ipv6)
{
    struct icmp6_filter filter;
    int err;

    BUG_ON(!ipv6->rpl.mrhof.ws_neigh_table);
    BUG_ON(!ipv6->rpl.mrhof.max_link_metric);
    BUG_ON(!ipv6->rpl.mrhof.parent_switch_threshold);
    ipv6->rpl.mrhof.cur_min_path_cost = ipv6->rpl.mrhof.max_path_cost;

    ipv6->rpl.dao_txalg.tx = rpl_send_dao;
    rfc8415_txalg_init(&ipv6->rpl.dao_txalg);

    ipv6->rpl.fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    FATAL_ON(ipv6->rpl.fd < 0, 2, "%s: socket: %m", __func__);
    err = setsockopt(ipv6->rpl.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (int[1]){ true }, sizeof(int));
    FATAL_ON(err < 0, 2, "%s: setsockopt IPV6_RECVPKTINFO: %m", __func__);
    err = setsockopt(ipv6->rpl.fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (int[1]){ false }, sizeof(int));
    FATAL_ON(err < 0, 2, "%s: setsockopt IPV6_MULTICAST_LOOP: %m", __func__);
    err = setsockopt(ipv6->rpl.fd, SOL_SOCKET, SO_BINDTODEVICE, ipv6->tun.ifname, IF_NAMESIZE);
    FATAL_ON(err < 0, 2, "%s: setsockopt SO_BINDTODEVICE %s: %m", __func__, ipv6->tun.ifname);
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ICMPV6_TYPE_RPL, &filter);
    err = setsockopt(ipv6->rpl.fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    FATAL_ON(err < 0, 2, "%s: setsockopt ICMP6_FILTER: %m", __func__);
}
