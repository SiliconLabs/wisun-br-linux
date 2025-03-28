/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "common/ws/ws_neigh.h"
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
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/specs/icmpv6.h"
#include "common/specs/rpl.h"
#include "common/ipv6/ipv6_addr.h"
#include "app_wsrd/ipv6/rpl_mrhof.h"
#include "app_wsrd/ipv6/ipv6.h"
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
                             const struct rpl_dio *dio,
                             const struct rpl_opt_config *config,
                             const struct rpl_opt_prefix *prefix)
{
    const struct in6_addr dodag_id = dio->dodag_id; // -Waddress-of-packed-member
    bool update = nce->rpl->dio.rank != dio->rank;

    WARN_ON(nce->rpl->dio.instance_id != dio->instance_id);
    WARN_ON(!IN6_ARE_ADDR_EQUAL(nce->rpl->dio.dodag_id.s6_addr, &dodag_id));
    WARN_ON(memcmp(&nce->rpl->config, config, sizeof(nce->rpl->config)));
    nce->rpl->dio = *dio;
    nce->rpl->config   = *config;
    // TODO: timer for prefix lifetime
    TRACE(TR_RPL, "rpl: neigh set %s rank=%u ",
          tr_ipv6(nce->gua.s6_addr), ntohs(dio->rank));
    if (update)
        rpl_mrhof_select_parent(ipv6);
}

static void rpl_neigh_add(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce,
                          const struct rpl_dio *dio,
                          const struct rpl_opt_config *config,
                          const struct rpl_opt_prefix *prefix)
{
    BUG_ON(nce->rpl);
    nce->rpl = zalloc(sizeof(struct rpl_neigh));
    nce->rpl->dio    = *dio;
    nce->rpl->config = *config;
    TRACE(TR_RPL, "rpl: neigh add %s", tr_ipv6(nce->gua.s6_addr));
    rpl_neigh_update(ipv6, nce, dio, config, prefix);
    rpl_mrhof_select_parent(ipv6);
}

void rpl_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce)
{
    bool is_parent = nce->rpl->is_parent;

    TRACE(TR_RPL, "rpl: neigh del %s", tr_ipv6(nce->gua.s6_addr));

    /*
     * We immediatly remove the RPL ctx from the neighbor.
     * This ensures we do not send any NS(ARO) lifetime 0 to the
     * old parent that is actually being deleted.
     *
     */
    free(nce->rpl);
    nce->rpl = NULL;
    /*
     * When cleaning our ipv6 neigh cache, RPL may not be operational
     * so we do not want to select a new parent after deleting the
     * current one.
     */
    if (is_parent && ipv6->rpl.fd >= 0)
        rpl_mrhof_select_parent(ipv6);
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
                     const void *buf, size_t buf_len,
                     const struct in6_addr *dst)
{
    struct icmpv6_hdr hdr = {
        .type  = ICMPV6_TYPE_RPL,
        .code  = code,
        .cksum = 0, // Filled by kernel
    };
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_addr   = *dst,
    };
    struct iovec iov[2] = {
        { &hdr,        sizeof(hdr) },
        { (void *)buf, buf_len },
    };
    struct msghdr msg = {
        .msg_name    = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
    };
    ssize_t ret;

    BUG_ON(ipv6->rpl.fd < 0);

    TRACE(TR_ICMP, "tx-icmp rpl-%-9s dst=%s", tr_icmp_rpl(code), tr_ipv6(dst->s6_addr));
    ret = sendmsg(ipv6->rpl.fd, &msg, 0);
    if (ret < sizeof(hdr) + buf_len)
        WARN("%s: sendto %s: %m", __func__, tr_ipv6(dst->s6_addr));
}

static void rpl_send_dio(struct ipv6_ctx *ipv6, const struct in6_addr *dst)
{
    struct iobuf_write iobuf = { };
    struct rpl_opt_prefix prefix;
    struct ipv6_neigh *parent;
    struct rpl_dio dio;

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent || IN6_IS_ADDR_UNSPECIFIED(&ipv6->dhcp.iaaddr)) {
        WARN("%s: not ready", __func__);
        return;
    }

    memset(&dio, 0, sizeof(dio));
    dio.instance_id = parent->rpl->dio.instance_id;
    dio.dodag_verno = parent->rpl->dio.dodag_verno;
    dio.rank        = htons(rpl_mrhof_rank(ipv6));
    dio.g_mop_prf   = parent->rpl->dio.g_mop_prf;
    dio.dtsn        = parent->rpl->dio.dtsn;
    dio.dodag_id    = parent->rpl->dio.dodag_id;
    iobuf_push_data(&iobuf, &dio, sizeof(dio));

    rpl_opt_push(&iobuf, RPL_OPT_CONFIG, &parent->rpl->config, sizeof(parent->rpl->config));

    memset(&prefix, 0, sizeof(prefix));
    /*
     * FIXME: Silicon Labs's embedded Wi-SUN stack is buggy and does not handle
     * the L flag. When the L flag is set in its parent's DIOs, the stack
     * becomes unable to route packets to its parent. Additionnaly, for some
     * reason, the stack will always override the prefix length to 64.
     */
    if (ipv6->rpl.compat) {
        prefix.prefix_len       = 64;
        prefix.flags            = RPL_MASK_OPT_PREFIX_R;
    } else {
        prefix.prefix_len       = 128;
        prefix.flags            = RPL_MASK_OPT_PREFIX_L | RPL_MASK_OPT_PREFIX_R;
    }
    prefix.lifetime_valid_s     = htonl(dhcp_iaaddr_valid_lifetime_s(&ipv6->dhcp.iaaddr));
    prefix.lifetime_preferred_s = htonl(dhcp_iaaddr_preferred_lifetime_s(&ipv6->dhcp.iaaddr));
    prefix.prefix               = ipv6->dhcp.iaaddr.ipv6;
    rpl_opt_push(&iobuf, RPL_OPT_PREFIX, &prefix, sizeof(prefix));

    rpl_send(ipv6, RPL_CODE_DIO, iobuf.data, iobuf.len, dst);
    iobuf_free(&iobuf);
}

static void rpl_send_dio_mc(struct trickle *tkl)
{
    struct ipv6_ctx *ipv6 = container_of(tkl, struct ipv6_ctx, rpl.dio_trickle);

    rpl_send_dio(ipv6, &ipv6_addr_all_rpl_nodes_link);
}

void rpl_start_dio(struct ipv6_ctx *ipv6)
{
    struct trickle_cfg *cfg = &ipv6->rpl.dio_trickle_cfg;
    struct ipv6_neigh *parent;

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent) {
        WARN("%s: not ready", __func__);
        return;
    }

    /*
     *   RFC 6550 - 8.3.1. Trickle Parameters
     * Imin: learned from the DIO message as (2^DIOIntervalMin) ms.
     */
    cfg->Imin_ms = POW2(parent->rpl->config.dio_i_min);
    cfg->Imax_ms = TRICKLE_DOUBLINGS(cfg->Imin_ms, parent->rpl->config.dio_i_doublings);
    cfg->k       = parent->rpl->config.dio_redundancy;
    trickle_start(&ipv6->rpl.dio_trickle);
}

static void rpl_send_dis(struct ipv6_ctx *ipv6, const struct in6_addr *dst)
{
    struct rpl_dis dis = { };

    rpl_send(ipv6, RPL_CODE_DIS, &dis, sizeof(dis), dst);
}

static void rpl_trig_dis(struct rfc8415_txalg *txalg)
{
    struct ipv6_ctx *ipv6 = container_of(txalg, struct ipv6_ctx, rpl.dis_txalg);
    struct in6_addr dst = ipv6_prefix_linklocal;
    struct ws_neigh *neigh;

    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.6.3 Upward Route Formation
     * A Router MAY wait for DIO messages, MAY solicit a DIO by issuing a
     * unicast DIS to a likely neighbor, or MAY solicit a DIO by issuing a
     * multicast DIS (as described in [RFC6550]).
     *
     * NOTE: This implementation sends unicast DIS packets to a limited
     * number of neighboring nodes.
     */
    if (SLIST_EMPTY(&ipv6->rpl.mrhof.ws_neigh_table->neigh_list)) {
        rpl_send_dis(ipv6, &ipv6_addr_all_rpl_nodes_link);
        return;
    }
    SLIST_FOREACH(neigh, &ipv6->rpl.mrhof.ws_neigh_table->neigh_list, link) {
        // TODO: Determine better creterias to filter out bad candidates (eg.
        // network name, PAN ID, PAN-IE routing metric, RSL...).
        if (!ws_neigh_has_us(&neigh->fhss_data_unsecured))
            continue;

        ipv6_addr_conv_iid_eui64(dst.s6_addr + 8, neigh->eui64.u8);
        rpl_send_dis(ipv6, &dst);
    }
}

void rpl_start_dis(struct ipv6_ctx *ipv6)
{
    rfc8415_txalg_start(&ipv6->rpl.dis_txalg);
}

static void rpl_send_dao(struct rfc8415_txalg *txalg)
{
    struct ipv6_ctx *ipv6 = container_of(txalg, struct ipv6_ctx, rpl.dao_txalg);
    struct iobuf_write iobuf = { };
    struct rpl_opt_transit transit;
    struct rpl_opt_target target;
    struct ipv6_neigh *parent;
    struct in6_addr dodag_id;
    struct rpl_dao dao;

    parent = rpl_neigh_pref_parent(ipv6);
    BUG_ON(!parent || !parent->rpl);
    // Prevent GCC warning -Waddress-of-packed-member
    dodag_id = parent->rpl->dio.dodag_id;

    //   Wi-SUN FAN 1.1v08 6.2.3.1.6.4 Downward Route Formation
    memset(&dao, 0, sizeof(dao));
    dao.instance_id = parent->rpl->dio.instance_id;
    // The K flag MUST be set to 1.
    dao.flags |= RPL_MASK_DAO_K;
    dao.dao_seq = ipv6->rpl.dao_seq;
    iobuf_push_data(&iobuf, &dao, sizeof(dao));

    // A RPL Target option MUST be included and populated for each GUA/ULA to
    // be advertised to the DODAG root.
    memset(&target, 0, sizeof(target));
    target.prefix_len = 128;
    target.prefix     = ipv6->dhcp.iaaddr.ipv6;
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
    const struct rpl_dio *dio;
    const struct rpl_opt *opt;
    struct ipv6_neigh *nce;
    struct in6_addr addr;
    struct eui64 eui64;
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    if (!IN6_IS_ADDR_LINKLOCAL(src)) {
        TRACE(TR_DROP, "drop %-9s: invalid source address", tr_icmp_rpl(RPL_CODE_DIO));
        return;
    }

    dio = iobuf_pop_data_ptr(&iobuf, sizeof(*dio));
    if (!dio)
        goto malformed;

    if (FIELD_GET(RPL_MASK_INSTANCE_ID_TYPE, dio->instance_id) == RPL_INSTANCE_ID_TYPE_LOCAL) {
        TRACE(TR_DROP, "drop %-9s: unsupported local RPL instance", tr_icmp_rpl(RPL_CODE_DIO));
        return;
    }
    if (!FIELD_GET(RPL_MASK_DIO_G, dio->g_mop_prf)) {
        TRACE(TR_DROP, "drop %-9s: unsupported floating DODAG", tr_icmp_rpl(RPL_CODE_DIO));
        return;
    }
    if (FIELD_GET(RPL_MASK_DIO_MOP, dio->g_mop_prf) != RPL_MOP_NON_STORING) {
        TRACE(TR_DROP, "drop %-9s: unsupported mode of operation", tr_icmp_rpl(RPL_CODE_DIO));
        return;
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
            if (!config->min_hop_rank_inc)
                goto malformed;
            break;
        case RPL_OPT_PREFIX:
            if (opt->len < sizeof(*prefix))
                goto malformed;
            if (prefix)
                TRACE(TR_IGNORE, "ignore %-9s: multiple prefix options", tr_icmp_rpl(RPL_CODE_DIO));
            prefix = (const struct rpl_opt_prefix *)(opt + 1);
            if (prefix->prefix_len > 128)
                goto malformed;
            if (!FIELD_GET(RPL_MASK_OPT_PREFIX_R, prefix->flags)) {
                TRACE(TR_DROP, "drop %-9s: unsupported prefix w/o router address", tr_icmp_rpl(RPL_CODE_DIO));
                return;
            }
            addr = prefix->prefix; // -Waddress-of-packed-member
            if (!IN6_IS_ADDR_UC_GLOBAL(&addr)) {
                TRACE(TR_DROP, "drop %-9s: unsupported non-global unicast prefix", tr_icmp_rpl(RPL_CODE_DIO));
                return;
            }
            break;
        default:
            TRACE(TR_IGNORE, "ignore %-9s: unsupported option %u", tr_icmp_rpl(RPL_CODE_DIO), opt->type);
            break;
        }
    }
    if (iobuf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", tr_icmp_rpl(RPL_CODE_DIO));
        return;
    }
    if (!config) {
        TRACE(TR_DROP, "drop %-9s: missing DODAG configuration option", tr_icmp_rpl(RPL_CODE_DIO));
        return;
    }
    if (ntohs(config->ocp) != RPL_OCP_MRHOF) {
        TRACE(TR_DROP, "drop %-9s: unsupported objective function", tr_icmp_rpl(RPL_CODE_DIO));
        return;
    }
    if (!prefix) {
        TRACE(TR_DROP, "drop %-9s: missing prefix information option", tr_icmp_rpl(RPL_CODE_DIO));
        return;
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
    ipv6_addr_conv_iid_eui64(eui64.u8, src->s6_addr + 8);
    nce = ipv6_neigh_fetch(ipv6, &addr, &eui64);

    if (!nce->rpl)
        rpl_neigh_add(ipv6, nce, dio, config, prefix);
    else
        rpl_neigh_update(ipv6, nce, dio, config, prefix);

    // TODO: filter candidate neighbors according to
    // Wi-SUN FAN 1.1v08 6.2.3.1.6.3 Upward Route Formation

    return;

malformed:
    TRACE(TR_DROP, "drop %-9s: malformed packet", tr_icmp_rpl(RPL_CODE_DIO));
}

static bool rpl_opt_solicit_matches(const struct rpl_opt_solicit *solicit, const struct rpl_dio *dio)
{
    const struct in6_addr dodag_id = dio->dodag_id; // -Waddress-of-packed-member

    if (solicit->flags & RPL_MASK_OPT_SOLICIT_I && solicit->instance_id != dio->instance_id)
        return false;
    if (solicit->flags & RPL_MASK_OPT_SOLICIT_D && !IN6_ARE_ADDR_EQUAL(&solicit->dodag_id, &dodag_id))
        return false;
    if (solicit->flags & RPL_MASK_OPT_SOLICIT_V && solicit->dodag_verno != dio->dodag_verno)
        return false;
    return true;
}

static void rpl_recv_dis(struct ipv6_ctx *ipv6, const uint8_t *buf, size_t buf_len,
                         const struct in6_addr *src, const struct in6_addr *dst)
{
    const struct rpl_opt_solicit *solicit;
    const struct rpl_dis *dis;
    const struct rpl_opt *opt;
    struct ipv6_neigh *parent;
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent) {
        TRACE(TR_DROP, "drop %-9s: routing not ready", tr_icmp_rpl(RPL_CODE_DIS));
        return;
    }

    dis = iobuf_pop_data_ptr(&iobuf, sizeof(*dis));
    if (!dis)
        goto malformed;

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
        case RPL_OPT_SOLICIT:
            solicit = (struct rpl_opt_solicit *)iobuf_pop_data_ptr(&iobuf, sizeof(*solicit));
            if (!solicit)
                goto malformed;
            if (!rpl_opt_solicit_matches(solicit, &parent->rpl->dio)) {
                TRACE(TR_DROP, "drop %-9s: solicited information mismatch", tr_icmp_rpl(RPL_CODE_DIS));
                return;
            }
            break;
        default:
            TRACE(TR_IGNORE, "ignore %-9s: unsupported option %u", tr_icmp_rpl(RPL_CODE_DIS), opt->type);
            break;
        }
    }

    if (IN6_IS_ADDR_MULTICAST(dst))
        trickle_inconsistent(&ipv6->rpl.dio_trickle);
    else
        rpl_send_dio(ipv6, src);
    return;

malformed:
    TRACE(TR_DROP, "drop %-9s: malformed packet", tr_icmp_rpl(RPL_CODE_DIS));
}

static void rpl_recv_dao_ack(struct ipv6_ctx *ipv6,
                             const uint8_t *buf, size_t buf_len)
{
    const struct rpl_dao_ack *dao_ack;
    struct ipv6_neigh *parent, *nce;
    struct iobuf_read iobuf = {
        .data_size = buf_len,
        .data = buf,
    };

    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent) {
        TRACE(TR_DROP, "drop %-9s: no preferred parent", tr_icmp_rpl(RPL_CODE_DAO_ACK));
        return;
    }

    dao_ack = iobuf_pop_data_ptr(&iobuf, sizeof(*dao_ack));
    if (!dao_ack) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", tr_icmp_rpl(RPL_CODE_DAO_ACK));
        return;
    }
    if (dao_ack->instance_id != parent->rpl->dio.instance_id) {
        TRACE(TR_DROP, "drop %-9s: InstanceID mismatch", tr_icmp_rpl(RPL_CODE_DAO_ACK));
        return;
    }
    if (dao_ack->flags & RPL_MASK_DAO_ACK_D) {
        TRACE(TR_DROP, "drop %-9s: unsupported DODAGID present", tr_icmp_rpl(RPL_CODE_DAO_ACK));
        return;
    }
    if (timer_stopped(&ipv6->rpl.dao_txalg.timer_rt) || dao_ack->dao_seq != ipv6->rpl.dao_seq) {
        TRACE(TR_DROP, "drop %-9s: unexpected DAOSequence", tr_icmp_rpl(RPL_CODE_DAO_ACK));
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
    if (ipv6->rpl.on_dao_ack)
        ipv6->rpl.on_dao_ack(ipv6);
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
    case RPL_CODE_DIS:
        rpl_recv_dis(ipv6, iobuf_ptr(&buf), iobuf_remaining_size(&buf), src, dst);
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

    BUG_ON(ipv6->rpl.fd < 0);

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

void rpl_stop(struct ipv6_ctx *ipv6)
{
    trickle_stop(&ipv6->rpl.dio_trickle);
    rfc8415_txalg_stop(&ipv6->rpl.dis_txalg);
    rfc8415_txalg_stop(&ipv6->rpl.dao_txalg);
    close(ipv6->rpl.fd);
    ipv6->rpl.fd = -1;
}

void rpl_start(struct ipv6_ctx *ipv6)
{
    struct icmp6_filter filter;
    int err;

    BUG_ON(ipv6->rpl.fd >= 0);
    BUG_ON(!ipv6->rpl.mrhof.ws_neigh_table);
    BUG_ON(!ipv6->rpl.mrhof.max_link_metric);
    BUG_ON(!ipv6->rpl.mrhof.parent_switch_threshold);

    strcpy(ipv6->rpl.dio_trickle.debug_name, "dio");
    ipv6->rpl.dio_trickle.cfg = &ipv6->rpl.dio_trickle_cfg;
    ipv6->rpl.dio_trickle.on_transmit = rpl_send_dio_mc;
    trickle_init(&ipv6->rpl.dio_trickle);
    ipv6->rpl.dis_txalg.tx = rpl_trig_dis;
    rfc8415_txalg_init(&ipv6->rpl.dis_txalg);
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
