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

#include "net/timers.h"
#include "app/wsbrd.h" // FIXME
#include "common/bits.h"
#include "common/capture.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/named_values.h"
#include "common/seqno.h"
#include "common/string_extra.h"
#include "common/sys_queue_extra.h"
#include "common/time_extra.h"
#include "common/mathutils.h"
#include "common/specs/icmpv6.h"
#include "common/specs/rpl.h"
#include "rpl_lollipop.h"
#include "rpl_storage.h"
#include "rpl.h"

struct rpl_opt_target {
    uint8_t prefix_len;
    uint8_t prefix[16];
};

struct rpl_opt_transit {
    bool external;
    uint8_t path_ctl;
    uint8_t path_seq;
    uint8_t path_lifetime;
    uint8_t parent[16];
};

const uint8_t rpl_all_nodes[16] = { // ff02::1a
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a,
};

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

struct rpl_target *rpl_target_get(struct rpl_root *root, const uint8_t prefix[16])
{
    struct rpl_target *target;

    return SLIST_FIND(target, &root->targets, link,
                      !memcmp(target->prefix, prefix, 16));
}

static void rpl_transit_expire(struct timer_group *group, struct timer_entry *timer);
struct rpl_target *rpl_target_new(struct rpl_root *root, const uint8_t prefix[16])
{
    struct rpl_target *target = zalloc(sizeof(struct rpl_target));

    target->timer.callback = rpl_transit_expire;
    memcpy(target->prefix, prefix, 16);
    SLIST_INSERT_HEAD(&root->targets, target, link);
    if (root->on_target_add)
        root->on_target_add(root, target);
    return target;
}

void rpl_target_del(struct rpl_root *root, struct rpl_target *target)
{
    TRACE(TR_RPL, "rpl: target  remove prefix=%s", tr_ipv6_prefix(target->prefix, 128));
    SLIST_REMOVE(&root->targets, target, rpl_target, link);
    if (root->on_target_del)
        root->on_target_del(root, target);
    free(target);
}

uint16_t rpl_target_count(struct rpl_root *root)
{
    return SLIST_SIZE(&root->targets, link);
}

struct rpl_transit *rpl_transit_preferred(struct rpl_root *root, struct rpl_target *target)
{
    for (uint8_t i = 0; i < root->pcs + 1; i++)
        if (memzcmp(target->transits + i, sizeof(struct rpl_transit)))
            return target->transits + i;
    return NULL;
}

static void rpl_transit_update_timer(struct rpl_root *root, struct rpl_target *target)
{
    uint64_t expire_s = UINT64_MAX;

    for (uint8_t i = 0; i < root->pcs + 1; i++) {
        if (!memzcmp(target->transits + i, sizeof(struct rpl_transit)))
            continue;
        if (expire_s > target->path_seq_tstamp_s + target->transits[i].path_lifetime_s)
            expire_s = target->path_seq_tstamp_s + target->transits[i].path_lifetime_s;
    }
    timer_start_abs(&root->timer_group, &target->timer, expire_s * 1000);
}

static void rpl_transit_expire(struct timer_group *group, struct timer_entry *timer)
{
    struct rpl_target *target = container_of(timer, struct rpl_target, timer);
    struct rpl_root *root = container_of(group, struct rpl_root, timer_group);
    time_t elapsed;

    elapsed = time_get_elapsed(CLOCK_MONOTONIC, target->path_seq_tstamp_s);
    for (uint8_t i = 0; i < root->pcs + 1; i++) {
        if (!memzcmp(target->transits + i, sizeof(struct rpl_transit)))
            continue;
        if (elapsed < target->transits[i].path_lifetime_s)
            continue;
        TRACE(TR_RPL, "rpl: transit expire target=%s parent=%s path-ctl-bit=%u",
                tr_ipv6_prefix(target->prefix, 128), tr_ipv6(target->transits[i].parent), i);
        memset(target->transits + i, 0, sizeof(struct rpl_transit));
    }
    if (!memzcmp(target->transits, sizeof(target->transits)))
        rpl_target_del(root, target);
    else
        rpl_transit_update_timer(root, target);
}

static void rpl_dio_trickle_params(struct rpl_root *root, struct trickle_params *params)
{
    memset(params, 0, sizeof(struct trickle_params));
    //   RFC 6550 - 8.3.1. Trickle Parameters
    // Imin: learned from the DIO message as (2^DIOIntervalMin) ms.
    params->Imin = roundup(POW2(root->dio_i_min),
                           g_timers[WS_TIMER_RPL].period_ms) / g_timers[WS_TIMER_RPL].period_ms;
    params->Imax = roundup(POW2(root->dio_i_min + root->dio_i_doublings),
                           g_timers[WS_TIMER_RPL].period_ms) / g_timers[WS_TIMER_RPL].period_ms;
    params->k    = root->dio_redundancy;
    params->TimerExpirations = TRICKLE_EXPIRATIONS_INFINITE;
}

void rpl_dodag_version_inc(struct rpl_root *root)
{
    struct trickle_params dio_trickle_params;

    root->dodag_version_number = rpl_lollipop_inc(root->dodag_version_number);
    //   RFC 6550 - 8.3. DIO Transmission
    // The following packets and events MUST be considered inconsistencies with
    // respect to the Trickle timer, and cause the Trickle timer to reset:
    // - When a node joins a new DODAG Version (e.g., by updating its
    //   DODAGVersionNumber, joining a new RPL Instance, etc.).
    rpl_dio_trickle_params(root, &dio_trickle_params);
    trickle_inconsistent_heard(&root->dio_trickle, &dio_trickle_params);
}

void rpl_dtsn_inc(struct rpl_root *root)
{
    struct trickle_params dio_trickle_params;

    root->dtsn++;
    rpl_dio_trickle_params(root, &dio_trickle_params);
    trickle_inconsistent_heard(&root->dio_trickle, &dio_trickle_params);
}

// RFC 6550 - 6.7.1. RPL Control Message Option Generic Format
static int rpl_opt_push(struct iobuf_write *buf, uint8_t type)
{
    int offset;

    iobuf_push_u8(buf, type);
    offset = buf->len;
    // Length is filled by calling rpl_opt_fill() with the returned offset.
    iobuf_push_u8(buf, 0);
    return offset;
}

static void rpl_opt_fill(struct iobuf_write *buf, int offset)
{
    const size_t len = buf->len - offset - 1;

    BUG_ON(buf->data[offset]);
    BUG_ON(len > UINT8_MAX);
    buf->data[offset] = len;
}

// RFC 6550 - 6.7.6. DODAG Configuration
static void rpl_opt_push_config(struct iobuf_write *buf, struct rpl_root *root)
{
    uint8_t bitfield;
    int offset;

    offset = rpl_opt_push(buf, RPL_OPT_CONFIG);
    bitfield = 0;
    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // The Authentication Enabled flag MUST be set to 0.
    bitfield |= FIELD_PREP(RPL_MASK_OPT_CONFIG_A, 0);
    bitfield |= FIELD_PREP(RPL_MASK_OPT_CONFIG_PCS, root->pcs);
    bitfield |= FIELD_PREP(RPL_MASK_OPT_CONFIG_RPI, root->rpi_ignorable);
    iobuf_push_u8(buf, bitfield);
    iobuf_push_u8(buf, root->dio_i_doublings);
    iobuf_push_u8(buf, root->dio_i_min);
    iobuf_push_u8(buf, root->dio_redundancy);
    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // The MaxRankIncrease field MUST be set to 0.
    iobuf_push_be16(buf, 0);
    iobuf_push_be16(buf, root->min_rank_hop_inc);
    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // The OCP field MUST be set to 1 to indicate usage of the MRHOF objective
    // function.
    iobuf_push_be16(buf, RPL_OCP_MRHOF);
    iobuf_push_u8(buf, 0); // Reserved
    iobuf_push_u8(buf, root->lifetime_s / root->lifetime_unit_s); // Default Lifetime
    iobuf_push_be16(buf, root->lifetime_unit_s);
    rpl_opt_fill(buf, offset);
}

// RFC 6550 - 6.7.6. DODAG Configuration
static void rpl_opt_push_prefix(struct iobuf_write *buf, struct rpl_root *root)
{
    int offset;

    offset = rpl_opt_push(buf, RPL_OPT_PREFIX);
    iobuf_push_u8(buf, 64);           // Prefix Length
    iobuf_push_u8(buf, FIELD_PREP(RPL_MASK_OPT_PREFIX_R, 1));
    iobuf_push_be32(buf, 0xffffffff); // Valid Lifetime
    iobuf_push_be32(buf, 0xffffffff); // Preferred Lifetime
    iobuf_push_be32(buf, 0);          // Reserved
    iobuf_push_data(buf, root->dodag_id, 16);
    rpl_opt_fill(buf, offset);
}

static void rpl_send(struct rpl_root *root, uint8_t code,
                     const uint8_t *pkt, size_t size,
                     const uint8_t dst[16])
{
    struct sockaddr_in6 addr = { .sin6_family = AF_INET6 };
    uint8_t icmpv6_hdr[4] = { ICMPV6_TYPE_RPL, code }; // Checksum filled by kernel
    struct iovec iov[2] = {
        { .iov_base = icmpv6_hdr,  .iov_len = sizeof(icmpv6_hdr) },
        { .iov_base = (void *)pkt, .iov_len = size               },
    };
    struct msghdr msg = {
        .msg_name    = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov     = iov,
        .msg_iovlen  = ARRAY_SIZE(iov),
    };
    ssize_t ret;

    memcpy(addr.sin6_addr.s6_addr, dst, 16);
    ret = xsendmsg(root->sockfd, &msg, 0);
    if (ret < sizeof(icmpv6_hdr) + size)
        FATAL(2, "%s: sendto %s: %m", __func__, tr_ipv6(dst));
    TRACE(TR_ICMP, "tx-icmp rpl-%-9s dst=%s", tr_icmp_rpl(code), tr_ipv6(dst));
}

// RFC 6550 - 6.3.1. Format of the DIO Base Object
static void rpl_send_dio(struct rpl_root *root, const uint8_t dst[16])
{
    struct iobuf_write buf = { };
    uint8_t bitfield;

    iobuf_push_u8(&buf, root->instance_id);
    iobuf_push_u8(&buf, root->dodag_version_number);
    iobuf_push_be16(&buf, rpl_root_rank(root));
    bitfield = 0;
    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // The G flag MUST be set to 1 (the DODAG is grounded).
    bitfield |= FIELD_PREP(RPL_MASK_DIO_G, 1);
    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // The MOP field MUST be set to 1 (Non-Storing mode of RPL).
    bitfield |= FIELD_PREP(RPL_MASK_DIO_MOP, RPL_MOP_NON_STORING);
    bitfield |= FIELD_PREP(RPL_MASK_DIO_PRF, root->dodag_pref);
    iobuf_push_u8(&buf, bitfield);
    iobuf_push_u8(&buf, root->dtsn);
    iobuf_push_u8(&buf, 0); // Flags
    iobuf_push_u8(&buf, 0); // Reserved
    iobuf_push_data(&buf, root->dodag_id, 16);

    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // A DODAG Configuration Option MUST be included
    rpl_opt_push_config(&buf, root);
    rpl_opt_push_prefix(&buf, root); // FIXME: is this necessary?

    rpl_send(root, RPL_CODE_DIO, buf.data, buf.len, dst);
    iobuf_free(&buf);
}

static void rpl_send_dao_ack(struct rpl_root *root, const uint8_t dst[16], uint8_t dao_seq)
{
    struct iobuf_write buf = { };

    iobuf_push_u8(&buf, root->instance_id);
    iobuf_push_u8(&buf, FIELD_PREP(RPL_MASK_DAO_ACK_D, 0));
    iobuf_push_u8(&buf, dao_seq);
    iobuf_push_u8(&buf, 0); // Status

    rpl_send(root, RPL_CODE_DAO_ACK, buf.data, buf.len, dst);
    iobuf_free(&buf);
}

// RFC 6550 - 6.7.9. Solicited Information
static bool rpl_opt_solicit_matches(struct iobuf_read *opt_buf, struct rpl_root *root)
{
    uint8_t instance_id, bitfield;
    uint8_t dodag_version_number;
    const uint8_t *dodag_id;

    instance_id          = iobuf_pop_u8(opt_buf);
    bitfield             = iobuf_pop_u8(opt_buf);
    dodag_id             = iobuf_pop_data_ptr(opt_buf, 16);
    dodag_version_number = iobuf_pop_u8(opt_buf);
    if (opt_buf->err)
        return false;
    if (FIELD_GET(RPL_MASK_OPT_SOLICIT_V, bitfield) && dodag_version_number != root->dodag_version_number)
        return false;
    if (FIELD_GET(RPL_MASK_OPT_SOLICIT_I, bitfield) && instance_id != root->instance_id)
        return false;
    if (FIELD_GET(RPL_MASK_OPT_SOLICIT_D, bitfield) && memcmp(dodag_id, root->dodag_id, 16))
        return false;
    return true;
}

static void rpl_recv_dis(struct rpl_root *root, const uint8_t *pkt, size_t size,
                         const uint8_t src[16], const uint8_t dst[16])
{
    struct trickle_params dio_trickle_params;
    struct iobuf_read opt_buf;
    struct iobuf_read buf = {
        .data_size = size,
        .data = pkt,
    };
    uint8_t opt_type;

    iobuf_pop_u8(&buf); // Flags
    iobuf_pop_u8(&buf); // Reserved

    while (iobuf_remaining_size(&buf)) {
        opt_type = iobuf_pop_u8(&buf);
        if (opt_type == RPL_OPT_PAD1)
            continue;
        opt_buf.data_size = iobuf_pop_u8(&buf);
        opt_buf.data      = iobuf_pop_data_ptr(&buf, opt_buf.data_size);
        opt_buf.err       = buf.err;
        opt_buf.cnt       = 0;
        switch (opt_type) {
        case RPL_OPT_PADN:
            continue;
        case RPL_OPT_SOLICIT:
            if (!rpl_opt_solicit_matches(&opt_buf, root)) {
                TRACE(TR_DROP, "drop %-9s: solicit info mismatch", "rpl-dis");
                return;
            }
            break;
        default:
            TRACE(TR_IGNORE, "ignore: rpl-dis unsupported option %u", opt_type);
            break;
        }
        buf.err |= opt_buf.err;
    }
    if (buf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "rpl-dis");
        return;
    }
    // RFC 6550 - 8.3. DIO Transmission
    if (IN6_IS_ADDR_MULTICAST(dst)) {
        rpl_dio_trickle_params(root, &dio_trickle_params);
        trickle_inconsistent_heard(&root->dio_trickle, &dio_trickle_params);
    } else {
        rpl_send_dio(root, src);
    }
}

static bool rpl_opt_target_parse(struct iobuf_read *opt_buf,
                                 struct rpl_opt_target *opt_target)
{
    iobuf_pop_u8(opt_buf); // Flags
    opt_target->prefix_len = iobuf_pop_u8(opt_buf);
    if (opt_target->prefix_len > 128) {
        opt_buf->err = true;
        return false;
    }
    iobuf_pop_data(opt_buf, opt_target->prefix, roundup(opt_target->prefix_len, 8) / 8);
    return !opt_buf->err;
}

static bool rpl_opt_transit_parse(struct iobuf_read *opt_buf,
                                  struct rpl_opt_transit *transit)
{
    transit->external      = FIELD_GET(RPL_MASK_OPT_TRANSIT_E, iobuf_pop_u8(opt_buf));
    transit->path_ctl      = iobuf_pop_u8(opt_buf);
    transit->path_seq      = iobuf_pop_u8(opt_buf);
    transit->path_lifetime = iobuf_pop_u8(opt_buf);
    iobuf_pop_data(opt_buf, transit->parent, 16);
    return !opt_buf->err;
}

static void rpl_transit_update(struct rpl_root *root,
                               struct rpl_opt_target *opt_target,
                               struct rpl_opt_transit *opt_transit)
{
    bool path_ctl_desync, path_ctl_old;
    struct rpl_transit transit;
    struct rpl_target *target;
    bool updated = false;

    BUG_ON(opt_target->prefix_len != 128);
    memcpy(transit.parent, opt_transit->parent, 16);
    transit.path_lifetime_s = opt_transit->path_lifetime * root->lifetime_unit_s;

    target = rpl_target_get(root, opt_target->prefix);
    if (!target) {
        target = rpl_target_new(root, opt_target->prefix);
        BUG_ON(!target);
        target->external = opt_transit->external;
        target->path_seq = opt_transit->path_seq;
        target->path_seq_tstamp_s = time_current(CLOCK_MONOTONIC);
        updated = true;
        TRACE(TR_RPL, "rpl: target  new    prefix=%s path-seq=%u external=%u",
              tr_ipv6_prefix(target->prefix, 128), target->path_seq, target->external);
    }

    if (root->compat) {
        target->path_seq = opt_transit->path_seq;
        target->path_seq_tstamp_s = time_current(CLOCK_MONOTONIC);
        updated = true;
        TRACE(TR_RPL, "rpl: target  update prefix=%s path-seq=%u",
              tr_ipv6_prefix(target->prefix, 128), target->path_seq);
    } else {
        path_ctl_desync = rpl_lollipop_desync(opt_transit->path_seq, target->path_seq);
        path_ctl_old    = rpl_lollipop_cmp(opt_transit->path_seq, target->path_seq) < 0;
        if (path_ctl_desync || path_ctl_old) {
            TRACE(TR_RPL, "rpl: transit ignore target=%s path-seq=(cur %3u, rcv %3u, %s)",
                  tr_ipv6_prefix(target->prefix, 128), target->path_seq, opt_transit->path_seq,
                  path_ctl_desync ? "desync" : "old");
            return;
        }
        if (rpl_lollipop_cmp(opt_transit->path_seq, target->path_seq) > 0) {
            memset(target->transits, 0, sizeof(target->transits));
            target->path_seq = opt_transit->path_seq;
            target->path_seq_tstamp_s = time_current(CLOCK_MONOTONIC);
            updated = true;
            TRACE(TR_RPL, "rpl: target  update prefix=%s path-seq=%u",
                  tr_ipv6_prefix(target->prefix, 128), target->path_seq);
        }
    }

    WARN_ON(opt_transit->external != target->external);
    target->external = opt_transit->external;

    for (uint8_t i = 0; i < root->pcs + 1; i++) {
        if (!(opt_transit->path_ctl & BIT(7 - i)))
            continue;
        if (memzcmp(target->transits + i, sizeof(struct rpl_transit)) &&
            memcmp(target->transits + i, &transit, sizeof(struct rpl_transit)) && !root->compat)
            WARN("%s: overwrite", __func__);
        target->transits[i] = transit;
        updated = true;
        TRACE(TR_RPL, "rpl: transit new    target=%s parent=%s path-ctl-bit=%u",
              tr_ipv6_prefix(target->prefix, 128), tr_ipv6(target->transits[i].parent), i);
    }
    if (updated && root->on_target_update)
        root->on_target_update(root, target);
    rpl_transit_update_timer(root, target);
}

static void rpl_recv_dao(struct rpl_root *root, const uint8_t *pkt, size_t size,
                         const uint8_t src[16], const uint8_t dst[16])
{
    struct iobuf_read opt_buf;
    struct iobuf_read buf = {
        .data_size = size,
        .data = pkt,
    };
    const uint8_t *dodag_id = NULL;
    struct rpl_opt_transit opt_transit;
    struct rpl_opt_target opt_target;
    bool has_transit = false;
    bool has_target = false;
    uint8_t instance_id;
    uint8_t bitfield;
    uint8_t opt_type;
    uint8_t dao_seq;

    if (IN6_IS_ADDR_MULTICAST(dst)) {
        TRACE(TR_DROP, "drop %-9s: unsupported multicast DAO", "rpl-dao");
        return;
    }
    instance_id = iobuf_pop_u8(&buf);
    bitfield    = iobuf_pop_u8(&buf);
    iobuf_pop_u8(&buf); // Reserved
    dao_seq     = iobuf_pop_u8(&buf);
    if (FIELD_GET(RPL_MASK_DAO_D, bitfield))
        dodag_id = iobuf_pop_data_ptr(&buf, 16);
    if (instance_id != root->instance_id ||
        (dodag_id && memcmp(dodag_id, root->dodag_id, 16))) {
        TRACE(TR_DROP, "drop %-9s: wrong instance", "rpl-dao");
        return;
    }

    while (iobuf_remaining_size(&buf)) {
        opt_type = iobuf_pop_u8(&buf);
        if (opt_type == RPL_OPT_PAD1)
            continue;
        opt_buf.data_size = iobuf_pop_u8(&buf);
        opt_buf.data      = iobuf_pop_data_ptr(&buf, opt_buf.data_size);
        opt_buf.err       = buf.err;
        opt_buf.cnt       = 0;
        switch (opt_type) {
        case RPL_OPT_PADN:
            break;
        case RPL_OPT_TARGET:
            if (has_target && !has_transit)
                TRACE(TR_IGNORE, "ignore: rpl-dao consecutive target options");
            has_transit = false;
            if (!rpl_opt_target_parse(&opt_buf, &opt_target))
                break;
            if (opt_target.prefix_len != 128) {
                TRACE(TR_IGNORE, "ignore: rpl-dao target prefix length != 128");
                break;
            }
            has_target = true;
            break;
        case RPL_OPT_TRANSIT:
            if (!has_target) {
                TRACE(TR_IGNORE, "ignore: rpl-dao transit without target");
                break;
            }
            if (!rpl_opt_transit_parse(&opt_buf, &opt_transit))
                break;
            has_transit = true;
            rpl_transit_update(root, &opt_target, &opt_transit);
            break;
        default:
            TRACE(TR_IGNORE, "ignore: rpl-dao unsupported option %u", opt_type);
            break;
        }
        buf.err |= opt_buf.err;
    }
    if (buf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "rpl-dao");
        return;
    }
    if (FIELD_GET(RPL_MASK_DAO_K, bitfield))
        rpl_send_dao_ack(root, src, dao_seq);
}

void rpl_recv_srh_err(struct rpl_root *root,
                      const uint8_t *pkt, size_t size,
                      const uint8_t src[16])
{
    struct iobuf_read iobuf = {
        .data_size = size,
        .data = pkt,
    };
    struct rpl_target *target;
    bool updated = false;
    const uint8_t *dst;

    //   RFC 6550 - 11.2.2.3. DAO Inconsistency Detection and Recovery
    // The portion of the invoking packet that is sent back in the ICMP message
    // should record at least up to the routing header, and the routing header
    // should be consumed by this node so that the destination in the IPv6
    // header is the next hop that this node could not reach.

    // FIXME: Only minimum parsing is done, and the source address of the
    // ICMPv6 packet is assumed to be same one used in the SRH.
    iobuf_pop_be32(&iobuf); // Version | Traffic Class | Flow Label
    iobuf_pop_be16(&iobuf); // Payload Length
    iobuf_pop_u8(&iobuf);   // Next Header
    iobuf_pop_u8(&iobuf);   // Hop Limit
    iobuf_pop_data_ptr(&iobuf, 16); // Source Address
    dst = iobuf_pop_data_ptr(&iobuf, 16);

    if (iobuf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "rpl-srh-err");
        return;
    }

    target = rpl_target_get(root, dst);
    if (!target) {
        TRACE(TR_DROP, "drop %-9s: unknown target=%s", "rpl-srh-err", tr_ipv6(dst));
        return;
    }
    for (uint8_t i = 0; i < root->pcs + 1; i++) {
        if (!memcmp(target->transits[i].parent, src, 16)) {
            memset(target->transits + i, 0, sizeof(struct rpl_transit));
            updated = true;
            TRACE(TR_RPL, "rpl: transit remove target=%s parent=%s path-ctl-bit=%u",
                  tr_ipv6_prefix(dst, 128), tr_ipv6(src), i);
        }
    }
    if (updated && root->on_target_update)
        root->on_target_update(root, target);
}

static void rpl_recv_dispatch(struct rpl_root *root, const uint8_t *pkt, size_t size,
                              const uint8_t src[16], const uint8_t dst[16])
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
    switch (type) {
    case ICMPV6_TYPE_RPL:
        TRACE(TR_ICMP, "rx-icmp rpl-%-9s src=%s", tr_icmp_rpl(code), tr_ipv6(src));
        switch (code) {
        case RPL_CODE_DIS:
            rpl_recv_dis(root, iobuf_ptr(&buf), iobuf_remaining_size(&buf), src, dst);
            break;
        case RPL_CODE_DAO:
            rpl_recv_dao(root, iobuf_ptr(&buf), iobuf_remaining_size(&buf), src, dst);
            break;
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported code %u", "rpl", code);
            break;
        }
        break;
    case ICMP6_DST_UNREACH:
        if (code != ICMPV6_CODE_DST_UNREACH_SRH)
            return;
        TRACE(TR_ICMP, "rx-icmp rpl-srh-err src=%s", tr_ipv6(src));
        iobuf_pop_be32(&buf); // Unused
        rpl_recv_srh_err(root, iobuf_ptr(&buf), iobuf_remaining_size(&buf), src);
        break;
    default:
        BUG();
    }
}

void rpl_recv(struct rpl_root *root)
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

    size = xrecvmsg(root->sockfd, &msg, 0);
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
    rpl_recv_dispatch(root, iov.iov_base, size,
                      src.sin6_addr.s6_addr, pktinfo->ipi6_addr.s6_addr);
}

void rpl_start(struct rpl_root *root,
               const char ifname[IF_NAMESIZE])
{
    struct trickle_params dio_trickle_params;
    struct icmp6_filter filter;
    int err;

    BUG_ON(!root->min_rank_hop_inc);
    BUG_ON(!memzcmp(root->dodag_id, 16));
    BUG_ON(root->pcs > 7);
    BUG_ON(!root->lifetime_s);
    BUG_ON(!root->lifetime_unit_s);
    BUG_ON(root->lifetime_s % root->lifetime_unit_s);
    //   Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    // The RPLInstanceID MUST be of the global form.
    BUG_ON(FIELD_GET(RPL_MASK_INSTANCE_ID_TYPE, root->instance_id) != RPL_INSTANCE_ID_TYPE_GLOBAL);

    root->sockfd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    FATAL_ON(root->sockfd < 0, 2, "%s: socket: %m", __func__);
    capture_register_netfd(root->sockfd);
    err = setsockopt(root->sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (int[1]){ true }, sizeof(int));
    FATAL_ON(err < 0, 2, "%s: setsockopt IPV6_RECVPKTINFO: %m", __func__);
    err = setsockopt(root->sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (int[1]){ false }, sizeof(int));
    FATAL_ON(err < 0, 2, "%s: setsockopt IPV6_MULTICAST_LOOP: %m", __func__);
    err = setsockopt(root->sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, IF_NAMESIZE);
    FATAL_ON(err < 0, 2, "%s: setsockopt SO_BINDTODEVICE %s: %m", __func__, ifname);
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ICMPV6_TYPE_RPL, &filter);
    ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);
    err = setsockopt(root->sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    FATAL_ON(err < 0, 2, "%s: setsockopt ICMP6_FILTER: %m", __func__);

    rpl_dio_trickle_params(root, &dio_trickle_params);
    trickle_start(&root->dio_trickle, "RPL DIO", &dio_trickle_params);
    timer_group_init(&root->timer_group);
    ws_timer_start(WS_TIMER_RPL);

    rpl_storage_store_config(root);
}

void rpl_timer(int ticks)
{
    struct trickle_params dio_trickle_params;
    struct rpl_root *root = &g_ctxt.net_if.rpl_root;

    rpl_dio_trickle_params(root, &dio_trickle_params);
    if (trickle_timer(&root->dio_trickle, &dio_trickle_params, ticks))
        rpl_send_dio(root, rpl_all_nodes);
}
