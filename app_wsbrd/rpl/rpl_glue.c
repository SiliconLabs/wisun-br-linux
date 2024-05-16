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
#include <netinet/in.h>

#include "common/bits.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/specs/rpl.h"
#include "common/specs/ipv6.h"

#include "ipv6/ipv6.h"
#include "ipv6/nd_router_object.h"
#include "net/ns_address_internal.h"
#include "app_wsbrd/net/protocol.h"
#include "rpl_glue.h"
#include "rpl_srh.h"
#include "rpl.h"

// The IPv6 extension system from the nanostack is not clear. Design choices
// for this file mostly come from mimicking the legacy RPL implementation.

// RFC 6553 - 3. Format of the RPL Option
bool rpl_glue_process_rpi(struct rpl_root *root, struct buffer *buf,
                          const uint8_t *opt, uint8_t opt_len)
{
    struct iobuf_read iobuf = {
        .data_size = opt_len,
        .data = opt,
    };
    uint8_t flags, instance_id;
    uint16_t rank;

    flags       = iobuf_pop_u8(&iobuf);
    instance_id = iobuf_pop_u8(&iobuf);
    rank        = iobuf_pop_be16(&iobuf);

    if (instance_id != root->instance_id) {
        TRACE(TR_DROP, "drop %-9s: invalid InstanceID", "rpl-ipv6");
        return false;
    }
    // It is not clear from RFC 6550, but it was confirmed by one of the
    // authors that SenderRank = 0 signifies "not set" and the O R F flags
    // should be ignored in that case.
    if (rank) {
        // FIXME: To comply with RFC 6550 11.2.2.2, the packet should only be
        // dropped if the R bit is set.
        if (FIELD_GET(RPL_MASK_RPI_O, flags)) {
            TRACE(TR_DROP, "drop %-9s: invalid down direction", "rpl-ipv6");
            return false;
        }
        if (rank <= rpl_dag_rank(root, rpl_root_rank(root))) {
            TRACE(TR_DROP, "drop %-9s: invalid rank", "rpl-ipv6");
            return false;
        }
    }
    buf->options.ip_extflags |= IPEXT_HBH_RPL;
    return !iobuf.err;
}

static buffer_t *rpl_glue_srh_provider(buffer_t *buf, ipv6_exthdr_stage_e stage, int16_t *res)
{
    __attribute__((cleanup(iobuf_free))) struct iobuf_write srh_buf = { };
    struct rpl_root *root = buf->route->route_info.info;
    const uint8_t *rpl_dst = buf->dst_sa.address;
    struct rpl_transit *transit;
    struct rpl_srh_decmpr srh;
    struct rpl_target *target;
    const uint8_t *nxthop;

    *res = 0;

    target = rpl_target_get(root, buf->dst_sa.address);
    if (!target) {
        *res = -1;
        return buf;
    }
    transit = rpl_transit_preferred(root, target);
    if (!transit) {
        *res = -1;
        return buf;
    }

    //   RFC 6554 - 2. Overview
    // If the SRH only specifies a subset of the path from source to
    // destination, the router uses IPv6-in-IPv6 tunneling [RFC2473] and places
    // the SRH in the outer IPv6 header.
    if (target->external) {
        if (!buf->options.tunnelled && (stage == IPV6_EXTHDR_SIZE || stage == IPV6_EXTHDR_INSERT)) {
            buf->options.ipv6_use_min_mtu = 1;
            return buf;
        }
        rpl_dst = transit->parent;
        target = rpl_target_get(root, rpl_dst);
        if (!target) {
            *res = -1;
            return buf;
        }
    }

    if (rpl_srh_build(root, rpl_dst, &srh, &nxthop) < 0) {
        *res = -1;
        return buf;
    }
    if (!srh.seg_count)
        return buf; // TODO: add hop-by-hop option
    rpl_srh_push(&srh_buf, &srh, nxthop, buf->options.type, root->compat);

    switch (stage) {
    case IPV6_EXTHDR_SIZE:
        *res = srh_buf.len;
        return buf;
    case IPV6_EXTHDR_INSERT:
        buf = buffer_headroom(buf, srh_buf.len);
        if (!buf)
            return NULL;
        memcpy(buffer_data_reserve_header(buf, srh_buf.len), srh_buf.data, srh_buf.len);
        buf->route->ip_dest = nxthop;
        buf->options.type = IPV6_NH_ROUTING;
        buf->options.ip_extflags |= IPEXT_SRH_RPL;
        return buf;
    case IPV6_EXTHDR_MODIFY:
        if (buf->options.ip_extflags & IPEXT_SRH_RPL)
            return buf;
        if (rpl_dst != buf->dst_sa.address)
            memcpy(buf->dst_sa.address, rpl_dst, 16);
        buf->route->ip_dest = nxthop;
        *res = IPV6_EXTHDR_MODIFY_TUNNEL;
        buf->src_sa.addr_type = ADDR_NONE; // force auto-selection
        return buf;
    default:
        return buffer_free(buf);
    }
}

static bool rpl_glue_nxthop(const uint8_t dst[16], ipv6_route_info_t *route)
{
    struct rpl_root *root = route->info;
    const uint8_t *rpl_dst = dst;
    struct rpl_transit *transit;
    struct rpl_target *target;
    const uint8_t *nxthop;

    target = rpl_target_get(root, dst);
    if (!target)
        return false;
    if (target->external) {
        transit = rpl_transit_preferred(root, target);
        if (!transit)
            return false;
        rpl_dst = transit->parent;
    }

    if (rpl_srh_build(root, rpl_dst, NULL, &nxthop) < 0)
        return false;

    memcpy(route->next_hop_addr, nxthop, 16);
    return true;
}

void rpl_glue_init(struct net_if *net_if)
{
    ipv6_set_exthdr_provider(ROUTE_RPL_DAO_SR, rpl_glue_srh_provider);
    ipv6_route_table_set_next_hop_fn(ROUTE_RPL_DAO_SR, rpl_glue_nxthop);
    addr_add_group(net_if, ADDR_LINK_LOCAL_ALL_RPL_NODES);
}
