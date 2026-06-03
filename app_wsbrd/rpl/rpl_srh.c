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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "common/bits.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/string_extra.h"
#include "common/specs/rpl.h"
#include "common/specs/ipv6.h"
#include "rpl_srh.h"
#include "rpl.h"

void rpl_srh_clear(struct rpl_srh_decmpr *srh)
{
    free(srh->seg_list);
    srh->seg_list = NULL;
    srh->seg_count = 0;
    srh->seg_left = 0;
}

void rpl_srh_trace_err(int err)
{
    static const char *prefix = "tx-abort rpl-srh";

    switch (err) {
    case -ENOENT:
        TRACE(TR_TX_ABORT, "%s: unknown target", prefix);
        break;
    case -EINVAL:
        TRACE(TR_TX_ABORT, "%s: external target", prefix);
        break;
    case -ENETUNREACH:
        TRACE(TR_TX_ABORT, "%s: no route to target", prefix);
        break;
    case -ERANGE:
        TRACE(TR_TX_ABORT, "%s: > %u hops", prefix, WS_RPL_SRH_MAXSEG);
        break;
    case -ELOOP:
        TRACE(TR_TX_ABORT, "%s: loop", prefix);
        break;
    }
}

int rpl_srh_build(struct rpl_root *root, const uint8_t dst[16], uint8_t hlim,
                  struct rpl_srh_decmpr *srh, const uint8_t **nxthop_ret)
{
    __attribute__((cleanup(iobuf_free)))
    struct iobuf_write seg_buf = { };
    struct rpl_transit *transit;
    struct rpl_target *target;
    uint8_t seg_count = 0;
    const uint8_t *nxthop;

    nxthop = dst;
    while (1) {
        target = rpl_target_get(root, nxthop);
        if (!target)
            return -ENOENT;
        if (target->external)
            return -EINVAL;
        // Only consider the preferred parent
        transit = rpl_transit_preferred(root, target);
        if (!transit)
            return -ENETUNREACH;
        if (!memcmp(transit->parent, root->dodag_id, 16))
            break;
        if (seg_count >= WS_RPL_SRH_MAXSEG)
            return -ERANGE;
        for (uint8_t i = 0; i < seg_count; i++)
            if (!memcmp(transit->parent, seg_buf.data + i * 16, 16))
                return -ELOOP;
        iobuf_push_data(&seg_buf, nxthop, 16);
        seg_count++;
        nxthop = transit->parent;
    }

    if (nxthop_ret)
        *nxthop_ret = nxthop;
    if (srh) {
        /*
         *   RFC 6554 4.1. Generating Source Routing Headers
         * In the case that the source route is longer than the original
         * datagram's IPv6 Hop Limit, only the initial hops (determined by the
         * original datagram's IPv6 Hop Limit) should be included in the SRH.
         */
        BUG_ON(!hlim);
        if (hlim - 1 < seg_count) { // NOTE: nxthop is not included in seg_count
            TRACE(TR_RPL, "rpl-srh: clamp from %u to %u segments", seg_count, hlim - 1);
            memmove(seg_buf.data, seg_buf.data + (seg_count - (hlim - 1)) * 16,
                    (hlim - 1) * 16);
            seg_count = hlim - 1;
            if (!seg_count)
                iobuf_free(&seg_buf);
        }
        // NOTE: transfer ownership
        srh->seg_list  = (struct in6_addr *)seg_buf.data;
        seg_buf.data = NULL;
        srh->seg_count = seg_count;
        srh->seg_left  = seg_count;
        for (uint8_t i = 0; i < seg_count / 2; i++)
            memswap(&srh->seg_list[i], &srh->seg_list[seg_count - i - 1], 16);
    }
    return seg_count;
}

// RFC 6554 - 3. Format of the RPL Routing Header
void rpl_srh_push(struct iobuf_write *buf, const struct rpl_srh_decmpr *srh,
                  const uint8_t dst[16], uint8_t nxthdr)
{
    uint8_t cmpri, cmpre, pad;
    size_t size_no_pad;
    uint32_t tmp;

    BUG_ON(!srh->seg_count);
    BUG_ON(srh->seg_left > srh->seg_count);
    cmpri = 15;
    for (uint8_t i = 0; i < srh->seg_count - 1; i++)
        for (uint8_t j = 0; j < cmpri; j++)
            if (srh->seg_list[i].s6_addr[j] != dst[j])
                cmpri = j;
    cmpre = 15;
    for (uint8_t i = 0; i < cmpre; i++)
        if (srh->seg_list[srh->seg_count - 1].s6_addr[i] != dst[i])
            cmpre = i;

    size_no_pad = 8 + (16 - cmpri) * (srh->seg_count - 1) + (16 - cmpre);
    pad = divup(size_no_pad, 8) * 8 - size_no_pad;

    iobuf_push_u8(buf, nxthdr);
    iobuf_push_u8(buf, (size_no_pad + pad) / 8 - 1);
    iobuf_push_u8(buf, IPV6_ROUTING_RPL_SRH);
    iobuf_push_u8(buf, srh->seg_left);
    tmp = 0;
    tmp |= FIELD_PREP(RPL_MASK_SRH_CMPRI, cmpri);
    tmp |= FIELD_PREP(RPL_MASK_SRH_CMPRE, cmpre);
    tmp |= FIELD_PREP(RPL_MASK_SRH_PAD,   pad);
    iobuf_push_be32(buf, tmp);
    for (uint8_t i = 0; i < srh->seg_count - 1; i++)
        iobuf_push_data(buf, srh->seg_list[i].s6_addr + cmpri, 16 - cmpri);
    iobuf_push_data(buf, srh->seg_list[srh->seg_count - 1].s6_addr + cmpre, 16 - cmpre);
    for (uint8_t i = 0; i < pad; i++)
        iobuf_push_u8(buf, 0);
}
