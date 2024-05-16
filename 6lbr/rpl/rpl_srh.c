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
#include <string.h>

#include "common/bits.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/specs/rpl.h"
#include "common/specs/ipv6.h"
#include "rpl_srh.h"
#include "rpl.h"

int rpl_srh_build(struct rpl_root *root, const uint8_t dst[16],
                  struct rpl_srh_decmpr *srh, const uint8_t **nxthop_ret)
{
    const uint8_t *seg_list[WS_RPL_SRH_MAXSEG];
    struct rpl_transit *transit;
    struct rpl_target *target;
    uint8_t seg_count = 0;
    const uint8_t *nxthop;

    nxthop = dst;
    while (1) {
        target = rpl_target_get(root, nxthop);
        if (!target) {
            TRACE(TR_TX_ABORT, "tx-abort: rpl srh unknown target %s", tr_ipv6(nxthop));
            return -1;
        }
        if (target->external) {
            TRACE(TR_TX_ABORT, "tx-abort: rpl srh external target %s", tr_ipv6(target->prefix));
            return -1;
        }
        // Only consider the preferred parent
        transit = rpl_transit_preferred(root, target);
        if (!transit) {
            TRACE(TR_TX_ABORT, "tx-abort: rpl srh no transit to target %s", tr_ipv6(target->prefix));
            return -1;
        }
        if (!memcmp(transit->parent, root->dodag_id, 16))
            break;
        if (seg_count > WS_RPL_SRH_MAXSEG) {
            TRACE(TR_TX_ABORT, "tx-abort: rpl srh > %u hops", WS_RPL_SRH_MAXSEG);
            return -1;
        }
        for (uint8_t i = 0; i < seg_count; i++) {
            if (!memcmp(transit->parent, seg_list[i], 16)) {
                TRACE(TR_TX_ABORT, "tx-abort: rpl srh loop");
                return -1;
            }
        }
        seg_list[seg_count++] = nxthop;
        nxthop = transit->parent;
    }

    if (nxthop_ret)
        *nxthop_ret = nxthop;
    if (srh) {
        srh->seg_count = seg_count;
        srh->seg_left  = seg_count;
        for (uint8_t i = 0; i < seg_count; i++)
            memcpy(srh->seg_list[i], seg_list[seg_count - i - 1], 16);
    }
    return seg_count;
}

// RFC 6554 - 3. Format of the RPL Routing Header
void rpl_srh_push(struct iobuf_write *buf, const struct rpl_srh_decmpr *srh,
                  const uint8_t dst[16], uint8_t nxthdr, bool cmpri_eq_cmpre)
{
    uint8_t cmpri, cmpre, pad;
    size_t size_no_pad;
    uint32_t tmp;

    BUG_ON(!srh->seg_count);
    BUG_ON(srh->seg_left > srh->seg_count);
    cmpri = 16;
    for (uint8_t i = 0; i < srh->seg_count - 1; i++)
        for (uint8_t j = 0; j < cmpri; j++)
            if (srh->seg_list[i][j] != dst[j])
                cmpri = j;
    cmpre = 16;
    for (uint8_t i = 0; i < cmpre; i++)
        if (srh->seg_list[srh->seg_count - 1][i] != dst[i])
            cmpre = i;
    if (cmpri_eq_cmpre) {
        // FIXME: Silicon Labs embedded stack incorrectly support cases where
        // swapping the final address changes the compression scheme. To remain
        // compatible, choice is made to use a worse compression scheme.
        cmpri = MIN(cmpri, cmpre);
        cmpre = cmpri;
    }

    size_no_pad = 8 + (16 - cmpri) * (srh->seg_count - 1) + (16 - cmpre);
    pad = roundup(size_no_pad, 8) - size_no_pad;

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
        iobuf_push_data(buf, srh->seg_list[i] + cmpri, 16 - cmpri);
    iobuf_push_data(buf, srh->seg_list[srh->seg_count - 1] + cmpre, 16 - cmpre);
    for (uint8_t i = 0; i < pad; i++)
        iobuf_push_u8(buf, 0);
}
