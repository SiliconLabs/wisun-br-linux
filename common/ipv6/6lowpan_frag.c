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
#include <sys/queue.h>
#include <errno.h>

#include "common/ipv6/6lowpan_iphc.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/specs/6lowpan.h"
#include "common/bits.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/sys_queue_extra.h"

#include "6lowpan_frag.h"

/*
 *   RFC 815 2. The Algorithm
 * Each hole can be characterized by two numbers, hole.first, the number of the
 * first octet in the hole, and hole.last, the number of the last octet in the
 * hole.
 *
 * NOTE: hole.last is replaced with hole.end (ie. hole.last + 1) to simplify
 * handling of 0 length fragments.
 */
struct lowpan_hole {
    uint16_t first;
    uint16_t end;
    SLIST_ENTRY(lowpan_hole) link;
};

// Declare struct lowpan_hole_list
SLIST_HEAD(lowpan_hole_list, lowpan_hole);

struct lowpan_reasm {
    SLIST_ENTRY(lowpan_reasm) link;
    struct eui64 src;
    struct eui64 dst;
    uint16_t len;
    uint16_t tag;
    struct timer_entry timer;
    struct lowpan_hole_list holes;
    uint8_t buf[];
};

static void lowpan_hole_add(struct lowpan_reasm *reasm,
                            uint16_t first, uint16_t end)
{
    struct lowpan_hole *hole = zalloc(sizeof(struct lowpan_hole));

    // NOTE: Always insert to the head for simplicity.
    hole->first = first;
    hole->end   = end;
    SLIST_INSERT_HEAD(&reasm->holes, hole, link);
}

static int lowpan_reasm_update(struct lowpan_reasm *reasm,
                               const void *buf, size_t buf_len,
                               uint8_t offset)
{
    struct lowpan_hole *prev, *hole, *next;
    uint16_t frag_first, frag_end;
    uint16_t hole_first, hole_end;

    frag_first = offset * 8;
    frag_end   = frag_first + buf_len;

    if (frag_end > reasm->len)
        return -EINVAL;

    /*
     *   RFC 4944 5.3. Fragmentation Type and Header
     * [...] all link fragments for a datagram except the last on MUST be
     * multiples of eight bytes in length.
     */
    if (frag_end != reasm->len && buf_len % 8 != 0)
        return -EINVAL;

    // RFC 815 3. Fragment Processing Algorithm
    for (prev = NULL, hole = SLIST_FIRST(&reasm->holes);
         hole && (next = SLIST_NEXT(hole, link), 1);
         prev = hole, hole = next) {

        hole_first = hole->first;
        hole_end   = hole->end;

        // Check overlap
        if (frag_first >= hole_end || frag_end <= hole_first)
            continue;

        // Remove hole
        if (!prev)
            SLIST_FIRST(&reasm->holes) = next;
        else
            SLIST_NEXT(prev, link) = next;
        free(hole);

        // Split hole
        if (frag_first > hole_first)
            lowpan_hole_add(reasm, hole_first, frag_first);
        if (frag_end < hole_end)
            lowpan_hole_add(reasm, frag_end, hole_end);
    }
    memcpy(reasm->buf + frag_first, buf, buf_len);
    return 0;
}

static struct lowpan_reasm *lowpan_reasm_get(struct lowpan_frag_ctx *ctx,
                                             const struct eui64 *src,
                                             const struct eui64 *dst,
                                             uint16_t tag, uint16_t len)
{
    struct lowpan_reasm *reasm;

    /*
     *   RFC 4944 5.3.  Fragmentation Type and Header
     * The recipient of link fragments SHALL use (1) the sender's 802.15.4
     * source address, (2) the destination's 802.15.4 address, (3)
     * datagram_size, and (4) datagram_tag to identify all the link fragments
     * that belong to a given datagram.
     */
    return SLIST_FIND(reasm, &ctx->reasm_list, link,
                      eui64_eq(&reasm->src, src) &&
                      eui64_eq(&reasm->dst, dst) &&
                      reasm->tag == tag && reasm->len == len);
}

static void lowpan_reasm_del(struct lowpan_frag_ctx *ctx,
                             struct lowpan_reasm *reasm)
{
    struct lowpan_hole *hole;

    while ((hole = SLIST_FIRST(&reasm->holes))) {
        SLIST_REMOVE_HEAD(&reasm->holes, link);
        free(hole);
    }
    SLIST_REMOVE(&ctx->reasm_list, reasm, lowpan_reasm, link);
    timer_stop(&ctx->timer_group, &reasm->timer);
    free(reasm);
}

static void lowpan_reasm_expire(struct timer_group *group, struct timer_entry *timer)
{
    struct lowpan_frag_ctx *ctx = container_of(group, struct lowpan_frag_ctx, timer_group);
    struct lowpan_reasm *reasm = container_of(timer, struct lowpan_reasm, timer);
    const struct lowpan_hole *hole;
    uint16_t len = 0;

    SLIST_FOREACH(hole, &reasm->holes, link)
        len += hole->end - hole->first;

    TRACE(TR_IPV6, "6lowpan: reasm drop src=%s tag=0x%04x len=%u/%u",
          tr_eui64(reasm->src.u8), reasm->tag, reasm->len - len, reasm->len);
    lowpan_reasm_del(ctx, reasm);
}

static struct lowpan_reasm *lowpan_reasm_new(struct lowpan_frag_ctx *ctx,
                                             const struct eui64 *src,
                                             const struct eui64 *dst,
                                             uint16_t tag, uint16_t len)
{
    struct lowpan_reasm *reasm;

    TRACE(TR_IPV6, "6lowpan: reasm new  src=%s tag=0x%04x len=%u",
          tr_eui64(src->u8), tag, len);

    reasm = zalloc(sizeof(struct lowpan_reasm) + len);
    reasm->src = *src;
    reasm->dst = *dst;
    reasm->tag = tag;
    reasm->len = len;

    lowpan_hole_add(reasm, 0, len);

    reasm->timer.callback = lowpan_reasm_expire;
    timer_start_rel(&ctx->timer_group, &reasm->timer, ctx->reasm_timeout_ms);

    SLIST_INSERT_HEAD(&ctx->reasm_list, reasm, link);
    return reasm;
}

int lowpan_frag_recv(struct lowpan_frag_ctx *ctx,
                     struct pktbuf *pktbuf,
                     const struct eui64 *src,
                     const struct eui64 *dst)
{
    uint8_t src_iid[8], dst_iid[8];
    struct lowpan_reasm *reasm;
    uint8_t offset, dispatch;
    uint16_t tmp, tag, len;
    int ret;

    tmp = pktbuf_pop_head_be16(pktbuf);
    dispatch = tmp >> 8;
    len = FIELD_GET(LOWPAN_MASK_FRAG_DGRAM_SIZE, tmp);
    tag = pktbuf_pop_head_be16(pktbuf);
    if (LOWPAN_DISPATCH_IS_FRAG1(dispatch))
        offset = 0;
    else
        offset = pktbuf_pop_head_u8(pktbuf);

    if (pktbuf->err)
        return -EINVAL;

    reasm = lowpan_reasm_get(ctx, src, dst, tag, len);
    if (!reasm)
        reasm = lowpan_reasm_new(ctx, src, dst, tag, len);

    /*
     *   RFC 6292 2. Specific Updates to RFC 4944
     * When using the fragmentation mechanism described in Section 5.3 of
     * [RFC4944], any header that cannot fit within the first fragment MUST
     * NOT be compressed.
     */
    if (LOWPAN_DISPATCH_IS_FRAG1(dispatch)) {
        if (pktbuf_len(pktbuf) < 1)
            return -EINVAL;
        dispatch = pktbuf->buf[pktbuf->offset_head];
        if (!LOWPAN_DISPATCH_IS_IPHC(dispatch)) {
            TRACE(TR_DROP, "drop %-9s: unsupported dispatch=%02x after frag1",
                  "6lowpan", dispatch);
            pktbuf->err = true;
            return -ENOTSUP;
        }
        ipv6_addr_conv_iid_eui64(src_iid, src->u8);
        ipv6_addr_conv_iid_eui64(dst_iid, dst->u8);
        lowpan_iphc_decmpr(pktbuf, src_iid, dst_iid);
    }

    if (pktbuf->err)
        return -EINVAL;

    TRACE(TR_IPV6, "6lowpan: frag  recv src=%s tag=0x%04x len=[%4u,%4zu)/%u",
          tr_eui64(src->u8), tag, offset * 8, offset * 8 + pktbuf_len(pktbuf), len);

    ret = lowpan_reasm_update(reasm, pktbuf_head(pktbuf), pktbuf_len(pktbuf), offset);
    if (ret < 0) {
        TRACE(TR_DROP, "drop %-9s: invalid fragment", "6lowpan");
        pktbuf->err = true;
        return ret;
    }

    if (!SLIST_EMPTY(&reasm->holes))
        return -EAGAIN;

    TRACE(TR_IPV6, "6lowpan: reasm done");
    ret = lowpan_iphc_decmpr_finish(reasm->buf, reasm->len);
    pktbuf_init(pktbuf, reasm->buf, reasm->len);
    pktbuf->err = ret < 0;
    lowpan_reasm_del(ctx, reasm);
    return ret;
}

void lowpan_frag_init(struct lowpan_frag_ctx *ctx)
{
    BUG_ON(!ctx->reasm_timeout_ms);
    SLIST_INIT(&ctx->reasm_list);
    timer_group_init(&ctx->timer_group);
}
