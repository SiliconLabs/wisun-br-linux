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
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/queue.h>
#include <errno.h>

#include "common/specs/ipv6.h"
#include "common/specs/mpl.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/seqno.h"
#include "common/sys_queue_extra.h"
#include "common/trickle.h"
#include "common/timer.h"

#include "mpl.h"

// Declare struct mpl_msg_set
SLIST_HEAD(mpl_msg_set, mpl_msg);

// RFC 7731 7.3. Seed Set
struct mpl_seed {
    SLIST_ENTRY(mpl_seed) link;
    uint8_t s;
    uint8_t id[16];
    uint8_t min_seq;
    struct mpl_msg_set msg_set; // Sorted by seq
    struct timer_entry lifetime;
};

// RFC 7731 7.4. Buffered Message Set
struct mpl_msg {
    SLIST_ENTRY(mpl_msg) link;
    struct trickle tkl;
    uint8_t tkl_e;
    int tx_handle;
    uint16_t opt_offset;
    union {
        struct ip6_hdr hdr[0];
        uint8_t buf[0];
    };
};

static const uint8_t mpl_seed_id_len[4] = {
    [MPL_S_SRC] = 16,
    [MPL_S_16]  =  2,
    [MPL_S_64]  =  8,
    [MPL_S_128] = 16,
};

static inline struct mpl_opt *mpl_msg_opt(struct mpl_msg *msg)
{
    return (struct mpl_opt *)(msg->buf + msg->opt_offset);
}

static inline uint16_t mpl_msg_seq(struct mpl_msg *msg)
{
    const struct mpl_opt *opt = mpl_msg_opt(msg);

    return opt->seq;
}

static const char *tr_seed_id(uint8_t s, const uint8_t *id)
{
    if (s == MPL_S_SRC)
        return tr_ipv6(id);
    else
        return tr_bytes(id, mpl_seed_id_len[s], NULL, 3 * 16, 0);
}

static const char *tr_msg_seed_id(struct mpl_msg *msg)
{
    const struct mpl_opt *opt = mpl_msg_opt(msg);
    uint8_t s = FIELD_GET(MPL_MASK_S, opt->flags);

    return tr_seed_id(s, s == MPL_S_SRC ? msg->hdr->ip6_src.s6_addr : opt->seed_id);
}

static void mpl_msg_del(struct mpl_ctx *mpl, struct mpl_seed *seed, struct mpl_msg *msg);
static void mpl_seed_expire(struct timer_group *group, struct timer_entry *timer)
{
    struct mpl_seed *seed = container_of(timer, struct mpl_seed, lifetime);
    struct mpl_ctx *mpl = container_of(group, struct mpl_ctx, timer_group);
    struct mpl_msg *msg;

    TRACE(TR_MPL, "mpl: seed del id=%s", tr_seed_id(seed->s, seed->id));
    while ((msg = SLIST_FIRST(&seed->msg_set)))
        mpl_msg_del(mpl, seed, msg);
    SLIST_REMOVE(&mpl->seed_set, seed, mpl_seed, link);
    free(seed);
}

static void mpl_seed_update_seq(struct mpl_ctx *mpl, struct mpl_seed *seed, uint8_t seq)
{
    struct mpl_msg *msg;

    /*
     * When increasing MinSequence for an MPL Seed, the MPL Forwarder MUST
     * delete any MPL Data Messages from the corresponding Buffered Message
     * Set that have sequence numbers less than MinSequence.
     */
    TRACE(TR_MPL, "mpl: seed set id=%s min-seq=%u",
          tr_seed_id(seed->s, seed->id), seq);
    WARN_ON(seqno_cmp8(seq, seed->min_seq) < 0);
    seed->min_seq = seq;
    while ((msg = SLIST_FIRST(&seed->msg_set))) {
        if (seqno_cmp8(mpl_msg_seq(msg), seq) >= 0)
            break;
        mpl_msg_del(mpl, seed, msg);
    }
}

static struct mpl_seed *mpl_seed_new(struct mpl_ctx *mpl,
                                     const struct in6_addr *src,
                                     const struct mpl_opt *opt)
{
    struct mpl_seed *seed = zalloc(sizeof(struct mpl_seed));
    const uint8_t *seed_id;

    seed->s = FIELD_GET(MPL_MASK_S, opt->flags);
    seed_id = seed->s == MPL_S_SRC ? src->s6_addr : opt->seed_id;
    memcpy(seed->id, seed_id, mpl_seed_id_len[seed->s]);
    seed->min_seq = opt->seq;
    seed->lifetime.callback = mpl_seed_expire;
    SLIST_INIT(&seed->msg_set);
    SLIST_INSERT_HEAD(&mpl->seed_set, seed, link);
    TRACE(TR_MPL, "mpl: seed new id=%s min-seq=%u",
          tr_seed_id(seed->s, seed->id), seed->min_seq);
    return seed;
}

static struct mpl_seed *mpl_seed_get(struct mpl_ctx *mpl,
                                     const struct in6_addr *src,
                                     const struct mpl_opt *opt)
{
    const uint8_t *seed_id;
    struct mpl_seed *seed;
    uint8_t s;

    s = FIELD_GET(MPL_MASK_S, opt->flags);
    seed_id = s == MPL_S_SRC ? src->s6_addr : opt->seed_id;
    return SLIST_FIND(seed, &mpl->seed_set, link,
                      seed->s == s && !memcmp(seed->id, seed_id, mpl_seed_id_len[s]));
}

static void mpl_msg_transmit(struct trickle *tkl, struct timer_group *group)
{
    struct mpl_ctx *mpl = container_of(group, struct mpl_ctx, timer_group);
    struct mpl_msg *msg = container_of(tkl, struct mpl_msg, tkl);

    if (!msg->hdr->ip6_hlim)
        return;

    if (msg->tx_handle >= 0) {
        TRACE(TR_TX_ABORT, "tx-abort: mpl msg id=%s seq=%u already queued",
              tr_msg_seed_id(msg), mpl_msg_seq(msg));
    } else {
        TRACE(TR_MPL, "mpl: msg tx  id=%s seq=%u", tr_msg_seed_id(msg), mpl_msg_seq(msg));
        msg->tx_handle = mpl->send(mpl, msg->buf,
                                    sizeof(struct ip6_hdr) + ntohs(msg->hdr->ip6_plen));
    }
}

void mpl_msg_confirm(struct mpl_ctx *mpl, int handle)
{
    const struct mpl_seed *seed;
    struct mpl_msg *msg = NULL;

    SLIST_FOREACH(seed, &mpl->seed_set, link)
        SLIST_FOREACH(msg, &seed->msg_set, link)
            if (msg->tx_handle == handle)
                break;
    if (msg)
        msg->tx_handle = -1;
}

static void mpl_msg_expire(struct trickle *tkl, struct timer_group *group)
{
    struct mpl_ctx *mpl = container_of(group, struct mpl_ctx, timer_group);
    struct mpl_msg *msg = container_of(tkl, struct mpl_msg, tkl);
    struct mpl_opt *opt = mpl_msg_opt(msg);
    struct mpl_seed *seed;

    msg->tkl_e++;
    TRACE(TR_MPL, "mpl: msg e=%u id=%s seq=%u",
          msg->tkl_e, tr_msg_seed_id(msg), opt->seq);

    /*
     * After DATA_MESSAGE_TIMER_EXPIRATIONS Trickle timer events, the MPL
     * Forwarder MUST disable the Trickle timer.
     */
    if (msg->tkl_e < mpl->tkl_data_e_max)
        return;

    /*
     * When a buffered MPL Data Message does not have an associated Trickle
     * timer, the MPL Forwarder MAY delete the message from the Buffered
     * Message Set by advancing the MinSequence value of the corresponding MPL
     * Seed in the Seed Set.
     */
    seed = mpl_seed_get(mpl, &msg->hdr->ip6_src, opt);
    mpl_seed_update_seq(mpl, seed, opt->seq + 1);
}

static struct mpl_msg *mpl_msg_new(struct mpl_ctx *mpl,
                                   struct mpl_seed *seed,
                                   const struct ip6_hdr *hdr,
                                   const struct mpl_opt *opt)
{
    const size_t len = sizeof(struct ip6_hdr) + ntohs(hdr->ip6_plen);
    struct mpl_msg *msg = zalloc(sizeof(struct mpl_msg) + len);
    struct mpl_msg *prev, *it;
    struct mpl_opt *msg_opt;

    strcpy(msg->tkl.debug_name, "mpl");
    msg->tkl.cfg = &mpl->tkl_data_cfg;
    msg->tkl.on_transmit      = mpl_msg_transmit;
    msg->tkl.on_interval_done = mpl_msg_expire;
    trickle_init(&msg->tkl);
    trickle_start(&msg->tkl, &mpl->timer_group);
    msg->tx_handle = -1;

    memcpy(msg->buf, hdr, len);
    msg->opt_offset = (uintptr_t)opt - (uintptr_t)hdr;
    msg_opt = mpl_msg_opt(msg);

    prev = NULL;
    SLIST_FOREACH(it, &seed->msg_set, link) {
        if (seqno_cmp8(msg_opt->seq, mpl_msg_seq(it)) <= 0)
            break;
        prev = it;
    }
    if (prev)
        SLIST_INSERT_AFTER(prev, msg, link);
    else
        SLIST_INSERT_HEAD(&seed->msg_set, msg, link);

    /*
     *   RFC 7731 9.2. MPL Data Message Transmission
     * This document defines an "inconsistent" transmission as receiving an MPL
     * Data Message that has the same MPL Domain Address, seed-id value, and
     * the M flag set, but has a sequence value less than that of the MPL Data
     * Message managed by the Trickle timer.
     */
    if (msg_opt->flags & MPL_MASK_M) {
        for (it = SLIST_NEXT(msg, link); it; it = SLIST_NEXT(it, link)) {
            trickle_inconsistent(&it->tkl, &mpl->timer_group);
            it->tkl_e = 0;
        }
    }

    /*
     *   RFC 7731 9.2. MPL Data Message Transmission
     * When transmitting an MPL Data Message, the MPL Forwarder MUST either
     * set the M flag to zero or set it to a level that indicates whether or
     * not the message's sequence number is the largest value that has been
     * received from the MPL Seed.
     */
    if (SLIST_NEXT(msg, link)) {
        msg_opt->flags &= ~MPL_MASK_M;
    } else {
        msg_opt->flags |= MPL_MASK_M;
        if (prev)
            mpl_msg_opt(prev)->flags &= ~MPL_MASK_M;
    }

    /*
     *   RFC 8200 3. IPv6 Header Format
     * Decremented by 1 by each node that forwards the packet. When forwarding,
     * the packet is discarded if Hop Limit was zero when received or is
     * decremented to zero. A node that is the destination of a packet should
     * not discard a packet with Hop Limit equal to zero; it should process the
     * packet normally.
     *
     * NOTE: Keep packets with 0 hop limit in the Buffered Message Set for
     * upper layer de-duplication, mpl_msg_transmit() will not forward them.
     */
    if (msg->hdr->ip6_hlim)
        msg->hdr->ip6_hlim--;

    TRACE(TR_MPL, "mpl: msg new id=%s seq=%u",
          tr_msg_seed_id(msg), msg_opt->seq);
    return msg;
}

static struct mpl_msg *mpl_msg_get(struct mpl_seed *seed, uint8_t seq)
{
    struct mpl_msg *msg;

    return SLIST_FIND(msg, &seed->msg_set, link, mpl_msg_seq(msg) == seq);
}

static void mpl_msg_del(struct mpl_ctx *mpl, struct mpl_seed *seed, struct mpl_msg *msg)
{
    TRACE(TR_MPL, "mpl: msg del id=%s seq=%u", tr_msg_seed_id(msg), mpl_msg_seq(msg));
    SLIST_REMOVE(&seed->msg_set, msg, mpl_msg, link);
    trickle_stop(&msg->tkl, &mpl->timer_group);
    free(msg);
}

// RFC 7731 9.1. MPL Data Message Generation
int mpl_msg_gen(struct mpl_ctx *mpl,
                const struct in6_addr *src,
                struct pktbuf *pktbuf)
{
    struct mpl_tunhdr *tunhdr;
    struct mpl_seed *seed;
    struct mpl_msg *msg;

    tunhdr = pktbuf_push_head(pktbuf, NULL, sizeof(struct mpl_tunhdr));
    tunhdr->hdr.ip6_flow = htonl(FIELD_PREP(IPV6_MASK_VERSION, 6));
    tunhdr->hdr.ip6_plen = htons(sizeof(struct mpl_tunhdr) - sizeof(struct ip6_hdr) + pktbuf_len(pktbuf));
    tunhdr->hdr.ip6_nxt  = IPPROTO_HOPOPTS;
    tunhdr->hdr.ip6_hlim = 24; // Arbitrary
    tunhdr->hdr.ip6_src  = *src;
    tunhdr->hdr.ip6_dst  = ipv6_addr_all_mpl_fwd_realm;
    tunhdr->hbh.hdr.ip6h_nxt = IPPROTO_IPV6;
    tunhdr->hbh.hdr.ip6h_len = sizeof(tunhdr->hbh) / 8 - 1;
    tunhdr->hbh.opt_mpl.hdr.ip6o_type = IPV6_OPTION_MPL;
    tunhdr->hbh.opt_mpl.hdr.ip6o_len  = sizeof(struct mpl_opt);
    tunhdr->hbh.opt_mpl.data.flags    = FIELD_PREP(MPL_MASK_S, MPL_S_SRC);
    tunhdr->hbh.opt_pad.hdr.ip6o_type = IP6OPT_PADN;
    tunhdr->hbh.opt_pad.hdr.ip6o_len  = 0;

    seed = mpl_seed_get(mpl, src, &tunhdr->hbh.opt_mpl.data);
    if (!seed)
        seed = mpl_seed_new(mpl, src, &tunhdr->hbh.opt_mpl.data);

    if (SLIST_EMPTY(&seed->msg_set)) {
        tunhdr->hbh.opt_mpl.data.seq = seed->min_seq;
    } else {
        // Get highest seq
        SLIST_FOREACH(msg, &seed->msg_set, link)
            tunhdr->hbh.opt_mpl.data.seq = mpl_msg_seq(msg);
        tunhdr->hbh.opt_mpl.data.seq++;
        if (seqno_cmp8(tunhdr->hbh.opt_mpl.data.seq, seed->min_seq) < 0) {
            TRACE(TR_TX_ABORT, "tx-abort %-9s: too many packets queued", "mpl");
            return -EBUSY;
        }
    }

    mpl_msg_new(mpl, seed, &tunhdr->hdr, &tunhdr->hbh.opt_mpl.data);
    return 0;
}

// RFC 7731 9.3. MPL Data Message Processing
int mpl_opt_process(struct mpl_ctx *mpl,
                    const struct ip6_hdr *hdr,
                    const struct ip6_opt *ipopt)
{
    struct mpl_seed *seed;
    struct mpl_msg *msg;
    struct mpl_opt *opt;
    uint8_t s;

    if (!IN6_ARE_ADDR_EQUAL(&hdr->ip6_dst, &ipv6_addr_all_mpl_fwd_realm)) {
        TRACE(TR_DROP, "drop %-9s: unsupported domain=%s",
              "mpl", tr_ipv6(hdr->ip6_dst.s6_addr));
        return -ENOTSUP;
    }
    if (ipopt->ip6o_len < sizeof(struct mpl_opt))
        return -EINVAL;
    opt = (struct mpl_opt *)(ipopt + 1);

    if (opt->flags & MPL_MASK_V)
        return -ENOTSUP;
    s = FIELD_GET(MPL_MASK_S, opt->flags);
    if (s != MPL_S_SRC && ipopt->ip6o_len < sizeof(struct mpl_opt) + mpl_seed_id_len[s])
        return -EINVAL;

    /*
     * If a Seed Set entry exists for the MPL Seed, the MPL Forwarder MUST
     * discard the MPL Data Message if its sequence number is less than
     * MinSequence or exists in the Buffered Message Set.
     */
    seed = mpl_seed_get(mpl, &hdr->ip6_src, opt);
    if (seed) {
        if (seqno_cmp8(opt->seq, seed->min_seq) < 0) {
            TRACE(TR_DROP, "drop %-9s: id=%s seq=%u < min-seq=%u", "mpl",
                  tr_seed_id(seed->s, seed->id), opt->seq, seed->min_seq);
            return -ETIMEDOUT;
        }
        msg = mpl_msg_get(seed, opt->seq);
        if (msg) {
            /*
             *   RFC 7731 10.2. MPL Control Message Transmission
             * This document defines a "consistent" transmission as receiving
             * an MPL Data Message that has the same MPL Domain Address,
             * seed-id, and sequence value as the MPL Data Message managed by
             * the Trickle timer.
             */
            trickle_consistent(&msg->tkl);
            if (msg->tkl.c >= msg->tkl.cfg->k && msg->tx_handle >= 0)
                mpl->abort(mpl, msg->tx_handle);
            TRACE(TR_DROP, "drop %-9s: id=%s seq=%u retransmission",
                  "mpl", tr_seed_id(seed->s, seed->id), opt->seq);
            return -EEXIST;
        }
    }

    /*
     * If a Seed Set entry does not exist for the MPL Seed, the MPL Forwarder
     * MUST create a new entry for the MPL Seed before accepting the MPL Data
     * Message.
     */
    if (!seed)
        seed = mpl_seed_new(mpl, &hdr->ip6_src, opt);

    /*
     * If the MPL Forwarder accepts the MPL Data Message, the MPL Forwarder
     * MUST perform the following actions:
     *  - Reset the Lifetime of the corresponding Seed Set entry to
     *    SEED_SET_ENTRY_LIFETIME.
     */
    timer_start_rel(&mpl->timer_group, &seed->lifetime, mpl->seed_lifetime_ms);

    mpl_msg_new(mpl, seed, hdr, opt);
    return 0;
}

void mpl_init(struct mpl_ctx *mpl)
{
    BUG_ON(!mpl->seed_lifetime_ms);
    BUG_ON(mpl->tkl_data_cfg.Imin_ms > mpl->tkl_data_cfg.Imax_ms);
    BUG_ON(!mpl->tkl_data_e_max);
    BUG_ON(!mpl->send);

    timer_group_init(&mpl->timer_group);
    SLIST_INIT(&mpl->seed_set);
}
