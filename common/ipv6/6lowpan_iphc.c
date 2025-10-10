/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>

#include "common/specs/6lowpan.h"
#include "common/specs/ip.h"
#include "common/specs/ipv6.h"
#include "common/ipv6/ipv6_cksum.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/string_extra.h"
#include "common/iobuf.h"
#include "common/pktbuf.h"

#include "6lowpan_iphc.h"

// RFC 6282 - 3.2.1. Traffic Class and Flow Label Compression
static uint32_t lowpan_iphc_decmpr_vtcflow(struct pktbuf *pktbuf, uint16_t base)
{
    uint32_t flow = 0;
    uint8_t tclass = 0;
    uint8_t dscp = 0;
    uint8_t ecn = 0;
    uint32_t tmp;

    switch (FIELD_GET(LOWPAN_MASK_IPHC_TF, base)) {
    case LOWPAN_TF_ECN_DSCP_FLOW:
        // 00: ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
        tmp = pktbuf_pop_head_be32(pktbuf);
        ecn  = FIELD_GET(LOWPAN_MASK_IPHC_TF00_ECN,  tmp);
        dscp = FIELD_GET(LOWPAN_MASK_IPHC_TF00_DSCP, tmp);
        flow = FIELD_GET(LOWPAN_MASK_IPHC_TF00_FLOW, tmp);
        break;
    case LOWPAN_TF_ECN_FLOW:
        // 01: ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided.
        tmp = pktbuf_pop_head_be24(pktbuf);
        ecn  = FIELD_GET(LOWPAN_MASK_IPHC_TF01_ECN,  tmp);
        flow = FIELD_GET(LOWPAN_MASK_IPHC_TF01_FLOW, tmp);
        break;
    case LOWPAN_TF_ECN_DSCP:
        // 10: ECN + DSCP (1 byte), Flow Label is elided.
        tmp = pktbuf_pop_head_u8(pktbuf);
        ecn  = FIELD_GET(LOWPAN_MASK_IPHC_TF10_ECN,  tmp);
        dscp = FIELD_GET(LOWPAN_MASK_IPHC_TF10_DSCP, tmp);
        break;
    case LOWPAN_TF_NONE:
        // 11: Traffic Class and Flow Label are elided.
        break;
    }
    tclass = FIELD_PREP(IP_TCLASS_ECN_MASK,  ecn) |
             FIELD_PREP(IP_TCLASS_DSCP_MASK, dscp);
    return FIELD_PREP(IPV6_MASK_VERSION, 6)      |
           FIELD_PREP(IPV6_MASK_TCLASS,  tclass) |
           FIELD_PREP(IPV6_MASK_FLOW,    flow);
}

static uint8_t lowpan_iphc_decmpr_hlim(struct pktbuf *pktbuf, uint16_t base)
{
    switch (FIELD_GET(LOWPAN_MASK_IPHC_HLIM, base)) {
    case LOWPAN_HLIM_INLINE:
        return pktbuf_pop_head_u8(pktbuf);
    case LOWPAN_HLIM_1:
        return 1;
    case LOWPAN_HLIM_64:
        return 64;
    case LOWPAN_HLIM_255:
        return 255;
    default:
        BUG();
    }
}

static void lowpan_iphc_decmpr_addr_stless(struct pktbuf *pktbuf, struct in6_addr *addr,
                                           uint8_t mode, const uint8_t iid[8])
{
    switch (mode) {
    case LOWPAN_AM_INLINE:
        // 00: 128 bits. The full address is carried in-line.
        pktbuf_pop_head(pktbuf, addr->s6_addr, 16);
        break;
    case LOWPAN_AM_IID64:
        // 01: 64 bits. The first 64-bits of the address are elided. The
        // value of those bits is the link-local prefix padded with zeros.
        // The remaining 64 bits are carried in-line.
        memcpy(addr->s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 8, 8);
        break;
    case LOWPAN_AM_IID16:
        // 10: 16 bits. The first 112 bits of the address are elided. The
        // value of the first 64 bits is the link-local prefix padded with
        // zeros. The following 64 bits are 0000:00ff:fe00:XXXX, where XXXX
        // are the 16 bits carried in-line.
        memcpy(addr->s6_addr,     ipv6_prefix_linklocal.s6_addr, 8);
        memcpy(addr->s6_addr + 8, (uint8_t[6]){ 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00 }, 6);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 14, 2);
        break;
    case LOWPAN_AM_NONE:
        // 11: 0 bits. The address is fully elided.  The first 64 bits of the
        // address are the link-local prefix padded with zeros. The remaining
        // 64 bits are computed from the encapsulating header (e.g., 802.15.4
        // or IPv6 source address)
        memcpy(addr->s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
        memcpy(addr->s6_addr + 8, iid, 8);
        break;
    }
}

// RFC 6282 - 3.2.3. Stateless Multicast Address Compression
static void lowpan_iphc_decmpr_maddr_stless(struct pktbuf *pktbuf, struct in6_addr *addr, uint8_t mode)
{
    switch (mode) {
    case LOWPAN_MAM_INLINE:
        // 00: 128 bits. The full address is carried in-line.
        pktbuf_pop_head(pktbuf, addr->s6_addr, 16);
        break;
    case LOWPAN_MAM_FS_G40:
        // 01: 48 bits. The address takes the form ffXX::00XX:XXXX:XXXX.
        addr->s6_addr[0] = 0xff;
        pktbuf_pop_head(pktbuf, addr->s6_addr + 1, 1);
        memset(addr->s6_addr + 2, 0, 9);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 11, 5);
        break;
    case LOWPAN_MAM_FS_G28:
        // 10: 32 bits. The address takes the form ffXX::00XX:XXXX.
        addr->s6_addr[0] = 0xff;
        pktbuf_pop_head(pktbuf, addr->s6_addr + 1, 1);
        memset(addr->s6_addr + 2, 0, 11);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 13, 3);
        break;
    case LOWPAN_MAM_G8:
        // 11: 8 bits. The address takes the form ff02::00XX.
        addr->s6_addr[0]  = 0xff;
        addr->s6_addr[1]  = 0x02;
        memset(addr->s6_addr + 2, 0, 13);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 15, 1);
        break;
    }
}

static void lowpan_iphc_decmpr_src(struct pktbuf *pktbuf, struct in6_addr *addr,
                                   uint16_t base, const uint8_t iid[8])
{
    const uint8_t mode = FIELD_GET(LOWPAN_MASK_IPHC_SAM, base);

    if (FIELD_GET(LOWPAN_MASK_IPHC_SAC, base)) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        pktbuf->err = true;
        return;
    }
    lowpan_iphc_decmpr_addr_stless(pktbuf, addr, mode, iid);
}

static void lowpan_iphc_decmpr_dst(struct pktbuf *pktbuf, struct in6_addr *addr,
                                   uint16_t base, const uint8_t iid[8])
{
    const uint8_t mode = FIELD_GET(LOWPAN_MASK_IPHC_DAM, base);

    if (FIELD_GET(LOWPAN_MASK_IPHC_DAC, base)) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        pktbuf->err = true;
        return;
    }
    if (FIELD_GET(LOWPAN_MASK_IPHC_M, base))
        lowpan_iphc_decmpr_maddr_stless(pktbuf, addr, mode);
    else
        lowpan_iphc_decmpr_addr_stless(pktbuf, addr, mode, iid);
}

static uint8_t lowpan_nhc_nxthdr(struct pktbuf *pktbuf)
{
    uint8_t nhc;

    if (pktbuf_len(pktbuf) < 1) {
        pktbuf->err = true;
        return 0;
    }
    nhc = pktbuf->buf[pktbuf->offset_head];
    if (LOWPAN_NHC_IS_EXTHDR(nhc)) {
        switch (FIELD_GET(LOWPAN_MASK_NHC_EXTHDR_EID, nhc)) {
        case LOWPAN_NHC_EID_HOPOPT:   return IPPROTO_HOPOPTS;
        case LOWPAN_NHC_EID_ROUTING:  return IPPROTO_ROUTING;
        case LOWPAN_NHC_EID_FRAG:     return IPPROTO_FRAGMENT;
        case LOWPAN_NHC_EID_DSTOPT:   return IPPROTO_DSTOPTS;
        case LOWPAN_NHC_EID_MOBILITY: return IPPROTO_MH;
        case LOWPAN_NHC_EID_IPV6:     return IPPROTO_IPV6;
        }
    } else if (LOWPAN_NHC_IS_UDP(nhc)) {
        return IPPROTO_UDP;
    }
    TRACE(TR_DROP, "drop %-9s: unsupported NHC 0x%02x", "6lowpan", nhc);
    pktbuf->err = true;
    return 0;
}

static void lowpan_nhc_decmpr(struct pktbuf *pktbuf, const struct in6_addr *src, const struct in6_addr *dst);

static void lowpan_nhc_decmpr_pad(struct pktbuf *pktbuf, uint8_t len)
{
    struct ip6_opt padn = {
        .ip6o_type = IP6OPT_PADN,
        .ip6o_len  = len - sizeof(struct ip6_opt),
    };

    if (len == 1) {
        pktbuf_push_head_u8(pktbuf, IP6OPT_PAD1);
    } else if (len > 1) {
        pktbuf_push_head(pktbuf, NULL, padn.ip6o_len);
        pktbuf_push_head(pktbuf, &padn, sizeof(struct ip6_opt));
    }
}

// RFC 6282 - 4.2. IPv6 Extension Header Compression
static void lowpan_nhc_decmpr_exthdr(struct pktbuf *pktbuf, uint8_t nhc,
                                     const struct in6_addr *src, const struct in6_addr *dst)
{
    struct ip6_ext hdr;
    uint8_t pad;
    void *buf;

    //   RFC 6282 - 4.2. IPv6 Extension Header Compression
    // When the identified next header is an IPv6 Header (EID=7), the NH bit of
    // the LOWPAN_NHC encoding is unused and MUST be set to zero. The following
    // bytes MUST be encoded using LOWPAN_IPHC.
    if (FIELD_GET(LOWPAN_MASK_NHC_EXTHDR_EID, nhc) == LOWPAN_NHC_EID_IPV6) {
        lowpan_iphc_decmpr(pktbuf, src->s6_addr + 8, dst->s6_addr + 8); // WARN: recursivity
        return;
    }

    if (!FIELD_GET(LOWPAN_MASK_NHC_EXTHDR_NH, nhc))
        hdr.ip6e_nxt = pktbuf_pop_head_u8(pktbuf);
    hdr.ip6e_len = pktbuf_pop_head_u8(pktbuf);
    buf = xalloc(hdr.ip6e_len);
    pktbuf_pop_head(pktbuf, buf, hdr.ip6e_len);

    if (FIELD_GET(LOWPAN_MASK_NHC_EXTHDR_NH, nhc)) {
        hdr.ip6e_nxt = lowpan_nhc_nxthdr(pktbuf);
        lowpan_nhc_decmpr(pktbuf, src, dst); // WARN: recursivity
    }

    //   RFC 6282 - 4.2. IPv6 Extension Header Compression
    // IPv6 Hop-by-Hop and Destination Options Headers may use a trailing Pad1
    // or PadN to achieve 8-octet alignment. When there is a single trailing
    // Pad1 or PadN option of 7 octets or less and the containing header is a
    // multiple of 8 octets, the trailing Pad1 or PadN option MAY be elided by
    // the compressor. A decompressor MUST ensure that the containing header is
    // padded out to a multiple of 8 octets in length, using a Pad1 or PadN
    // option if necessary.
    pad = 0;
    switch (FIELD_GET(LOWPAN_MASK_NHC_EXTHDR_EID, nhc)) {
    case LOWPAN_NHC_EID_HOPOPT:
    case LOWPAN_NHC_EID_DSTOPT:
        pad = (8 - ((2 + hdr.ip6e_len) % 8)) % 8;
        break;
    }
    if (pad)
        lowpan_nhc_decmpr_pad(pktbuf, pad);

    pktbuf_push_head(pktbuf, buf, hdr.ip6e_len);
    free(buf);
    hdr.ip6e_len = (2 + hdr.ip6e_len + pad) / 8 - 1;
    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));
}

// RFC 6282 - 4.3. UDP Header Compression
static void lowpan_nhc_decmpr_udp(struct pktbuf *pktbuf, uint8_t nhc,
                                  const struct in6_addr *src, const struct in6_addr *dst)
{
    struct udphdr hdr;
    uint8_t tmp;

    switch (FIELD_GET(LOWPAN_MASK_NHC_UDP_P, nhc)) {
    case LOWPAN_UDP_P_INLINE:
        // 00: All 16 bits for both Source Port and Destination Port are
        // carried in-line.
        pktbuf_pop_head(pktbuf, &hdr.uh_sport, sizeof(hdr.uh_sport));
        pktbuf_pop_head(pktbuf, &hdr.uh_dport, sizeof(hdr.uh_dport));
        break;
    case LOWPAN_UDP_P_S16_D8:
        // 01: All 16 bits for Source Port are carried in-line. First 8 bits of
        // Destination Port is 0xf0 and elided. The remaining 8 bits of
        // Destination Port are carried in-line.
        pktbuf_pop_head(pktbuf, &hdr.uh_sport, sizeof(hdr.uh_sport));
        hdr.uh_dport = htons((LOWPAN_UDP_PORT_PREFIX & 0xff00) |
                             pktbuf_pop_head_u8(pktbuf));
        break;
    case LOWPAN_UDP_P_S8_D16:
        // 10: First 8 bits of Source Port are 0xf0 and elided. The remaining 8
        // bits of Source Port are carried in-line. All 16 bits for Destination
        // Port are carried in-line.
        hdr.uh_sport = htons((LOWPAN_UDP_PORT_PREFIX & 0xff00) |
                             pktbuf_pop_head_u8(pktbuf));
        pktbuf_pop_head(pktbuf, &hdr.uh_dport, sizeof(hdr.uh_dport));
        break;
    case LOWPAN_UDP_P_S8_D8:
        // 11: First 12 bits of both Source Port and Destination Port are 0xf0b
        // and elided. The remaining 4 bits for each are carried in-line.
        tmp = pktbuf_pop_head_u8(pktbuf);
        hdr.uh_sport = htons((LOWPAN_UDP_PORT_PREFIX & 0xfff0) |
                             FIELD_GET(LOWPAN_MASK_NHC_UDP_P11_SRC, tmp));
        hdr.uh_dport = htons((LOWPAN_UDP_PORT_PREFIX & 0xfff0) |
                             FIELD_GET(LOWPAN_MASK_NHC_UDP_P11_DST, tmp));
        break;
    }

    if (!FIELD_GET(LOWPAN_MASK_NHC_UDP_C, nhc)) {
        pktbuf_pop_head(pktbuf, &hdr.uh_sum, sizeof(hdr.uh_sum));
        hdr.uh_ulen = 0;
    } else {
        // NOTE: filled by lowpan_iphc_decmpr_finish()
        hdr.uh_sum = 0;
        hdr.uh_ulen = UINT16_MAX;
    }

    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));
}

static void lowpan_nhc_decmpr(struct pktbuf *pktbuf, const struct in6_addr *src, const struct in6_addr *dst)
{
    uint8_t nhc;

    nhc = pktbuf_pop_head_u8(pktbuf);
    if (LOWPAN_NHC_IS_EXTHDR(nhc)) {
        lowpan_nhc_decmpr_exthdr(pktbuf, nhc, src, dst);
    } else if (LOWPAN_NHC_IS_UDP(nhc)) {
        lowpan_nhc_decmpr_udp(pktbuf, nhc, src, dst);
    } else {
        TRACE(TR_DROP, "drop %-9s: unsupported NHC 0x%02x", "6lowpan", nhc);
        pktbuf->err = true;
    }
}

int lowpan_iphc_decmpr(struct pktbuf *pktbuf,
                       const uint8_t src_iid[8],
                       const uint8_t dst_iid[8])
{
    struct ip6_hdr hdr;
    uint16_t base;

    base = pktbuf_pop_head_be16(pktbuf);
    if (FIELD_GET(LOWPAN_MASK_IPHC_CID, base)) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        pktbuf->err = true;
        return -ENOTSUP;
    }
    hdr.ip6_flow = htonl(lowpan_iphc_decmpr_vtcflow(pktbuf, base));
    if (!FIELD_GET(LOWPAN_MASK_IPHC_NH, base))
        hdr.ip6_nxt = pktbuf_pop_head_u8(pktbuf);
    hdr.ip6_hlim = lowpan_iphc_decmpr_hlim(pktbuf, base);
    lowpan_iphc_decmpr_src(pktbuf, &hdr.ip6_src, base, src_iid);
    lowpan_iphc_decmpr_dst(pktbuf, &hdr.ip6_dst, base, dst_iid);
    if (FIELD_GET(LOWPAN_MASK_IPHC_NH, base)) {
        hdr.ip6_nxt = lowpan_nhc_nxthdr(pktbuf);
        lowpan_nhc_decmpr(pktbuf, &hdr.ip6_src, &hdr.ip6_dst);
    }

    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));
    return pktbuf->err ? -EINVAL : 0;
}

int lowpan_iphc_decmpr_finish(void *buf, size_t buf_len)
{
    const struct ip6_ext *ext;
    uint8_t *buf_ptr = buf;
    struct ip6_hdr *hdr;
    struct udphdr *udp;
    bool do_cksum;
    uint8_t nxt;

    nxt = IPPROTO_IPV6;
    while (buf_len) {
        switch (nxt) {
        case IPPROTO_IPV6:
            if (buf_len < sizeof(struct ip6_hdr))
                return -EINVAL;
            hdr = (struct ip6_hdr *)buf_ptr;
            buf_ptr += sizeof(struct ip6_hdr);
            buf_len -= sizeof(struct ip6_hdr);
            hdr->ip6_plen = htons(buf_len);
            nxt = hdr->ip6_nxt;
            continue;
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_MH:
            ext = (struct ip6_ext *)buf_ptr;
            if (buf_len < sizeof(struct ip6_ext) || buf_len < (ext->ip6e_len + 1) * 8)
                return -EINVAL;
            buf_ptr += (ext->ip6e_len + 1) * 8;
            buf_len -= (ext->ip6e_len + 1) * 8;
            nxt = ext->ip6e_nxt;
            continue;
        case IPPROTO_UDP:
            if (buf_len < sizeof(struct udphdr))
                return -EINVAL;
            udp = (struct udphdr *)buf_ptr;
            do_cksum = udp->uh_ulen == UINT16_MAX; // See lowpan_iphc_decmpr_udp()
            udp->uh_ulen = htons(buf_len);
            if (do_cksum)
                udp->uh_sum = ipv6_cksum(&hdr->ip6_src, &hdr->ip6_dst, nxt, buf_ptr, buf_len);
            return 0;
        default:
            return 0;
        }
    }
    return 0;
}

/*
 * 6LoWPAN IPHC Compression Context: rbuf and wbuf use the same underlying
 * buffer. During compression, the read pointer always advances faster than
 * the write pointer.
 */
struct lowpan_cmpr_ctx {
    uint8_t src_iid[8];
    uint8_t dst_iid[8];
    struct iobuf_write wbuf;
    struct iobuf_read rbuf;
};

// RFC 6282 3.2.1. Traffic Class and Flow Label Compression
static uint8_t lowpan_iphc_calc_tf(uint32_t vtcflow)
{
    const uint8_t tclass = FIELD_GET(IPV6_MASK_TCLASS, vtcflow);
    const uint32_t flow = FIELD_GET(IPV6_MASK_FLOW, vtcflow);

    if (!flow && !tclass)
        return LOWPAN_TF_NONE;
    if (!flow)
        return LOWPAN_TF_ECN_DSCP;
    if (!FIELD_GET(IP_TCLASS_DSCP_MASK, tclass))
        return LOWPAN_TF_ECN_FLOW;
    else
        return LOWPAN_TF_ECN_DSCP_FLOW;
}

static void lowpan_iphc_cmpr_tf(struct lowpan_cmpr_ctx *cmpr, uint8_t tf, uint32_t vtcflow)
{
    const uint8_t tclass = FIELD_GET(IPV6_MASK_TCLASS, vtcflow);
    const uint32_t flow = FIELD_GET(IPV6_MASK_FLOW, vtcflow);
    const uint8_t dscp = FIELD_GET(IP_TCLASS_DSCP_MASK, tclass);
    const uint8_t ecn = FIELD_GET(IP_TCLASS_ECN_MASK, tclass);

    switch (tf) {
    case LOWPAN_TF_ECN_DSCP_FLOW:
        iobuf_push_be32(&cmpr->wbuf,
                        FIELD_PREP(LOWPAN_MASK_IPHC_TF00_ECN, ecn) |
                        FIELD_PREP(LOWPAN_MASK_IPHC_TF00_DSCP, dscp) |
                        FIELD_PREP(LOWPAN_MASK_IPHC_TF00_FLOW, flow));
        break;
    case LOWPAN_TF_ECN_FLOW:
        iobuf_push_be24(&cmpr->wbuf,
                        FIELD_PREP(LOWPAN_MASK_IPHC_TF01_ECN, ecn) |
                        FIELD_PREP(LOWPAN_MASK_IPHC_TF01_FLOW, flow));
        break;
    case LOWPAN_TF_ECN_DSCP:
        iobuf_push_u8(&cmpr->wbuf,
                      FIELD_PREP(LOWPAN_MASK_IPHC_TF10_ECN, ecn) |
                      FIELD_PREP(LOWPAN_MASK_IPHC_TF10_DSCP, dscp));
        break;
    }
}

// RFC 6282 3.1.1. Base Format
static uint8_t lowpan_iphc_calc_hlim(uint8_t hlim)
{
    switch (hlim) {
    case 1:
        return LOWPAN_HLIM_1;
    case 64:
        return LOWPAN_HLIM_64;
    case 255:
        return LOWPAN_HLIM_255;
    default:
        return LOWPAN_HLIM_INLINE;
    }
}

// RFC 6282 3.1.1. Base Format
static uint8_t lowpan_iphc_calc_am(const struct in6_addr *addr,
                                   const uint8_t iid[8])
{
    if (memcmp(addr, &ipv6_prefix_linklocal, 8))
        return LOWPAN_AM_INLINE;
    if (!memcmp(addr->s6_addr + 8, iid, 8))
        return LOWPAN_AM_NONE;
    if (!memcmp(addr->s6_addr + 8, (uint8_t[6]){ 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00 }, 6))
        return LOWPAN_AM_IID16;
    else
        return LOWPAN_AM_IID64;
}

static void lowpan_iphc_cmpr_addr(struct lowpan_cmpr_ctx *cmpr, uint8_t am,
                                     const struct in6_addr *addr)
{
    switch (am) {
    case LOWPAN_AM_INLINE:
        iobuf_push_data(&cmpr->wbuf, addr, 16);
        break;
    case LOWPAN_AM_IID16:
        iobuf_push_data(&cmpr->wbuf, addr->s6_addr + 14, 2);
        break;
    case LOWPAN_AM_IID64:
        iobuf_push_data(&cmpr->wbuf, addr->s6_addr + 8, 8);
        break;
    }
}

// RFC 6282 3.2.3. Stateless Multicast Address Compression
static uint8_t lowpan_iphc_calc_mam(const struct in6_addr *addr)
{
    if (memzcmp(addr->s6_addr + 2, 9))
        return LOWPAN_MAM_INLINE;
    if (memzcmp(addr->s6_addr + 9, 2))
        return LOWPAN_MAM_FS_G40;
    if (addr->s6_addr[1] != 0x02 || memzcmp(addr->s6_addr + 11, 2))
        return LOWPAN_MAM_FS_G28;
    else
        return LOWPAN_MAM_G8;
}

static void lowpan_iphc_cmpr_maddr(struct lowpan_cmpr_ctx *cmpr, uint8_t mam,
                                   const struct in6_addr *addr)
{
    switch (mam) {
    case LOWPAN_MAM_INLINE:
        iobuf_push_data(&cmpr->wbuf, addr, 16);
        break;
    case LOWPAN_MAM_FS_G40:
        iobuf_push_u8(&cmpr->wbuf, addr->s6_addr[1]);
        iobuf_push_data(&cmpr->wbuf, addr->s6_addr + 11, 5);
        break;
    case LOWPAN_MAM_FS_G28:
        iobuf_push_u8(&cmpr->wbuf, addr->s6_addr[1]);
        iobuf_push_data(&cmpr->wbuf, addr->s6_addr + 13, 3);
        break;
    case LOWPAN_MAM_G8:
        iobuf_push_u8(&cmpr->wbuf, addr->s6_addr[15]);
        break;
    }
}

// RFC 6282 3.1. LOWPAN_IPHC Encoding Format
static int __lowpan_iphc_cmpr(struct lowpan_cmpr_ctx *cmpr)
{
    struct ip6_hdr hdr;
    uint16_t iphc;

    iobuf_pop_data(&cmpr->rbuf, &hdr, sizeof(struct ip6_hdr));
    if (cmpr->rbuf.err)
        return -EINVAL;
    cmpr->wbuf.data_size += sizeof(struct ip6_hdr);
    if (FIELD_GET(IPV6_MASK_VERSION, ntohl(hdr.ip6_flow)) != 6)
        return -EINVAL;
    if (iobuf_remaining_size(&cmpr->rbuf) < ntohs(hdr.ip6_plen))
        return -EINVAL;
    // Clamp buffer length in case there are garbage trailing bytes
    cmpr->rbuf.data_size = cmpr->rbuf.cnt + ntohs(hdr.ip6_plen);

    iphc = LOWPAN_DISPATCH_IPHC << 8;
    iphc |= FIELD_PREP(LOWPAN_MASK_IPHC_TF, lowpan_iphc_calc_tf(ntohl(hdr.ip6_flow)));
    iphc |= FIELD_PREP(LOWPAN_MASK_IPHC_HLIM, lowpan_iphc_calc_hlim(hdr.ip6_hlim));
    iphc |= FIELD_PREP(LOWPAN_MASK_IPHC_SAM, lowpan_iphc_calc_am(&hdr.ip6_src, cmpr->src_iid));
    if (IN6_IS_ADDR_MULTICAST(&hdr.ip6_dst)) {
        iphc |= LOWPAN_MASK_IPHC_M;
        iphc |= FIELD_PREP(LOWPAN_MASK_IPHC_DAM, lowpan_iphc_calc_mam(&hdr.ip6_dst));
    } else {
        iphc |= FIELD_PREP(LOWPAN_MASK_IPHC_DAM, lowpan_iphc_calc_am(&hdr.ip6_dst, cmpr->dst_iid));
    }
    iobuf_push_be16(&cmpr->wbuf, iphc);

    lowpan_iphc_cmpr_tf(cmpr, FIELD_GET(LOWPAN_MASK_IPHC_TF, iphc), ntohl(hdr.ip6_flow));

    // TODO: Next Header Compression

    if (FIELD_GET(LOWPAN_MASK_IPHC_HLIM, iphc) == LOWPAN_HLIM_INLINE)
        iobuf_push_u8(&cmpr->wbuf, hdr.ip6_hlim);

    lowpan_iphc_cmpr_addr(cmpr, FIELD_GET(LOWPAN_MASK_IPHC_SAM, iphc), &hdr.ip6_src);

    if (iphc & LOWPAN_MASK_IPHC_M)
        lowpan_iphc_cmpr_maddr(cmpr, FIELD_GET(LOWPAN_MASK_IPHC_DAM, iphc), &hdr.ip6_dst);
    else
        lowpan_iphc_cmpr_addr(cmpr, FIELD_GET(LOWPAN_MASK_IPHC_DAM, iphc), &hdr.ip6_dst);

    return 0;
}

ssize_t lowpan_iphc_cmpr(void *buf, size_t buf_len,
                         const uint8_t src_iid[8],
                         const uint8_t dst_iid[8])
{
    struct lowpan_cmpr_ctx cmpr = {
        .rbuf.data      = buf,
        .rbuf.data_size = buf_len,
        .wbuf.data      = buf,
        .wbuf.data_size = 0,
        .wbuf.no_realloc = true,
    };
    const void *data;
    int data_len;
    int ret;

    memcpy(cmpr.src_iid, src_iid, 8);
    memcpy(cmpr.dst_iid, dst_iid, 8);

    ret = __lowpan_iphc_cmpr(&cmpr);
    if (ret < 0)
        return ret;

    data_len = iobuf_remaining_size(&cmpr.rbuf);
    data = iobuf_pop_data_ptr(&cmpr.rbuf, data_len);
    cmpr.wbuf.data_size += data_len;
    iobuf_push_data(&cmpr.wbuf, data, data_len);
    return cmpr.wbuf.len;
}
