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
#include <string.h>

#include "common/specs/6lowpan.h"
#include "common/specs/ip.h"
#include "common/specs/ipv6.h"
#include "common/bits.h"
#include "common/ipv6_cksum.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/string_extra.h"
#include "common/pktbuf.h"
#include "app_wsrd/ipv6/ipv6_addr.h"

#include "6lowpan_iphc.h"

// RFC 6282 - 3.2.1. Traffic Class and Flow Label Compression
static uint32_t lowpan_iphc_decmpr_vtcflow(struct pktbuf *pktbuf, uint16_t base)
{
    uint32_t flow, tmp;
    uint8_t tclass = 0;
    uint8_t dscp = 0;
    uint8_t ecn;

    switch (FIELD_GET(LOWPAN_MASK_IPHC_TF, base)) {
    case 0b00:
        // 00: ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
        tmp = pktbuf_pop_head_be32(pktbuf);
        ecn  = FIELD_GET(LOWPAN_MASK_IPHC_TF00_ECN,  tmp);
        dscp = FIELD_GET(LOWPAN_MASK_IPHC_TF00_DSCN, tmp);
        flow = FIELD_GET(LOWPAN_MASK_IPHC_TF00_FLOW, tmp);
        break;
    case 0b01:
        // 01: ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided.
        tmp = pktbuf_pop_head_be24(pktbuf);
        ecn  = FIELD_GET(LOWPAN_MASK_IPHC_TF01_ECN,  tmp);
        flow = FIELD_GET(LOWPAN_MASK_IPHC_TF01_FLOW, tmp);
        break;
    case 0b10:
        // 10: ECN + DSCP (1 byte), Flow Label is elided.
        tmp = pktbuf_pop_head_u8(pktbuf);
        ecn  = FIELD_GET(LOWPAN_MASK_IPHC_TF10_ECN,  tmp);
        dscp = FIELD_GET(LOWPAN_MASK_IPHC_TF10_DSCN, tmp);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported TF=0b11", "6lowpan");
        pktbuf->err = true;
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
    case 0b00:
        // 00: The Hop Limit field is carried in-line.
        return pktbuf_pop_head_u8(pktbuf);
    case 0b01:
        // 01: The Hop Limit field is compressed and the hop limit is 1.
        return 1;
    case 0b10:
        // 10: The Hop Limit field is compressed and the hop limit is 64.
        return 64;
    case 0b11:
        // 11: The Hop Limit field is compressed and the hop limit is 255.
        return 255;
    default:
        BUG();
    }
}

static void lowpan_iphc_decmpr_addr_stless(struct pktbuf *pktbuf, struct in6_addr *addr,
                                           uint8_t mode, const uint8_t iid[8])
{
    switch (mode) {
    case 0b00:
        // 00: 128 bits. The full address is carried in-line.
        pktbuf_pop_head(pktbuf, addr->s6_addr, 16);
        break;
    case 0b01:
        // 01: 64 bits. The first 64-bits of the address are elided. The
        // value of those bits is the link-local prefix padded with zeros.
        // The remaining 64 bits are carried in-line.
        memcpy(addr->s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 8, 8);
        break;
    case 0b10:
        // 10: 16 bits. The first 112 bits of the address are elided. The
        // value of the first 64 bits is the link-local prefix padded with
        // zeros. The following 64 bits are 0000:00ff:fe00:XXXX, where XXXX
        // are the 16 bits carried in-line.
        memcpy(addr->s6_addr,     ipv6_prefix_linklocal.s6_addr, 8);
        memcpy(addr->s6_addr + 8, (uint8_t[6]){ 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00 }, 6);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 14, 2);
        break;
    case 0b11:
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
    case 0b00:
        // 00: 128 bits. The full address is carried in-line.
        pktbuf_pop_head(pktbuf, addr->s6_addr, 16);
        break;
    case 0b01:
        // 01: 48 bits. The address takes the form ffXX::00XX:XXXX:XXXX.
        addr->s6_addr[0] = 0xff;
        pktbuf_pop_head(pktbuf, addr->s6_addr + 1, 1);
        memset(addr->s6_addr + 2, 0, 9);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 11, 5);
        break;
    case 0b10:
        // 10: 32 bits. The address takes the form ffXX::00XX:XXXX.
        addr->s6_addr[0] = 0xff;
        pktbuf_pop_head(pktbuf, addr->s6_addr + 1, 1);
        memset(addr->s6_addr + 2, 0, 11);
        pktbuf_pop_head(pktbuf, addr->s6_addr + 13, 3);
        break;
    case 0b11:
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
    if (pad) {
        TRACE(TR_DROP, "drop %s: unsupported unaligned options", "6lowpan");
        pktbuf->err = true;
    }

    // ipv6_opt_push_pad(pktbuf, pad);
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
    case 0b00:
        // 00: All 16 bits for both Source Port and Destination Port are
        // carried in-line.
        pktbuf_pop_head(pktbuf, &hdr.uh_sport, sizeof(hdr.uh_sport));
        pktbuf_pop_head(pktbuf, &hdr.uh_dport, sizeof(hdr.uh_dport));
        break;
    case 0b01:
        // 01: All 16 bits for Source Port are carried in-line. First 8 bits of
        // Destination Port is 0xf0 and elided. The remaining 8 bits of
        // Destination Port are carried in-line.
        pktbuf_pop_head(pktbuf, &hdr.uh_sport, sizeof(hdr.uh_sport));
        hdr.uh_dport = htons(0xf000 | pktbuf_pop_head_u8(pktbuf));
        break;
    case 0b10:
        // 10: First 8 bits of Source Port are 0xf0 and elided. The remaining 8
        // bits of Source Port are carried in-line. All 16 bits for Destination
        // Port are carried in-line.
        hdr.uh_sport = htons(0xf000 | pktbuf_pop_head_u8(pktbuf));
        pktbuf_pop_head(pktbuf, &hdr.uh_dport, sizeof(hdr.uh_dport));
        break;
    case 0b11:
        // 11: First 12 bits of both Source Port and Destination Port are 0xf0b
        // and elided. The remaining 4 bits for each are carried in-line.
        tmp = pktbuf_pop_head_u8(pktbuf);
        hdr.uh_sport = htons(0xf0b0 | FIELD_GET(LOWPAN_MASK_NHC_UDP_P11_SRC, tmp));
        hdr.uh_dport = htons(0xf0b0 | FIELD_GET(LOWPAN_MASK_NHC_UDP_P11_DST, tmp));
        break;
    }

    if (!FIELD_GET(LOWPAN_MASK_NHC_UDP_C, nhc))
        pktbuf_pop_head(pktbuf, &hdr.uh_sum, sizeof(hdr.uh_sum));
    else
        hdr.uh_sum = 0;

    hdr.uh_ulen = htons(pktbuf_len(pktbuf) + sizeof(hdr));
    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));

    if (FIELD_GET(LOWPAN_MASK_NHC_UDP_C, nhc) && !pktbuf->err) {
        hdr.uh_sum = ipv6_cksum(src, dst, IPPROTO_UDP, pktbuf_head(pktbuf), pktbuf_len(pktbuf));
        memcpy(pktbuf_head(pktbuf) + offsetof(struct udphdr, uh_sum),
               &hdr.uh_sum, sizeof(hdr.uh_sum));
    }
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

void lowpan_iphc_decmpr(struct pktbuf *pktbuf,
                        const uint8_t src_iid[8],
                        const uint8_t dst_iid[8])
{
    struct ip6_hdr hdr;
    uint16_t base;

    base = pktbuf_pop_head_be16(pktbuf);
    if (FIELD_GET(LOWPAN_MASK_IPHC_CID, base)) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        pktbuf->err = true;
        return;
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
    hdr.ip6_plen = htons(pktbuf_len(pktbuf));

    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));

    if (pktbuf->err) {
        TRACE(TR_DROP, "drop %-9s: unsupported or malformed packet", "6lowpan");
        return;
    }
}

// RFC 6282 - 3.2.1. Traffic Class and Flow Label Compression
static uint8_t lowpan_iphc_cmpr_vtcflow(struct pktbuf *pktbuf, uint32_t vtcflow)
{
    uint8_t ecn, dscp;
    uint8_t tclass;
    uint32_t flow;

    BUG_ON(FIELD_GET(IPV6_MASK_VERSION, vtcflow) != 6);

    tclass = FIELD_GET(IPV6_MASK_TCLASS, vtcflow);
    flow   = FIELD_GET(IPV6_MASK_FLOW,   vtcflow);
    ecn  = FIELD_GET(IP_TCLASS_ECN_MASK,  tclass);
    dscp = FIELD_GET(IP_TCLASS_DSCP_MASK, tclass);

    if (!flow) {
        // 10: ECN + DSCP (1 byte), Flow Label is elided.
        pktbuf_push_head_u8(pktbuf, FIELD_PREP(LOWPAN_MASK_IPHC_TF10_ECN,  ecn) |
                                    FIELD_PREP(LOWPAN_MASK_IPHC_TF10_DSCN, dscp));
        return 0b10;
    } else if (!dscp) {
        // 01: ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided.
        pktbuf_push_head_be24(pktbuf, FIELD_PREP(LOWPAN_MASK_IPHC_TF01_ECN,  ecn) |
                                      FIELD_PREP(LOWPAN_MASK_IPHC_TF01_FLOW, flow));
        return 0b01;
    } else {
        // 00: ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
        pktbuf_push_head_be24(pktbuf, FIELD_PREP(LOWPAN_MASK_IPHC_TF00_ECN,  ecn)  |
                                      FIELD_PREP(LOWPAN_MASK_IPHC_TF00_DSCN, dscp) |
                                      FIELD_PREP(LOWPAN_MASK_IPHC_TF00_FLOW, flow));
        return 0b00;
    }
}

static uint8_t lowpan_iphc_cmpr_hlim(struct pktbuf *pktbuf, uint8_t hlim)
{
    switch (hlim) {
    case 255:
        // 11: The Hop Limit field is compressed and the hop limit is 255.
        return 0b11;
    case 64:
        // 10: The Hop Limit field is compressed and the hop limit is 64.
        return 0b10;
    case 1:
        // 01: The Hop Limit field is compressed and the hop limit is 1.
        return 0b01;
    default:
        // 00: The Hop Limit field is carried in-line.
        pktbuf_push_head_u8(pktbuf, hlim);
        return 0b00;
    }
}

static uint8_t lowpan_iphc_cmpr_addr_stless(struct pktbuf *pktbuf,
                                            const struct in6_addr *addr,
                                            const uint8_t iid[8])
{
    if (memcmp(addr, ipv6_prefix_linklocal.s6_addr, 8)) {
        // 00: 128 bits. The full address is carried in-line.
        pktbuf_push_head(pktbuf, addr->s6_addr, 16);
        return 0b00;
    } else if (!memcmp(addr->s6_addr + 8, iid, 8)) {
        // 11:  0 bits.  The address is fully elided.  The first 64 bits of
        // the address are the link-local prefix padded with zeros. The
        // remaining 64 bits are computed from the encapsulating header
        // (e.g., 802.15.4 or IPv6 source address)
        return 0b11;
    } else if (!memcmp(addr->s6_addr + 8, (uint8_t[6]){ 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00 }, 6)) {
        // 10: 16 bits. The first 112 bits of the address are elided. The
        // value of the first 64 bits is the link-local prefix padded with
        // zeros. The following 64 bits are 0000:00ff:fe00:XXXX, where XXXX
        // are the 16 bits carried in-line.
        pktbuf_push_head(pktbuf, addr->s6_addr + 14, 2);
        return 0b10;
    } else {
        // 01: 64 bits. The first 64-bits of the address are elided. The
        // value of those bits is the link-local prefix padded with zeros.
        // The remaining 64 bits are carried in-line.
        pktbuf_push_head(pktbuf, addr->s6_addr + 8, 8);
        return 0b01;
    }
}

// RFC 6282 - 3.2.3. Stateless Multicast Address Compression
static uint8_t lowpan_iphc_cmpr_maddr_stless(struct pktbuf *pktbuf,
                                             const struct in6_addr *addr)
{
    BUG_ON(!IN6_IS_ADDR_MULTICAST(addr));
    if (memzcmp(addr->s6_addr + 2, 9)) {
        // 00: 128 bits. The full address is carried in-line.
        pktbuf_push_head(pktbuf, addr->s6_addr, 16);
        return 0x00;
    } else if (memzcmp(addr->s6_addr + 9, 2)) {
        // 01: 48 bits. The address takes the form ffXX::00XX:XXXX:XXXX.
        pktbuf_push_head_u8(pktbuf, addr->s6_addr[1]);
        pktbuf_push_head(pktbuf, addr->s6_addr + 11, 5);
        return 0x01;
    } else if (addr->s6_addr[1] != 0x02 || memzcmp(addr->s6_addr + 11, 2)) {
        // 10: 32 bits. The address takes the form ffXX::00XX:XXXX.
        pktbuf_push_head_u8(pktbuf, addr->s6_addr[1]);
        pktbuf_push_head(pktbuf, addr->s6_addr + 13, 3);
        return 0x02;
    } else {
        // 11: 8 bits. The address takes the form ff02::00XX.
        pktbuf_push_head_u8(pktbuf, addr->s6_addr[15]);
        return 0x03;
    }
}

void lowpan_iphc_cmpr(struct pktbuf *pktbuf,
                      const uint8_t src_iid[8],
                      const uint8_t dst_iid[8])
{
    uint16_t base = htons(LOWPAN_DISPATCH_IPHC);
    struct ip6_hdr hdr;
    uint8_t field;

    pktbuf_pop_head(pktbuf, &hdr, sizeof(hdr));
    BUG_ON(pktbuf->err);

    if (IN6_IS_ADDR_MULTICAST(&hdr.ip6_dst)) {
        field = lowpan_iphc_cmpr_maddr_stless(pktbuf, &hdr.ip6_dst);
        base |= LOWPAN_MASK_IPHC_M;
    } else {
        field = lowpan_iphc_cmpr_addr_stless(pktbuf, &hdr.ip6_dst, dst_iid);
    }
    base |= FIELD_PREP(LOWPAN_MASK_IPHC_DAM, field);

    field = lowpan_iphc_cmpr_addr_stless(pktbuf, &hdr.ip6_src, src_iid);
    base |= FIELD_PREP(LOWPAN_MASK_IPHC_SAM, field);

    field = lowpan_iphc_cmpr_hlim(pktbuf, hdr.ip6_hlim);
    base |= FIELD_PREP(LOWPAN_MASK_IPHC_HLIM, field);

    // TODO: Next Header Compression
    pktbuf_push_head_u8(pktbuf, hdr.ip6_nxt);

    field = lowpan_iphc_cmpr_vtcflow(pktbuf, ntohl(hdr.ip6_flow));
    base |= FIELD_PREP(LOWPAN_MASK_IPHC_TF, field);

    pktbuf_push_head_be16(pktbuf, base);
}
