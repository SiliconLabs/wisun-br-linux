/*
 * Copyright (c) 2014-2020, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>
#include "common/bits.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/specs/ipv6.h"

#include "net/ns_buffer.h"
#include "net/protocol.h"
#include "6lowpan/iphc_decode/cipv6.h"

#include "6lowpan/iphc_decode/iphc_decompress.h"

#define TRACE_GROUP "iphc"

/* Analyse a 6LoWPAN datagram for fragmentation, checking header length */
/* Critical fact is that fragments are described with their size+offsets in */
/* terms of the UNCOMPRESSED IP datagram, so when presented with a 6LoWPAN datagram, */
/* we need to work backwards. Another constraint is that compressed headers */
/* must all lie within the first fragment - doesn't concern us here. */
/* Input: a potentially oversized 6lowpan-format datagram without fragmentation */
/* Return: size of compressed IPHC headers */
/* Output: uncompressed_size = uncompressed size of IPHC headers */
uint16_t iphc_header_scan(buffer_t *buf, uint16_t *uncompressed_size)
{
    const uint8_t *ptr = buffer_data_pointer(buf);
    const uint8_t *end = buffer_data_end(buf);
    uint16_t uncomp_len = 0;
    const uint8_t *ip_hc;

    *uncompressed_size = 0;

    /* Fragmentation needs us to handle uncompressed case */
    if (ptr < end && ptr[0] == LOWPAN_DISPATCH_IPV6) {
        return 1;
    }

    /* Handle compressed IP header (LOWPAN_IPHC) - LOWPAN_HC1 etc not handled */
IPv6START:
    ip_hc = ptr;
    ptr += 2;
    uncomp_len += 40;

    if (ptr > end) {
        goto truncated;
    }

    if ((ip_hc[0] & LOWPAN_DISPATCH_IPHC_MASK) != LOWPAN_DISPATCH_IPHC) {
        tr_warn("Unexpected 6LoWPAN ID");
        return 0;
    }

    if (ip_hc[1] & HC_CIDE_COMP) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        return 0;
    }

    switch (ip_hc[0] & HC_TF_MASK) {
        case HC_TF_ECN_DSCP_FLOW_LABEL:
            ptr += 4;
            break;
        case HC_TF_ECN_FLOW_LABEL:
            ptr += 3;
            break;
        case HC_TF_ECN_DSCP:
            ptr += 1;
            break;
        default:
            break;
    }

    if (!(ip_hc[0] & HC_NEXT_HEADER_MASK)) {
        ptr++;
    }

    if ((ip_hc[0] & HC_HOP_LIMIT_MASK) == HC_HOP_LIMIT_CARRIED_IN_LINE) {
        ptr++;
    }

    switch (ip_hc[1] & HC_SRC_ADR_MODE_MASK) {
        case HC_SRC_ADR_128_BIT:
            if (!(ip_hc[1] & HC_SRCADR_COMP)) {
                ptr += 16;
            }
            break;
        case HC_SRC_ADR_64_BIT:
            ptr += 8;
            break;
        case HC_SRC_ADR_16_BIT:
            ptr += 2;
            break;
        case HC_SRC_ADR_FROM_MAC:
            break;
    }

    if (ip_hc[1] & HC_MULTICAST_COMP) {
        switch (ip_hc[1] & (HC_DSTADR_COMP | HC_DST_ADR_MODE_MASK)) {
            case HC_128BIT_MULTICAST:
                ptr += 16;
                break;
            case HC_48BIT_MULTICAST:
                ptr += 6;
                break;
            case HC_32BIT_MULTICAST:
                ptr += 4;
                break;
            case HC_8BIT_MULTICAST:
                ptr += 1;
                break;
            default:
                tr_warn("Unknown multicast compression");
                return 0;
        }
    } else {
        switch (ip_hc[1] & HC_DST_ADR_MODE_MASK) {
            case HC_DST_ADR_128_BIT:
                ptr += 16;
                break;
            case HC_DST_ADR_64_BIT:
                ptr += 8;
                break;
            case HC_DST_ADR_16_BIT:
                ptr += 2;
                break;
            case HC_DST_ADR_FROM_MAC:
                break;
        }
    }

    /* Handle following headers (LOWPAN_NHC) */
    bool nhc_next_header = ip_hc[0] & HC_NEXT_HEADER_MASK;
    while (nhc_next_header) {
        uint8_t nhc_id;
        if (ptr >= end) {
            goto truncated;
        }
        nhc_id = *ptr++;
        //tr_debug("IPNH: %02x", next_header);
        if ((nhc_id & NHC_EXT_HEADER_MASK) == NHC_EXT_HEADER) {
            uint8_t len = 0;
            switch (nhc_id & NHC_EXT_ID_MASK) {
                case NHC_EXT_IPV6:
                    goto IPv6START;
                case NHC_EXT_HOP_BY_HOP:
                case NHC_EXT_ROUTING:
                case NHC_EXT_FRAG:
                case NHC_EXT_DEST_OPT:
                case NHC_EXT_MOBILITY:
                    nhc_next_header = nhc_id & NHC_EXT_NH;
                    if (!nhc_next_header) {
                        ptr++;
                    }
                    if (ptr >= end) {
                        goto truncated;
                    }
                    if ((nhc_id & NHC_EXT_ID_MASK) == NHC_EXT_FRAG) {
                        /* See notes in main decompress routine */
                        ptr += 7;
                        uncomp_len += 8;
                    } else {
                        len = *ptr++;
                        /* len is length of following data in bytes */
                        ptr += len;
                        /* Uncompressed headers must be multiple of 8 octets, so
                         * uncompressed length is 2+len ("NH" + "len" + data),
                         * rounded up to a multiple of 8.
                         */
                        uncomp_len += ((2 + len) + 7) & ~ 7;
                    }
                    break;
                default:
                    goto bad_nhc_id;
            }
        } else if ((nhc_id & NHC_UDP_MASK) == NHC_UDP) {
            uncomp_len += 8;
            nhc_next_header = false;
            if (!(nhc_id & NHC_UDP_CKSUM_COMPRESS)) {
                ptr += 2;
            }
            switch (nhc_id & NHC_UDP_PORT_COMPRESS_MASK) {
                case NHC_UDP_PORT_COMPRESS_DST:
                case NHC_UDP_PORT_COMPRESS_SRC:
                    ptr += 3;
                    break;
                case NHC_UDP_PORT_COMPRESS_NONE:
                    ptr += 4;
                    break;
                case NHC_UDP_PORT_COMPRESS_BOTH:
                default:
                    ptr += 1;
                    break;
            }
        } else {
bad_nhc_id:
            tr_warn("Unknown NHC ID: %02x", nhc_id);
            nhc_next_header = false;
        }
    }

    if (ptr > end) {
truncated:
        tr_warn("Truncated packet");
        return 0;
    }

    *uncompressed_size = uncomp_len;
    return ptr - buffer_data_pointer(buf);
}

static bool decompress_mc_addr(uint8_t *addr, const uint8_t **in_ptr, const uint8_t *outer_iid, uint8_t mode)
{
    const uint8_t *in = *in_ptr;
    (void) outer_iid;
    switch (mode) {
        case HC_128BIT_MULTICAST:
            memcpy(addr, in, 16);
            *in_ptr = in + 16;
            return true;
        case HC_48BIT_MULTICAST:
            addr[0] = 0xff;
            addr[1] = *in++;
            memset(&addr[2], 0, 9);
            memcpy(&addr[11], in, 5);
            *in_ptr = in + 5;
            return true;
        case HC_32BIT_MULTICAST:
            addr[0] = 0xff;
            addr[1] = *in++;
            memset(&addr[2], 0, 11);
            memcpy(&addr[13], in, 3);
            *in_ptr = in + 3;
            return true;
        case HC_8BIT_MULTICAST:
            memcpy(addr, ADDR_LINK_LOCAL_ALL_NODES, 15);
            addr[15] = *in++;
            *in_ptr = in;
            return true;
        default:
            return false;
    }
}

static bool decompress_addr(uint8_t *addr, const uint8_t **in_ptr, bool is_dst, const uint8_t *outer_iid, uint8_t mode)
{
    if (!is_dst) {
        /* Get SRC bits and move into DST position, without multicast bit */
        mode = (mode >> 4) & (HC_DSTADR_COMP | HC_DST_ADR_MODE_MASK);
    } else {
        mode &= (HC_MULTICAST_COMP | HC_DSTADR_COMP | HC_DST_ADR_MODE_MASK);
    }

    if (mode & HC_DSTADR_COMP) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        return false;
    }

    if (mode & HC_MULTICAST_COMP) {
        return decompress_mc_addr(addr, in_ptr, outer_iid, mode & ~ HC_MULTICAST_COMP);
    }

    switch (mode & HC_DST_ADR_MODE_MASK) {
        case HC_DST_ADR_128_BIT:
            memcpy(addr, *in_ptr, 16);
            *in_ptr += 16;
            return true;
        case HC_DST_ADR_64_BIT:
            memcpy(addr + 8, *in_ptr, 8);
            *in_ptr += 8;
            break;
        case HC_DST_ADR_16_BIT:
            memcpy(addr + 8, ADDR_SHORT_ADDR_SUFFIX, 6);
            addr[14] = (*in_ptr)[0];
            addr[15] = (*in_ptr)[1];
            *in_ptr += 2;
            break;
        case HC_DST_ADR_FROM_MAC:
            memcpy(addr + 8, outer_iid, 8);
            break;
    }

    memcpy(addr, ADDR_LINK_LOCAL_PREFIX, 8);
    return true;
}

typedef struct iphc_decompress_state {
    const uint8_t *in;
    const uint8_t *const end;
    uint8_t *out;
    uint8_t *nh_ptr;
    const uint8_t *outer_src_iid;
    const uint8_t *outer_dst_iid;
} iphc_decompress_state_t;

static bool decompress_ipv6(iphc_decompress_state_t *restrict ds)
{
    const uint8_t *iphc = ds->in;
    ds->in += 2;

    if (iphc[1] & HC_CIDE_COMP) {
        TRACE(TR_DROP, "drop %-9s: unsupported stateful compression", "6lowpan");
        return false;
    }

    /* First, Traffic Class and Flow Label */
    uint8_t tc = 0;
    uint8_t tf = iphc[0] & HC_TF_MASK;

    /* Extract ECN */
    if (tf != HC_TF_ELIDED) {
        tc = *ds->in >> 6;
    }

    /* Extract DSCP */
    if (tf == HC_TF_ECN_DSCP || tf == HC_TF_ECN_DSCP_FLOW_LABEL) {
        tc |= *ds->in++ << 2;
    }

    *ds->out++ = 0x60 | (tc >> 4);

    if (tf == HC_TF_ECN_FLOW_LABEL || tf == HC_TF_ECN_DSCP_FLOW_LABEL) {
        *ds->out++ = (tc << 4) | (*ds->in++ & 0x0f);
        *ds->out++ = *ds->in++;
        *ds->out++ = *ds->in++;
    } else {
        *ds->out++ = tc << 4;
        *ds->out++ = 0;
        *ds->out++ = 0;
    }

    /* Compute payload length */
    ds->out = write_be16(ds->out, ds->end - (ds->out + 36));

    /* Next Header */
    if (iphc[0] & HC_NEXT_HEADER_MASK) {
        /* Reserve space for Next Header - will be filled later */
        ds->nh_ptr = ds->out;
        *ds->out++ = IPV6_NH_NONE;
    } else {
        ds->nh_ptr = NULL;
        *ds->out++ = *ds->in++;
    }

    /* Hop Limit */
    switch (iphc[0] & HC_HOP_LIMIT_MASK) {
        case HC_HOP_LIMIT_1:
            *ds->out++ = 1;
            break;
        case HC_HOP_LIMIT_64:
            *ds->out++ = 64;
            break;
        case HC_HOP_LIMIT_255:
            *ds->out++ = 255;
            break;
        case HC_HOP_LIMIT_CARRIED_IN_LINE:
        default:
            *ds->out++ = *ds->in++;
            break;
    }

    if (!decompress_addr(ds->out, &ds->in, false, ds->outer_src_iid, iphc[1])) {
        tr_warn("SRC Address decompress fail");
        return false;
    }
    ds->outer_src_iid = ds->out + 8;
    ds->out += 16;
    if (!decompress_addr(ds->out, &ds->in, true, ds->outer_dst_iid, iphc[1])) {
        tr_warn("DST Address decompress fail");
        return false;
    }
    ds->outer_dst_iid = ds->out + 8;
    ds->out += 16;

    return true;
}

static bool decompress_exthdr(iphc_decompress_state_t *ds)
{
    uint8_t nh;

    switch (*ds->in & NHC_EXT_ID_MASK) {
        case NHC_EXT_HOP_BY_HOP:
            nh = IPV6_NH_HOP_BY_HOP;
            break;
        case NHC_EXT_ROUTING:
            nh = IPV6_NH_ROUTING;
            break;
        case NHC_EXT_FRAG:
            nh = IPV6_NH_FRAGMENT;
            break;
        case NHC_EXT_DEST_OPT:
            nh = IPV6_NH_DEST_OPT;
            break;
        case NHC_EXT_MOBILITY:
            nh = IPV6_NH_MOBILITY;
            break;
        case NHC_EXT_IPV6:
            *ds->nh_ptr = IPV6_NH_IPV6;
            ds->in++;
            return decompress_ipv6(ds);
        default:
            return false;
    }

    *ds->nh_ptr = nh;

    if (*ds->in++ & NHC_EXT_NH) {
        /* Reserve space for Next Header - will be filled later */
        ds->nh_ptr = ds->out;
        *ds->out++ = IPV6_NH_NONE;
    } else {
        ds->nh_ptr = NULL;
        *ds->out++ = *ds->in++;
    }

    uint8_t clen;
    if (nh == IPV6_NH_FRAGMENT) {
        /* Fragmentation header is awkward, and RFC 6282 isn't terribly clear */
        /* Second byte is reserved. It isn't a length field. */
        *ds->out++ = *ds->in++;
        clen = 6;
    } else {
        clen = *ds->in++;                   /* Compressed data len */
        *ds->out++ = (clen + 2 - 1) >> 3;   /* Uncompressed header length byte (8-octet units, excluding first) */
    }

    /* Copy main option data */
    memcpy(ds->out, ds->in, clen);
    ds->out += clen;
    ds->in += clen;

    /* If not aligned, add a PAD1 or PADN */
    if ((clen + 2) & 7) {
        uint8_t pad = 8 - ((clen + 2) & 7);
        if (pad == 1) {
            *ds->out++ = IPV6_OPTION_PAD1;
        } else {
            *ds->out++ = IPV6_OPTION_PADN;
            *ds->out++ = (pad -= 2);
            while (pad) {
                *ds->out++ = 0, pad--;
            }
        }
    }

    return true;
}

static bool decompress_udp(iphc_decompress_state_t *ds)
{
    uint8_t nhc = *ds->in++;

    /* Ports */
    if ((nhc & NHC_UDP_PORT_COMPRESS_MASK) == NHC_UDP_PORT_COMPRESS_BOTH) {
        *ds->out++ = 0xf0;
        *ds->out++ = 0xb0 | (*ds->in >> 4);
        *ds->out++ = 0xf0;
        *ds->out++ = 0xb0 | (*ds->in++ & 0x0f);
    } else {
        *ds->out++ = (nhc & NHC_UDP_PORT_COMPRESS_MASK) == NHC_UDP_PORT_COMPRESS_SRC ? 0xf0 : *ds->in++;
        *ds->out++ = *ds->in++;
        *ds->out++ = (nhc & NHC_UDP_PORT_COMPRESS_MASK) == NHC_UDP_PORT_COMPRESS_DST ? 0xf0 : *ds->in++;
        *ds->out++ = *ds->in++;
    }

    /* Length */
    ds->out = write_be16(ds->out, ds->end - (ds->out - 4));

    /* Don't currently allow checksum compression */
    if (nhc & NHC_UDP_CKSUM_COMPRESS) {
        return false;
    }
    *ds->out++ = *ds->in++;
    *ds->out++ = *ds->in++;

    *ds->nh_ptr = IPV6_NH_UDP;
    ds->nh_ptr = NULL;

    return true;
}

/* Input: A 6LoWPAN frame, starting with an IPHC header, with outer layer 802.15.4 MAC addresses in src+dst */
/* Output:  An IPv6 frame */
buffer_t *iphc_decompress(buffer_t *buf)
{
    uint8_t src_iid[8], dst_iid[8];
    uint8_t *iphc = NULL;

    /* Pre-scan to get compressed and uncompressed header size */
    uint16_t ip_size;
    uint16_t hc_size = iphc_header_scan(buf, &ip_size);
    if (hc_size == 0) {
        tr_warn("IPHC size 0");
        goto decomp_error;
    }

    /* Copy compressed header into temporary buffer */
    iphc = malloc(hc_size);
    if (!iphc) {
        tr_warn("IPHC header alloc fail %d", hc_size);
        goto decomp_error;
    }
    memcpy(iphc, buffer_data_pointer(buf), hc_size);

    /* Reserve buffer room for the uncompressed header */
    buffer_data_strip_header(buf, hc_size);
    buf = buffer_headroom(buf, ip_size);
    if (!buf) {
        tr_warn("IPHC headroom get fail %d", ip_size);
        goto decomp_error;
    }
    buffer_data_reserve_header(buf, ip_size);

    if (!addr_iid_from_outer(src_iid, &buf->src_sa) || !addr_iid_from_outer(dst_iid, &buf->dst_sa)) {
        tr_warn("Bad outer addr");
        goto decomp_error;
    }

    {
        iphc_decompress_state_t ds = {
            .in = iphc,
            .nh_ptr = NULL,
            .out = buffer_data_pointer(buf),
            .end = buffer_data_end(buf),
            .outer_src_iid = src_iid,
            .outer_dst_iid = dst_iid,
        };

        /* Always start with the IP header */
        if (!decompress_ipv6(&ds)) {
            tr_warn("IPV6 decompres fail");
            goto decomp_error;
        }

        /* After the first IP header, we switch on the NHC byte */
        /* Know we're finished when there's no NH byte waiting to be filled */
        while (ds.nh_ptr) {
            bool ok = false;
            if ((ds.in[0] & NHC_UDP_MASK) == NHC_UDP) {
                ok = decompress_udp(&ds);
            } else if ((ds.in[0] & NHC_EXT_HEADER_MASK) == NHC_EXT_HEADER) {
                ok = decompress_exthdr(&ds);
            }
            if (!ok) {
                tr_warn("Unknow NH");
                goto decomp_error;
            }
        }

        if (ds.out != buffer_data_pointer(buf) + ip_size) {
            tr_error("IPHC decompression bug");
            goto decomp_error;
        }
    }

    free(iphc);
    return buf;

decomp_error:
    tr_warn("IPHC decompression error");
    free(iphc);
    return buffer_free(buf);
}
