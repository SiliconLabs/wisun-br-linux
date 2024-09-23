/*
 * Copyright (c) 2013-2021, Pelion and affiliates.
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
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "common/ipv6/ipv6_cksum.h"
#include "common/log.h"
#include "common/string_extra.h"
#include "common/rand.h"
#include "common/bits.h"
#include "common/named_values.h"
#include "common/iobuf.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/specs/ndp.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ipv6.h"
#include "common/specs/ip.h"

#include "net/protocol.h"
#include "mpl/mpl.h"
#include "ipv6/ipv6_routing_table.h"
#include "ipv6/ipv6_routing_table.h"
#include "ipv6/nd_router_object.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "ws/ws_common.h"

#include "ipv6/ipv6.h"

#include "ipv6/icmpv6.h"

#define TRACE_GROUP "icmp"

/* Check to see if a message is recognisable ICMPv6, and if so, fill in code/type */
/* This used ONLY for the e.1 + e.2 tests in RFC 4443, to try to avoid ICMPv6 error loops */
/* Packet may be ill-formed, because we are considering an ICMPv6 error response. */
static bool is_icmpv6_msg(buffer_t *buf)
{
    const uint8_t *ptr = buffer_data_pointer(buf);
    uint16_t len = buffer_data_length(buf);

    /* IP header format:
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Version| Traffic Class |           Flow Label                  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Payload Length        |  Next Header  |   Hop Limit   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *    + Source Address (16) + Destination Address (16), total 40
     */
    if (len < IPV6_HDRLEN) {
        return false;
    }
    uint16_t ip_len = read_be16(ptr + IPV6_HDROFF_PAYLOAD_LENGTH);
    uint8_t nh = ptr[IPV6_HDROFF_NH];
    ptr += IPV6_HDRLEN;
    len -= IPV6_HDRLEN;
    if (ip_len > len) {
        return false;
    }
    len = ip_len;
    while (len) {
        uint16_t hdrlen;
        switch (nh) {
            case IPV6_NH_ICMPV6:
                if (len < 4) {
                    return false;
                }
                buf->options.type = ptr[0];
                buf->options.code = ptr[1];
                return true;
            case IPV6_NH_HOP_BY_HOP:
            case IPV6_NH_DEST_OPT:
            case IPV6_NH_ROUTING:
            case IPV6_NH_MOBILITY:
            case IPV6_NH_HIP:
            case IPV6_NH_SHIM6:
                if (len < 8) {
                    return false;
                }
                nh = ptr[0];
                hdrlen = (ptr[1] + 1) * 8;
                break;
            case IPV6_NH_AUTH:
                if (len < 8) {
                    return false;
                }
                nh = ptr[0];
                hdrlen = (ptr[1] + 2) * 4;
                break;
            default:
                return false;
        }
        if (hdrlen > len || (hdrlen & 7)) {
            return false;
        }
        ptr += hdrlen;
        len -= hdrlen;
    }
    return false;
}

buffer_t *icmpv6_error(buffer_t *buf, struct net_if *cur, uint8_t type, uint8_t code, uint32_t aux)
{
    uint8_t *ptr;

    /* Don't send ICMP errors to improperly-secured packets (they either reach MLE etc successfully, or we just drop) */
    if (buf->options.ll_security_bypass_rx) {
        return buffer_free(buf);
    }

    if (cur == NULL) {
        cur = buf->interface;
    }

    /* RFC 4443 processing rules e.1-2: don't send errors for ICMPv6 errors or redirects */
    if (is_icmpv6_msg(buf) && (buf->options.type < 128 || buf->options.type == ICMPV6_TYPE_REDIRECT)) {
        return buffer_free(buf);
    }

    /* RFC 4443 processing rules e.3-5: don't send errors for IP multicasts or link-layer multicasts+broadcasts (with exceptions) */
    if (addr_is_ipv6_multicast(buf->dst_sa.address) || buf->options.ll_broadcast_rx) {
        if (!(type == ICMPV6_TYPE_ERROR_PACKET_TOO_BIG ||
                (type == ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM && code == ICMPV6_CODE_PARAM_PRB_UNREC_IPV6_OPT))) {
            return buffer_free(buf);
        }
    }

    /* RFC 4443 processing rule e.6 - source doesn't identify a single node */
    if (addr_is_ipv6_unspecified(buf->src_sa.address) || addr_is_ipv6_multicast(buf->src_sa.address)) {
        return buffer_free(buf);
    }

    if (addr_interface_address_compare(cur, buf->dst_sa.address) == 0) {
        // RFC 4443 2.2 - if addressed to us, use that address as source
        memswap(buf->dst_sa.address, buf->src_sa.address, 16);
    } else {
        // Otherwise we will use normal address selection rule
        buf->dst_sa = buf->src_sa;

        // This makes buffer_route choose the address
        buf->src_sa.addr_type = ADDR_NONE;
    }

    buffer_turnaround(buf);

    if (!ipv6_buffer_route(buf)) {
        return buffer_free(buf);
    }
    cur = buf->interface;

    /* Token-bucket rate limiting */
    if (!cur->icmp_tokens) {
        return buffer_free(buf);
    }
    cur->icmp_tokens--;

    /* Include as much of the original packet as possible, without exceeding
     * minimum MTU of 1280. */
    uint16_t max_payload = ipv6_max_unfragmented_payload(buf, IPV6_MIN_LINK_MTU);
    if (buffer_data_length(buf) > max_payload - 8) {
        buffer_data_length_set(buf, max_payload - 8);
    }

    if ((buf = buffer_headroom(buf, 4)) == NULL) {
        return NULL;
    }
    ptr = buffer_data_reserve_header(buf, 4);
    ptr = write_be32(ptr, aux);
    buf->options.traffic_class = 0;
    buf->options.type = type;
    buf->options.code = code;
    buf->options.hop_limit = cur->cur_hop_limit;
    buf->info = (buffer_info_t)(B_FROM_ICMP | B_TO_ICMP | B_DIR_DOWN);

    return (buf);
}

static bool icmpv6_nd_options_validate(const uint8_t *data, size_t len)
{
    struct iobuf_read input = {
        .data_size = len,
        .data = data,
    };
    int opt_start, opt_len;

    while (iobuf_remaining_size(&input)) {
        opt_start = input.cnt;
        iobuf_pop_u8(&input); // Type
        opt_len = 8 * iobuf_pop_u8(&input);
        if (!opt_len)
            return false;
        input.cnt = opt_start;
        iobuf_pop_data_ptr(&input, opt_len);
    }
    return !input.err;
}

static bool icmpv6_nd_option_get(const uint8_t *data, size_t len, uint16_t option, struct iobuf_read *res)
{
    struct iobuf_read input = {
        .data_size = len,
        .data = data,
    };
    int opt_start, opt_len;
    uint8_t opt_type;

    memset(res, 0, sizeof(struct iobuf_read));
    res->err = true;
    while (iobuf_remaining_size(&input)) {
        opt_start = input.cnt;
        opt_type = iobuf_pop_u8(&input);
        opt_len = 8 * iobuf_pop_u8(&input);
        input.cnt = opt_start;
        if (opt_type == option) {
            res->data = iobuf_pop_data_ptr(&input, opt_len);
            if (!res->data)
                return false;
            res->err = false;
            res->data_size = opt_len;
            return true;
        }
        iobuf_pop_data_ptr(&input, opt_len);
    }
    return false;
}

// Wi-SUN allows to use an ARO without an SLLAO. This function builds a dummy
// SLLAO using the information from the ARO, which can be processed using the
// standard ND procedure.
static bool icmpv6_nd_ws_sllao_dummy(struct iobuf_write *sllao, const uint8_t *aro_ptr, size_t aro_len)
{
    struct iobuf_read earo = {
        .data = aro_ptr,
        .data_size = aro_len,
    };
    const uint8_t *eui64;

    iobuf_pop_u8(&earo);          // Type
    iobuf_pop_u8(&earo);          // Length
    iobuf_pop_u8(&earo);          // Status
    iobuf_pop_data_ptr(&earo, 3); // Reserved
    iobuf_pop_be16(&earo);        // Registration Lifetime
    eui64 = iobuf_pop_data_ptr(&earo, 8);

    BUG_ON(sllao->len);
    iobuf_push_u8(sllao, NDP_OPT_SLLAO);
    iobuf_push_u8(sllao, 0); // Length (filled after)
    iobuf_push_data(sllao, eui64, 8);
    while (sllao->len % 8)
        iobuf_push_u8(sllao, 0); // Padding
    sllao->data[1] = sllao->len / 8;

    return !earo.err;
}

/*
 *      Neighbor Solicitation Message Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |     Type      |     Code      |          Checksum             |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                           Reserved                            |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                                                               |
 *       +                                                               +
 *       |                                                               |
 *       +                       Target Address                          +
 *       |                                                               |
 *       +                                                               +
 *       |                                                               |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |   Options ...
 *       +-+-+-+-+-+-+-+-+-+-+-+-
 *
 *
 *      Source/Target Link-layer Address
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |     Type      |    Length     |    Link-Layer Address ...
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static buffer_t *icmpv6_ns_handler(buffer_t *buf)
{
    struct iobuf_read iobuf = {
        .data_size = buffer_data_length(buf),
        .data = buffer_data_pointer(buf),
    };
    struct ipv6_nd_opt_earo na_earo = { };
    struct iobuf_write sllao_dummy = { };
    bool has_earo, has_sllao;
    struct iobuf_read sllao;
    struct iobuf_read earo;
    struct net_if *cur;
    uint8_t target[16];
    bool proxy = false;
    buffer_t *na_buf;

    cur = buf->interface;

    iobuf_pop_data_ptr(&iobuf, 4); // Reserved
    iobuf_pop_data(&iobuf, target, 16);

    has_sllao = icmpv6_nd_option_get(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf),
                                     NDP_OPT_SLLAO, &sllao);
    has_earo = icmpv6_nd_option_get(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf),
                                    NDP_OPT_ARO, &earo);
    if (!cur->ipv6_neighbour_cache.recv_addr_reg)
        has_earo = false;
    //   Wi-SUN - IPv6 Neighbor Discovery Optimizations
    // Optional usage of SLLAO. The ARO already includes the EUI-64 that is the
    // link-layer address of the node transmitting the Neighbor Solicitation.
    // SLLAO provides a way to use a link layer address other than the EUI-64,
    // but that comes at a 10 octet overhead, and is unnecessary as FAN assumes
    // EUI-64 global uniqueness.
    if (has_earo && !has_sllao) {
        has_sllao = icmpv6_nd_ws_sllao_dummy(&sllao_dummy, earo.data, earo.data_size);
        sllao.data_size = sllao_dummy.len;
        sllao.data      = sllao_dummy.data;
        sllao.err       = false;
        sllao.cnt       = 0;
    }

    //   RFC 4861 Section 7.1.1 - Validation of Neighbor Solicitations
    // A node MUST silently discard any received Neighbor Solicitation
    // messages that do not satisfy all of the following validity checks:
    if (buf->options.hop_limit != 255)
        goto drop; // The IP Hop Limit field has a value of 255
    if (buf->options.code != 0)
        goto drop; // ICMP Code is 0.
    if (!icmpv6_nd_options_validate(iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf)))
        goto drop; // All included options have a length that is greater than zero.
    if (addr_is_ipv6_unspecified(buf->src_sa.address)) {
        // If the IP source address is the unspecified address,
        if (!memcmp(buf->dst_sa.address, ADDR_MULTICAST_SOLICITED, sizeof(ADDR_MULTICAST_SOLICITED)))
            goto drop; // the IP destination address is a solicited-node multicast address.
        if (has_sllao)
            goto drop; // there is no source link-layer address option in the message.
    }

    /* This first check's a bit dodgy - it responds to our address on the other
     * interface, which we should only do in the whiteboard case.
     */
    if (addr_interface_address_compare(cur, target) != 0) {
        //tr_debug("Received  NS for proxy %s", tr_ipv6(target));

        proxy = true;
        //Filter Link Local scope
        if (addr_is_ipv6_link_local(target)) {
            goto drop;
        }
    }

    if (has_earo) {
        /* If it had an ARO, and we're paying attention to it, possibilities:
         * 1) No reply to NS now, we need to contact border router (false return)
         * 2) Reply to NS now, with ARO (true return, aro_out.present true)
         * 3) Reply to NS now, without ARO (true return, aro_out.present false)
         */
        if (!nd_ns_earo_handler(cur, earo.data, earo.data_size,
                                has_sllao ? sllao.data : NULL,
                                buf->src_sa.address, target, &na_earo))
            goto drop;
    }

    /* If we're returning an ARO, then we assume the ARO handler has done the
     * necessary to the Neighbour Cache. Otherwise, normal RFC 4861 processing. */
    if (!na_earo.present && has_sllao && cur->if_llao_parse(cur, sllao.data, &buf->dst_sa))
        ipv6_neighbour_update_unsolicited(&cur->ipv6_neighbour_cache, buf->src_sa.address, buf->dst_sa.addr_type, buf->dst_sa.address);

    na_buf = icmpv6_build_na(cur, true, !proxy, addr_is_ipv6_multicast(buf->dst_sa.address), target,
                             na_earo.present ? &na_earo : NULL, buf->src_sa.address);

    buffer_free(buf);
    iobuf_free(&sllao_dummy);

    return na_buf;

drop:
    buf = buffer_free(buf);
    iobuf_free(&sllao_dummy);

    return buf;

}

void trace_icmp(buffer_t *buf, bool is_rx)
{
    static const struct name_value icmp_frames[] = {
        { "na",              ICMPV6_TYPE_NA },
        { "ns",              ICMPV6_TYPE_NS },
        { "ra",              ICMPV6_TYPE_RA },
        { "rs",              ICMPV6_TYPE_RS },
        { "dac",             ICMPV6_TYPE_DAC },
        { "dar",             ICMPV6_TYPE_DAR },
        { "mpl",             ICMPV6_TYPE_MPL },
        { "ping rpl",        ICMPV6_TYPE_ECHO_REPLY },
        { "ping req",        ICMPV6_TYPE_ECHO_REQUEST },
        { "mc done",         ICMPV6_TYPE_MCAST_LIST_DONE },
        { "mc query",        ICMPV6_TYPE_MCAST_LIST_QUERY },
        { "mc reprt",        ICMPV6_TYPE_MCAST_LIST_REPORT },
        { "mc reprt v2",     ICMPV6_TYPE_MCAST_LIST_REPORT_V2 },
        { "redirect",        ICMPV6_TYPE_REDIRECT },
        { "e. dest unreach", ICMPV6_TYPE_ERROR_DESTINATION_UNREACH },
        { "e. pkt too big",  ICMPV6_TYPE_ERROR_PACKET_TOO_BIG },
        { "e. timeout",      ICMPV6_TYPE_ERROR_TIME_EXCEEDED },
        { "e. params",       ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM },
        { NULL },
    };
    struct iobuf_read ns_earo_buf;
    char frame_type[40] = "";
    const char *ns_aro_str;
    uint8_t ns_earo_flags;

    strncat(frame_type, val_to_str(buf->options.type, icmp_frames, "[UNK]"),
            sizeof(frame_type) - strlen(frame_type) - 1);
    if (buf->options.type == ICMPV6_TYPE_NS) {
        if (buffer_data_length(buf) > 20 &&
            icmpv6_nd_option_get(buffer_data_pointer(buf) + 20, buffer_data_length(buf) - 20,
                                 NDP_OPT_ARO, &ns_earo_buf)) {
            iobuf_pop_u8(&ns_earo_buf); // Type
            iobuf_pop_u8(&ns_earo_buf); // Length
            iobuf_pop_u8(&ns_earo_buf); // Status
            iobuf_pop_u8(&ns_earo_buf); // Opaque
            ns_earo_flags = iobuf_pop_u8(&ns_earo_buf);
            if (FIELD_GET(NDP_MASK_ARO_R, ns_earo_flags) &&
                FIELD_GET(NDP_MASK_ARO_T, ns_earo_flags))
                ns_aro_str = " w/ earo";
            else
                ns_aro_str = " w/ aro";
            strncat(frame_type, ns_aro_str, sizeof(frame_type) - strlen(frame_type) - 1);
        }
    }
    if (is_rx)
        TRACE(TR_ICMP, "rx-icmp %-9s src:%s", frame_type, tr_ipv6(buf->src_sa.address));
    else
        TRACE(TR_ICMP, "tx-icmp %-9s dst:%s", frame_type, tr_ipv6(buf->dst_sa.address));
}

buffer_t *icmpv6_up(buffer_t *buf)
{
    struct iobuf_read iobuf = {
        .data      = buffer_data_pointer(buf),
        .data_size = buffer_data_length(buf),
    };

    buf->options.type = iobuf_pop_u8(&iobuf);
    buf->options.code = iobuf_pop_u8(&iobuf);
    iobuf_pop_be16(&iobuf); // Checksum
    if (iobuf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed header", "icmpv6");
        return buffer_free(buf);
    }

    if (ipv6_cksum((struct in6_addr *)buf->src_sa.address,
                   (struct in6_addr *)buf->dst_sa.address,
                   IPV6_NH_ICMPV6,
                   buffer_data_pointer(buf),
                   buffer_data_length(buf))) {
        TRACE(TR_DROP, "drop %-9s: invalid checksum", "icmpv6");
        return buffer_free(buf);
    }

    buffer_data_strip_header(buf, 4);

    trace_icmp(buf, true);

    switch (buf->options.type) {
    case ICMPV6_TYPE_NS:
        return icmpv6_ns_handler(buf);

    default:
        // FIXME: forward DAR/DAC to Linux?
        TRACE(TR_DROP, "drop %-9s: unsupported type %u", "icmpv6", buf->options.type);
        return buffer_free(buf);
    }
}

buffer_t *icmpv6_down(buffer_t *buf)
{
    struct net_if *cur = buf->interface;

    trace_icmp(buf, false);
    buf = buffer_headroom(buf, 4);
    if (buf) {
        uint8_t *dptr;
        dptr = buffer_data_reserve_header(buf, 4);
        buf->info = (buffer_info_t)(B_FROM_ICMP | B_TO_IPV6 | B_DIR_DOWN);

        if (buf->src_sa.addr_type != ADDR_IPV6) {
            if (addr_interface_select_source(cur, buf->src_sa.address, buf->dst_sa.address, 0) != 0) {
                tr_error("ICMP:InterFace Address Get Fail--> free Buffer");
                return buffer_free(buf);
            } else {
                buf->src_sa.addr_type = ADDR_IPV6;
            }

        }

        *dptr++ = buf->options.type;
        *dptr++ = buf->options.code;
        *(be16_t *)dptr = 0;
        *(be16_t *)dptr = ipv6_cksum((struct in6_addr *)buf->src_sa.address,
                                     (struct in6_addr *)buf->dst_sa.address,
                                     IPV6_NH_ICMPV6,
                                     buffer_data_pointer(buf),
                                     buffer_data_length(buf));
        buf->options.type = IPV6_NH_ICMPV6;
        buf->options.code = 0;
        buf->options.traffic_class &= ~IP_TCLASS_ECN_MASK;
    }
    return (buf);
}

uint8_t *icmpv6_write_icmp_lla(struct net_if *cur, uint8_t *dptr, uint8_t icmp_opt, bool must, const uint8_t *ip_addr)
{
    dptr += cur->if_llao_write(cur, dptr, icmp_opt, must, ip_addr);

    return dptr;
}

buffer_t *icmpv6_build_ns(struct net_if *cur, const uint8_t target_addr[16], bool unicast)
{
    if (!cur || addr_is_ipv6_multicast(target_addr)) {
        return NULL;
    }

    buffer_t *buf = buffer_get(127);
    if (!buf) {
        return buf;
    }

    buf->options.type = ICMPV6_TYPE_NS;
    buf->options.code = 0;
    buf->options.hop_limit = 255;

    uint8_t *ptr = buffer_data_pointer(buf);
    ptr = write_be32(ptr, 0);
    memcpy(ptr, target_addr, 16);
    ptr += 16;

    if (unicast) {
        memcpy(buf->dst_sa.address, target_addr, 16);
    } else {
        memcpy(buf->dst_sa.address, ADDR_MULTICAST_SOLICITED, 13);
        memcpy(buf->dst_sa.address + 13, target_addr + 13, 3);
    }
    buf->dst_sa.addr_type = ADDR_IPV6;

    /* RFC 4861 7.2.2. says we should use the source of traffic prompting the NS, if possible */
    /* Otherwise, according to RFC 4861, we could use any address.
     * But there is a 6lowpan/RPL hiccup - a node may have registered
     * to us with an ARO, and we might send it's global address a NUD
     * probe. But it doesn't know _our_ global address, which default
     * address selection would favour.
     * If it was still a host, we'd get away with using our global
     * address, as we'd be its default route, so its reply comes to us.
     * But if it's switched to being a RPL router, it would send its
     * globally-addressed reply packet up the RPL DODAG.
     * Avoid the problem by using link-local source.
     * This will still leave us with an asymmetrical connection - its
     * global address on-link for us, and we send to it directly (and
     * can NUD probe it), whereas it regards us as off-link and will
     * go via RPL (and won't probe us). But it will work fine.
     */
    if (addr_interface_get_ll_address(cur, buf->src_sa.address, 0) < 0) {
        tr_debug("No address for NS");
        return buffer_free(buf);
    }

    buf->src_sa.addr_type = ADDR_IPV6;

    /* NS packets are implicitly on-link. If we ever find ourselves sending an
     * NS to a global address, it's because we are in some way regarding
     * it as on-link. (eg, redirect, RPL source routing header). We force
     * transmission as on-link here, regardless of routing table, to avoid any
     * potential oddities.
     */
    ipv6_buffer_route_to(buf, buf->dst_sa.address, cur);

    buffer_data_end_set(buf, ptr);
    buf->interface = cur;
    buf->info = (buffer_info_t)(B_FROM_ICMP | B_TO_ICMP | B_DIR_DOWN);

    return buf;
}

/*
 * Neighbor Advertisement Message Format
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |     Code      |          Checksum             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |R|S|O|                     Reserved                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                       Target Address                          +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Options ...
 *  +-+-+-+-+-+-+-+-+-+-+-+-
 *
 *    R              Router flag.
 *    S              Solicited flag.
 *    O              Override flag.
 */

buffer_t *icmpv6_build_na(struct net_if *cur, bool solicited, bool override, bool tllao_required,
                          const uint8_t target[16], const struct ipv6_nd_opt_earo *earo,
                          const uint8_t src_addr[16])
{
    uint8_t *ptr;
    uint8_t flags;

    /* Check if ARO response and status == success, then sending can be omitted with flag */
    // FIXME: It is not clear how ARO and EARO are differentiated.
    // This hack is based on the Wi-SUN specification.
    if (cur->ipv6_neighbour_cache.omit_na_aro_success && earo &&
        earo->status == NDP_ARO_STATUS_SUCCESS && (!earo->t || !earo->lifetime)) {
        tr_debug("Omit NA ARO success");
        return NULL;
    }
    /* All other than ARO NA messages are omitted and MAC ACK is considered as success */
    if (!tllao_required && (!earo && cur->ipv6_neighbour_cache.omit_na)) {
        return NULL;
    }


    buffer_t *buf = buffer_get(8 + 16 + 16 + 16); /* fixed, target addr, target ll addr, aro */
    if (!buf) {
        return NULL;
    }

    ptr = buffer_data_pointer(buf);
    buf->options.hop_limit = 255;

    // Set the ICMPv6 NA type and code fields as per RFC4861
    buf->options.type = ICMPV6_TYPE_NA;
    buf->options.code = 0x00;

    flags = 0;

    if (override) {
        flags |= NA_O;
    }

    if (addr_is_ipv6_unspecified(src_addr)) {
        // Solicited flag must be 0 if responding to DAD
        memcpy(buf->dst_sa.address, ADDR_LINK_LOCAL_ALL_NODES, 16);
    } else {
        if (solicited) {
            flags |= NA_S;
        }

        /* See RFC 6775 6.5.2 - errors are sent to LL64 address
         * derived from EUI-64, success to IP source address */
        if (earo && earo->status != NDP_ARO_STATUS_SUCCESS) {
            memcpy(buf->dst_sa.address, ADDR_LINK_LOCAL_PREFIX, 8);
            memcpy(buf->dst_sa.address + 8, earo->eui64, 8);
            buf->dst_sa.address[8] ^= 2;
        } else {
            memcpy(buf->dst_sa.address, src_addr, 16);
        }
    }
    buf->dst_sa.addr_type = ADDR_IPV6;

    /* In theory we could just use addr_select_source(), as RFC 4861 allows
     * any address assigned to the interface as source. But RFC 6775 shows LL64
     * as the source in its appendix, sending NA to a global address, and our
     * lower layers go a bit funny with RPL during bootstrap if we send from a
     * global address to a global address. By favouring the target address as
     * source, we catch that 6LoWPAN case (the target is LL), as well as making
     * it look neater anyway.
     */
    if (addr_is_assigned_to_interface(cur, target)) {
        memcpy(buf->src_sa.address, target, 16);
    } else {
        const uint8_t *src = addr_select_source(cur, buf->dst_sa.address, 0);
        if (!src) {
            tr_debug("No address");
            return buffer_free(buf);
        }
        memcpy(buf->src_sa.address, src, 16);
    }
    buf->src_sa.addr_type = ADDR_IPV6;

    ptr = write_be32(ptr, (uint32_t) flags << 24);
    // Set the target IPv6 address
    memcpy(ptr, target, 16);
    ptr += 16;

    // Set the target Link-Layer address
    ptr = icmpv6_write_icmp_lla(cur, ptr, NDP_OPT_TLLAO, tllao_required, target);

    if (earo) {
        *ptr++ = NDP_OPT_ARO;
        *ptr++ = 2;
        *ptr++ = earo->status;
        *ptr++ = earo->opaque;
        *ptr++ = FIELD_PREP(NDP_MASK_ARO_P, earo->p)
               | FIELD_PREP(NDP_MASK_ARO_I, earo->i)
               | FIELD_PREP(NDP_MASK_ARO_R, earo->r)
               | FIELD_PREP(NDP_MASK_ARO_T, earo->t);
        *ptr++ = earo->tid;
        ptr = write_be16(ptr, earo->lifetime);
        memcpy(ptr, earo->eui64, 8);
        ptr += 8;
    }

    //Force Next Hop is destination
    ipv6_buffer_route_to(buf, buf->dst_sa.address, cur);

    buffer_data_end_set(buf, ptr);
    buf->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_ICMP | B_TO_ICMP);
    buf->interface = cur;

    return (buf);
}
