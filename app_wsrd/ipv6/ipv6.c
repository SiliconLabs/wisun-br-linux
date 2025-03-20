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
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "common/ipv6/ipv6_addr.h"
#include "common/bits.h"
#include "common/eui64.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/netinet_in_extra.h"
#include "common/pktbuf.h"
#include "common/sys_queue_extra.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ipv6.h"
#include "app_wsrd/ipv6/6lowpan.h"
#include "app_wsrd/ipv6/ipv6_addr_mc.h"
#include "app_wsrd/ipv6/rpl_rpi.h"
#include "app_wsrd/ipv6/rpl_srh.h"
#include "ipv6.h"

static const struct ip6_hbh *ipv6_process_hopopts(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf)
{
    struct iobuf_read iobuf = { };
    const struct ip6_hbh *hbh;
    struct ip6_opt *opt;
    int ret;

    hbh = (struct ip6_hbh *)pktbuf_head(pktbuf);
    if (pktbuf_len(pktbuf) < sizeof(struct ip6_hbh) ||
        pktbuf_len(pktbuf) < (hbh->ip6h_len + 1) * 8) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "ipv6-hbh");
        pktbuf->err = true;
        return NULL;
    }
    pktbuf_pop_head(pktbuf, NULL, (hbh->ip6h_len + 1) * 8);
    iobuf.data      = (const uint8_t *)(hbh + 1);
    iobuf.data_size = (hbh->ip6h_len + 1) * 8 - sizeof(struct ip6_hbh);
    while (iobuf_remaining_size(&iobuf)) {
        opt = (struct ip6_opt *)iobuf_ptr(&iobuf);
        if (opt->ip6o_type == IP6OPT_PAD1)
            continue;
        if (!iobuf_pop_data_ptr(&iobuf, sizeof(struct ip6_opt)) ||
            !iobuf_pop_data_ptr(&iobuf, opt->ip6o_len)) {
            TRACE(TR_DROP, "drop %-9s: malformed packet", "ipv6-hbh");
            pktbuf->err = true;
            return NULL;
        }
        switch (opt->ip6o_type) {
        case IP6OPT_PADN:
            continue;
        case IPV6_OPTION_RPI:
        case IPV6_OPTION_RPI_DEPRECATED:
            ret = rpl_rpi_process(ipv6, opt);
            if (ret < 0)
                return NULL;
            break;
        default:
            switch (IP6OPT_TYPE(opt->ip6o_type)) {
            case IP6OPT_TYPE_SKIP:
                TRACE(TR_IGNORE, "ignore %-9s: unsupported opt=0x%02x", "ipv6-hbh", opt->ip6o_type);
                continue;
            case IP6OPT_TYPE_DISCARD:
            case IP6OPT_TYPE_FORCEICMP: // TODO
            case IP6OPT_TYPE_ICMP: // TODO
                TRACE(TR_DROP, "drop %-9s: unsupported opt=0x%02x", "ipv6-hbh", opt->ip6o_type);
                pktbuf->err = true;
                return NULL;
            }
        }
    }
    return hbh;
}

void ipv6_recvfrom_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const struct eui64 *src_eui64)
{
    struct in6_addr addr_linklocal = ipv6_prefix_linklocal;
    const struct ip6_hbh *hbh = NULL;
    const struct icmpv6_hdr *icmp;
    const struct ip6_rthdr *rthdr;
    struct ip6_hdr hdr;
    ssize_t ret;

    pktbuf_pop_head(pktbuf, &hdr, sizeof(hdr));
    TRACE(TR_IPV6, "rx-ipv6 src=%s dst=%s",
          tr_ipv6(hdr.ip6_src.s6_addr), tr_ipv6(hdr.ip6_dst.s6_addr));
    if (FIELD_GET(IPV6_MASK_VERSION, ntohl(hdr.ip6_flow)) != 6) {
        TRACE(TR_DROP, "drop %-9s: invalid IP version", "ipv6");
        return;
    }

    /*
     *     RFC 8200 4. IPv6 Extension Headers
     * Extension headers (except for the Hop-by-Hop Options header) are not
     * processed, inserted, or deleted by any node along a packet's delivery
     * path, until the packet reaches the node [...] identified in the
     * Destination Address field of the IPv6 header.
     */
    if (hdr.ip6_nxt == IPPROTO_HOPOPTS) {
        hbh = ipv6_process_hopopts(ipv6, pktbuf);
        if (!hbh)
            return;
        /*
         * FIXME: Do not drop hop-by-hop header. This should be fine most of
         * the time in Wi-SUN because of:
         *
         *         Wi-SUN FAN 1.1v09 6.2.3.1.7 Unicast Forwarding
         *     The outer header MUST contain a parent’s IPv6 address
         *
         * But this way of doing prevent processing both a hop-by-hop header
         * and a routing header.
         */
        hdr.ip6_plen = htons(ntohs(hdr.ip6_plen) - (1 + hbh->ip6h_len) * 8);
        hdr.ip6_nxt  = hbh->ip6h_nxt;
    }

    ipv6_neigh_aro_refresh(ipv6, src_eui64, &hdr.ip6_src);

    ipv6_addr_conv_iid_eui64(addr_linklocal.s6_addr + 8, ipv6->eui64.u8);
    if (!(IN6_IS_ADDR_MULTICAST(&hdr.ip6_dst) && ipv6_addr_has_mc(ipv6, &hdr.ip6_dst)) &&
        !(IN6_IS_ADDR_LINKLOCAL(&hdr.ip6_dst) && IN6_ARE_ADDR_EQUAL(&hdr.ip6_dst, &addr_linklocal)) &&
        !(IN6_IS_ADDR_UC_GLOBAL(&hdr.ip6_dst) && IN6_ARE_ADDR_EQUAL(&hdr.ip6_dst, &ipv6->dhcp.iaaddr.ipv6))) {
        TRACE(TR_DROP, "drop %-9s: invalid dst=%s", "ipv6", tr_ipv6(hdr.ip6_dst.s6_addr));
        pktbuf->err = true;
        return;
    }

    if (hdr.ip6_nxt == IPPROTO_ROUTING) {
        if (hbh) {
            TRACE(TR_DROP, "drop %-9s: unsupported hop-by-hop + routing header", "ipv6");
            return;
        }
        if (pktbuf_len(pktbuf) < sizeof(struct ip6_rthdr)) {
            TRACE(TR_DROP, "drop %-9s: malformed packet", "ipv6");
            return;
        }
        rthdr = (struct ip6_rthdr *)pktbuf_head(pktbuf);
        if (rthdr->ip6r_segleft) {
            switch (rthdr->ip6r_type) {
            case IPV6_ROUTING_RPL_SRH:
                ret = rpl_srh_process(ipv6, pktbuf, &hdr);
                if (ret < 0)
                    return;
                ipv6_sendto_mac(ipv6, pktbuf, hdr.ip6_nxt, hdr.ip6_hlim, &hdr.ip6_src, &hdr.ip6_dst);
                return;
            default:
                TRACE(TR_DROP, "drop %-9s: unsupported routing header", "ipv6");
                return;
            }
        }

        // HACK: Linux drops IPv6 packets that include a SRH even with 0
        // segments left (unless net.ipv6.conf.[ifname].rpl_seg_enabled is
        // set). According to RFC 8200, routing headers with 0 segments left
        // should always be accepted and ignored, but since Linux does not do
        // so, the SRH must be stripped.
        pktbuf_pop_head(pktbuf, NULL, 8 * (rthdr->ip6r_len + 1));
        hdr.ip6_nxt  = rthdr->ip6r_nxt;
        hdr.ip6_plen = htons(MAX(0, ntohs(hdr.ip6_plen) - 8 * (rthdr->ip6r_len + 1)));
    }

    // TODO: support hob-by-hop options
    switch (hdr.ip6_nxt) {
    case IPPROTO_NONE:
    case IPPROTO_FRAGMENT:
    case IPPROTO_UDP:
    case IPPROTO_TCP:
        break;
    case IPPROTO_IPV6:
        // Forget outer header, and submit inner packet to Linux.
        // NOTE: IPv6 header is reinserted before writing to TUN.
        pktbuf_pop_head(pktbuf, &hdr, sizeof(hdr));
        TRACE(TR_IPV6, "rx-ipv6 src=%s dst=%s (tunnelled)",
              tr_ipv6(hdr.ip6_src.s6_addr), tr_ipv6(hdr.ip6_dst.s6_addr));
        ipv6_neigh_aro_refresh(ipv6, src_eui64, &hdr.ip6_src);
        break;
    case IPPROTO_ICMPV6:
        if (pktbuf_len(pktbuf) < sizeof(*icmp)) {
            TRACE(TR_DROP, "drop %-9s: malformed packet", "icmp");
            return;
        }
        icmp = (struct icmpv6_hdr *)pktbuf_head(pktbuf);
        switch (icmp->type) {
        case ICMP6_DST_UNREACH:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PARAM_PROB:
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
        case ICMPV6_TYPE_RPL:
            break;
        case ND_NEIGHBOR_SOLICIT:
            ipv6_recv_ns(ipv6, pktbuf_head(pktbuf), pktbuf_len(pktbuf), &hdr.ip6_src);
            return;
        // TODO: NA
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported ICMPv6 type %u", "ipv6", icmp->type);
            return;
        }
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported next header %u", "ipv6", hdr.ip6_nxt);
        return;
    }

    if (pktbuf->err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "ipv6");
        return;
    }
    TRACE(TR_TUN, "tx-tun: %zu bytes", pktbuf_len(pktbuf));

    // Reinsert previously parsed IPv6 header.
    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));

    ret = write(ipv6->tun.fd, pktbuf->buf + pktbuf->offset_head, pktbuf_len(pktbuf));
    if (ret < 0)
        WARN("write tun : %m");
    else if (ret != pktbuf_len(pktbuf))
        WARN("write tun: Short write: %zi < %zu", ret, pktbuf_len(pktbuf));
}

/*
 *   RFC 4861 5.2. Conceptual Sending Algorithm
 * The sender performs a longest prefix match against the Prefix List to
 * determine whether the packet's destination is on- or off-link. If the
 * destination is on-link, the next-hop address is the same as the packet's
 * destination address. Otherwise, the sender selects a router from the
 * Default Router List.
 *
 *   Wi-SUN FAN 1.1v08 6.2.3.1.4.1 FFN Neighbor Discovery
 * The Router Solicitation/Router Advertisement exchange described in [RFC6775]
 * is not used. Router discovery is performed using [RFC6550] DIO and DIS
 * messaging.
 *
 * NOTE: Consequently, the prefix and router lists only come from RPL DIOs in
 * this implementation. Also this implementation does not use a destination
 * cache, next-hop determination is thus always performed.
 */
static int ipv6_nxthop(struct ipv6_ctx *ipv6,
                       const struct in6_addr *dst,
                       const struct in6_addr **nxthop)
{
    struct ipv6_neigh *nce;

    //   RFC 4861 5.2. Conceptual Sending Algorithm
    // For multicast packets, the next-hop is always the (multicast)
    // destination address and is considered to be on-link.
    if (IN6_IS_ADDR_MULTICAST(dst)) {
        *nxthop = dst;
        return 0;
    }

    //   RFC 4861 5.1. Conceptual Data Structures
    // The link-local prefix is considered to be on the prefix list with an
    // infinite invalidation timer regardless of whether routers are
    // advertising a prefix for it.
    if (IN6_IS_ADDR_LINKLOCAL(dst)) {
        *nxthop = dst;
        return 0;
    }

    nce = ipv6_neigh_get_from_gua(ipv6, dst);
    if (nce) {
        *nxthop = &nce->gua;
        return 0;
    }

    // Default to preferred RPL parent.
    nce = rpl_neigh_pref_parent(ipv6);
    if (nce) {
        *nxthop = &nce->gua;
        return 0;
    }

    TRACE(TR_TX_ABORT, "tx-abort %-9s: no next hop available", "ipv6");
    return -ENETUNREACH;
}

static void ipv6_addr_resolution(struct ipv6_ctx *ipv6,
                                 const struct in6_addr *nxthop,
                                 struct eui64 *eui64)
{
    struct ipv6_neigh *nce;

    //   RFC 4944 3. Addressing Modes
    // IPv6 level multicast packets MUST be carried as link-layer broadcast
    // frames in IEEE 802.15.4 networks.
    if (IN6_IS_ADDR_MULTICAST(nxthop)) {
        *eui64 = EUI64_BC;
        return;
    }

    //   RFC 6778 5.6. Next-Hop Determination
    // It is assumed that link-local addresses are formed [...] from the
    // EUI-64, and address resolution is not performed.
    if (IN6_IS_ADDR_LINKLOCAL(nxthop)) {
        ipv6_addr_conv_iid_eui64(eui64->u8, nxthop->s6_addr + 8);
        return;
    }

    nce = container_of(nxthop, struct ipv6_neigh, gua);
    *eui64 = nce->eui64;
}

static bool ipv6_is_exthdr(uint8_t ipproto)
{
    switch (ipproto) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MH:
        return true;
    default:
        return false;
    }
}

static bool ipv6_is_pkt_allowed(struct pktbuf *pktbuf)
{
    const struct ip6_ext *ext;
    struct icmpv6_hdr icmp;
    struct ip6_hdr hdr;
    size_t offset_head;
    uint8_t ipproto;

    offset_head = pktbuf->offset_head;
    pktbuf_pop_head(pktbuf, &hdr, sizeof(hdr));
    if (FIELD_GET(IPV6_MASK_VERSION, ntohl(hdr.ip6_flow)) != 6) {
        TRACE(TR_DROP, "drop %-9s: invalid IP version", "tun");
        return false;
    }

    ipproto = hdr.ip6_nxt;
    while (ipv6_is_exthdr(ipproto) && !pktbuf->err) {
        if (ipproto == IPPROTO_FRAGMENT) {
            pktbuf->offset_head = offset_head;
            return true;
        }
        if (pktbuf_len(pktbuf) < sizeof(*ext)) {
            TRACE(TR_DROP, "drop %-9s: malformed extension header", "tun");
            return false;
        }
        ext = (struct ip6_ext *)pktbuf_head(pktbuf);
        ipproto = ext->ip6e_nxt;
        pktbuf_pop_head(pktbuf, NULL, 8 * (ext->ip6e_len + 1));
    }

    switch (ipproto) {
    case IPPROTO_NONE:
    case IPPROTO_UDP:
    case IPPROTO_TCP:
        break;
    case IPPROTO_ICMPV6:
        pktbuf_pop_head(pktbuf, &icmp, sizeof(icmp));
        switch (icmp.type) {
        case ICMP6_DST_UNREACH:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PARAM_PROB:
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
        case ICMPV6_TYPE_RPL:
            break;
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported ICMPv6 type %u", "tun", icmp.type);
            return false;
        }
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported next header %u", "tun", ipproto);
        return false;
    }

    if (pktbuf->err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "tun");
        return false;
    }

    pktbuf->offset_head = offset_head;
    return true;
}

void ipv6_recvfrom_tun(struct ipv6_ctx *ipv6)
{
    const struct in6_addr *nxthop;
    struct pktbuf pktbuf = { };
    const struct ip6_hdr *hdr;
    struct eui64 dst_eui64;
    ssize_t size;

    pktbuf_init(&pktbuf, NULL, 1500);
    size = read(ipv6->tun.fd, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    if (size < 0) {
        WARN("%s read: %m", __func__);
        goto err;
    }
    pktbuf.offset_tail = size;

    TRACE(TR_TUN, "rx-tun: %zd bytes", size);

    if (!ipv6_is_pkt_allowed(&pktbuf))
        goto err;
    hdr = (const struct ip6_hdr *)pktbuf_head(&pktbuf);

    if (ipv6_nxthop(ipv6, &hdr->ip6_dst, &nxthop))
        return;
    ipv6_addr_resolution(ipv6, nxthop, &dst_eui64);

    TRACE(TR_IPV6, "tx-ipv6 src=%s dst=%s",
          tr_ipv6(hdr->ip6_src.s6_addr), tr_ipv6(hdr->ip6_dst.s6_addr));

    lowpan_send(ipv6, &pktbuf, &ipv6->eui64, &dst_eui64);
err:
    pktbuf_free(&pktbuf);
}

int ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf,
                     uint8_t ipproto, uint8_t hlim,
                     const struct in6_addr *src, const struct in6_addr *dst)
{
    const struct in6_addr *nxthop;
    struct eui64 dst_eui64;
    struct ip6_hdr hdr = {
        .ip6_flow = htonl(FIELD_PREP(IPV6_MASK_VERSION, 6)),
        .ip6_plen = htons(pktbuf_len(pktbuf)),
        .ip6_nxt  = ipproto,
        .ip6_hlim = hlim,
        .ip6_src  = *src,
        .ip6_dst  = *dst,
    };
    int ret;

    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));

    TRACE(TR_IPV6, "tx-ipv6 src=%s dst=%s",
          tr_ipv6(hdr.ip6_src.s6_addr), tr_ipv6(hdr.ip6_dst.s6_addr));

    ret = ipv6_nxthop(ipv6, dst, &nxthop);
    if (ret < 0)
        return ret;
    ipv6_addr_resolution(ipv6, nxthop, &dst_eui64);

    // TODO: MPL
    // TODO: RPL Option
    // TODO: IPv6 Tunnel

    return lowpan_send(ipv6, pktbuf, &ipv6->eui64, &dst_eui64);
}
