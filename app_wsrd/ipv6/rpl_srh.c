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
#include <linux/rpl.h>
#include <errno.h>

#include "app_wsrd/ipv6/ndp.h"
#include "app_wsrd/ipv6/ipv6.h"
#include "common/specs/ipv6.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/string_extra.h"

#include "rpl_srh.h"

static void rpl_srh_decmpr(const struct ipv6_rpl_sr_hdr *srh,
                           const struct in6_addr *dst,
                           struct in6_addr *segaddr, int n)
{
    BUG_ON(n <= 0);
    for (int i = 0; i < n - 1; i++) {
        memcpy(segaddr[i].s6_addr, dst, srh->cmpri);
        memcpy(segaddr[i].s6_addr + srh->cmpri,
               srh->rpl_segdata + i * (16 - srh->cmpri),
               16 - srh->cmpri);
    }
    memcpy(segaddr[n - 1].s6_addr, dst, srh->cmpre);
    memcpy(segaddr[n - 1].s6_addr + srh->cmpre,
           srh->rpl_segdata + (n - 1) * (16 - srh->cmpri),
           16 - srh->cmpre);
}

static int rpl_srh_push(struct pktbuf *pktbuf,
                        const struct in6_addr *dst,
                        const struct in6_addr *segaddr, int n,
                        uint8_t nxthdr, uint8_t seg_left)
{
    struct ipv6_rpl_sr_hdr *srh;
    int cmpri, cmpre, pad, len;

    BUG_ON(n <= 0);
    cmpri = 15;
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < cmpri; j++)
            if (segaddr[i].s6_addr[j] != dst->s6_addr[j])
                cmpri = j;
    cmpre = 15;
    for (int i = 0; i < cmpre; i++)
        if (segaddr[n - 1].s6_addr[i] != dst->s6_addr[i])
            cmpre = i;

    len = sizeof(struct ipv6_rpl_sr_hdr) + (n - 1) * (16 - cmpri) + (16 - cmpre);
    pad = roundup(len, 8) - len;

    srh = pktbuf_push_head(pktbuf, NULL, len + pad);
    srh->nexthdr       = nxthdr;
    srh->hdrlen        = (len + pad) / 8 - 1;
    srh->type          = IPV6_ROUTING_RPL_SRH;
    srh->segments_left = seg_left;
    srh->cmpri         = cmpri;
    srh->cmpre         = cmpre;
    srh->pad           = pad;
    for (int i = 0; i < n - 1; i++)
        memcpy(srh->rpl_segdata + i * (16 - srh->cmpri),
               segaddr[i].s6_addr + srh->cmpri,
               16 - srh->cmpri);
    memcpy(srh->rpl_segdata + (n - 1) * (16 - srh->cmpri),
           segaddr[n - 1].s6_addr + srh->cmpre,
           16 - srh->cmpre);
    return len + pad;
}

// RFC 6554 4.2. Processing Source Routing Headers
int rpl_srh_process(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, struct ip6_hdr *hdr)
{
    struct ipv6_rpl_sr_hdr *srh;
    struct in6_addr *segaddr;
    struct ipv6_neigh *nce;
    int n, i, len;

    srh = (struct ipv6_rpl_sr_hdr *)pktbuf_head(pktbuf);
    BUG_ON(pktbuf_len(pktbuf) < sizeof(struct ip6_rthdr));
    BUG_ON(srh->type != IPV6_ROUTING_RPL_SRH);
    BUG_ON(!srh->segments_left);
    pktbuf_pop_head(pktbuf, NULL, (1 + srh->hdrlen) * 8);
    if (pktbuf->err)
        return -EINVAL;

    /* compute n, the number of addresses in the Routing header */
    n = ((srh->hdrlen * 8 - srh->pad - (16 - srh->cmpre)) / (16 - srh->cmpri)) + 1;

    /* if Segments Left is greater than n */
    if (srh->segments_left > n) {
        // TODO: send ICMP Parameter Problem, Code 0
        TRACE(TR_DROP, "drop %-9s: invalid routing header", "rpl-srh");
        return -EINVAL;
    }

    segaddr = xalloc(n * sizeof(struct in6_addr));
    rpl_srh_decmpr(srh, &hdr->ip6_dst, segaddr, n);

    /* decrement Segments Left by 1 */
    srh->segments_left--;

    /*
     * compute i, the index of the next address to be visited in the address
     * vector, by subtracting Segments Left from n
     */
    i = n - srh->segments_left - 1; // NOTE: RFC uses 1-based indexing

    /* if Address[i] or the IPv6 Destination Address is multicast */
    if (IN6_IS_ADDR_MULTICAST(&segaddr[i]) || IN6_IS_ADDR_MULTICAST(&hdr->ip6_dst)) {
        TRACE(TR_DROP, "drop %-9s: invalid multicast", "rpl-srh");
        free(segaddr);
        return -EINVAL;
    }

    /*
     * if 2 or more entries in Address[1..n] are assigned to local interface
     * and are separated by at least one address not assigned to local
     * interface
     */
    for (int j = 0; j < n; j++) {
        // NOTE: only check if the GUA appears more than once.
        if (IN6_ARE_ADDR_EQUAL(&segaddr[j], &ipv6->dhcp.iaaddr.ipv6)) {
            // TODO: send an ICMP Parameter Problem (Code 0)
            TRACE(TR_DROP, "drop %-9s: loop seg[%i] assigned to self", "rpl-srh", j);
            free(segaddr);
            return -EINVAL;
        }
    }

    /* swap the IPv6 Destination Address and Address[i] */
    memswap(&hdr->ip6_dst, &segaddr[i], 16);
    len = rpl_srh_push(pktbuf, &hdr->ip6_dst, segaddr, n, srh->nexthdr, srh->segments_left);
    hdr->ip6_plen = htons(ntohs(hdr->ip6_plen) - (1 + srh->hdrlen) * 8 + len);
    free(segaddr);

    /* if the IPv6 Hop Limit is less than or equal to 1 */
    if (hdr->ip6_hlim <= 1) {
        // TODO: send ICMP Time Exceeded -- Hop Limit Exceeded
        TRACE(TR_DROP, "drop %-9s: hop limit exceeded", "rpl-srh");
        return -ETIMEDOUT;
    }

    /* decrement the Hop Limit by 1 */
    hdr->ip6_hlim--;

    /*
     * if the IPv6 Destination Address is not on-link, a router MUST drop the
     * datagram and SHOULD send an ICMP Destination Unreachable (ICMPv6 Type 1)
     * message with ICMPv6 Code set to 7 to the packet's Source Address.
     */
    nce = ipv6_neigh_get_from_gua(ipv6, &hdr->ip6_dst);
    if (!nce) {
        TRACE(TR_DROP, "drop %-9s: dst=%s not on-link",
              "rpl-srh", tr_ipv6(hdr->ip6_dst.s6_addr));
        // TODO: send ICMP Destination Unreachable, Code 7
        return -EHOSTUNREACH;
    }

    /*
     * resubmit the packet to the IPv6 module for transmission to the new
     * destination
     */
    return 0;
}
