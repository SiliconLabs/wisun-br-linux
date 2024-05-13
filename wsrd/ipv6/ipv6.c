/*
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
#include <string.h>
#include <unistd.h>

#include "common/bits.h"
#include "common/log.h"
#include "common/netinet_in_extra.h"
#include "common/pktbuf.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ipv6.h"
#include "wsrd/ipv6/ipv6_addr.h"
#include "ipv6.h"

void ipv6_init(struct ipv6_ctx *ipv6, struct timer_ctxt *timer_ctx, const uint8_t eui64[8])
{
    tun_init(&ipv6->tun, true);
    tun_sysctl_set("/proc/sys/net/ipv6/conf", ipv6->tun.ifname, "accept_ra", '0');

    memcpy(ipv6->eui64, eui64, 8);
    memcpy(ipv6->addr_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
    ipv6_addr_conv_iid_eui64(ipv6->addr_linklocal.s6_addr + 8, eui64);
    tun_addr_add(&ipv6->tun, &ipv6->addr_linklocal, 64);

    timer_group_init(timer_ctx, &ipv6->timer_group);

    // FIXME: BaseReachableTime and RetransTimer can be overritten by Router
    // Advertisements in normal NDP, but Wi-SUN disables RAs without providing
    // any sensible default values.

    // RFC 4861 10. Protocol Constants
    if (!ipv6->reach_base_ms)
        ipv6->reach_base_ms  = 30000; // REACHABLE_TIME  30,000 milliseconds
    if (!ipv6->probe_delay_ms)
        ipv6->probe_delay_ms =  1000; // RETRANS_TIMER    1,000 milliseconds

    rpl_start(ipv6);
}

void ipv6_recvfrom_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf)
{
    struct icmp6_hdr icmp;
    struct ip6_hdr hdr;
    ssize_t ret;

    pktbuf_pop_head(pktbuf, &hdr, sizeof(hdr));

    if (FIELD_GET(IPV6_MASK_VERSION, ntohl(hdr.ip6_flow)) != 6) {
        TRACE(TR_DROP, "drop %-9s: invalid IP version", "ipv6");
        return;
    }
    if (!(IN6_IS_ADDR_MULTICAST(&hdr.ip6_dst) && ipv6_addr_has_mc(ipv6, &hdr.ip6_dst)) &&
        !(IN6_IS_ADDR_LINKLOCAL(&hdr.ip6_dst) && IN6_ARE_ADDR_EQUAL(&hdr.ip6_dst, &ipv6->addr_linklocal)) &&
        !(IN6_IS_ADDR_UC_GLOBAL(&hdr.ip6_dst) && IN6_ARE_ADDR_EQUAL(&hdr.ip6_dst, &ipv6->addr_uc_global))) {
        TRACE(TR_DROP, "drop %-9s: invalid dst=%s", "ipv6", tr_ipv6(hdr.ip6_dst.s6_addr));
        pktbuf->err = true;
        return;
    }

    // TODO: support extension headers, IPv6 tunnels
    switch (hdr.ip6_nxt) {
    case IPPROTO_UDP:
    case IPPROTO_TCP:
        break;
    case IPPROTO_ICMPV6:
        pktbuf_pop_head(pktbuf, &icmp, sizeof(icmp));
        switch (icmp.icmp6_type) {
        case ICMP6_DST_UNREACH:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PARAM_PROB:
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
        case ICMPV6_TYPE_RPL:
            break;
        // TODO: NS/NA
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported ICMPv6 type %u", "ipv6", icmp.icmp6_type);
            return;
        }
        pktbuf_push_head(pktbuf, &icmp, sizeof(icmp));
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported next header %u", "ipv6", hdr.ip6_nxt);
        return;
    }

    if (pktbuf->err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "ipv6");
        return;
    }
    TRACE(TR_IPV6, "rx-ipv6 src=%s dst=%s",
          tr_ipv6(hdr.ip6_src.s6_addr), tr_ipv6(hdr.ip6_dst.s6_addr));

    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));

    ret = write(ipv6->tun.fd, pktbuf->buf + pktbuf->offset_head, pktbuf_len(pktbuf));
    if (ret < 0)
        WARN("write tun : %m");
    else if (ret != pktbuf_len(pktbuf))
        WARN("write tun: Short write: %zi < %zu", ret, pktbuf_len(pktbuf));
}
