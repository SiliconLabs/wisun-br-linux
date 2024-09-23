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
#include <netinet/icmp6.h>

#include "common/ipv6/ipv6_cksum.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/bits.h"
#include "common/memutils.h"
#include "common/named_values.h"
#include "common/pktbuf.h"
#include "common/rand.h"
#include "common/sys_queue_extra.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ndp.h"
#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/ndp.h"
#include "app_wsrd/ipv6/ndp_pkt.h"
#include "app_wsrd/ipv6/rpl.h"

#include "ndp.h"

static const char *tr_nud_state(int state)
{
    static const struct name_value table[] = {
#define ENTRY(name) { #name, IPV6_NUD_##name }
        ENTRY(INCOMPLETE),
        ENTRY(REACHABLE),
        ENTRY(STALE),
        ENTRY(DELAY),
        ENTRY(PROBE),
#undef ENTRY
        { }
    };

    return val_to_str(state, table, "UNKNOWN");
}

static void ipv6_send_ns(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    const bool has_gua = !IN6_IS_ADDR_UNSPECIFIED(&ipv6->dhcp.iaaddr.ipv6);
    struct nd_neighbor_solicit ns;
    struct pktbuf pktbuf = { };
    struct in6_addr src, dst;
    struct ndp_opt_earo aro;

    if (neigh->ns_handle >= 0) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: ns already in progress for %s",
              has_gua ? "ns(aro)" : "ns", tr_ipv6(neigh->eui64));
        return;
    }

    if (has_gua) {
        //   RFC 6775 4.1. Address Registration Option
        // [...] the address that is to be registered MUST be the IPv6 source
        // address of the NS message.
        src = ipv6->dhcp.iaaddr.ipv6;
        dst = neigh->gua;
    } else {
        src = ipv6_prefix_linklocal;
        ipv6_addr_conv_iid_eui64(src.s6_addr + 8, ipv6->eui64);
        dst = ipv6_prefix_linklocal;
        ipv6_addr_conv_iid_eui64(dst.s6_addr + 8, neigh->eui64);
    }

    memset(&ns, 0, sizeof(ns));
    ns.nd_ns_type   = ND_NEIGHBOR_SOLICIT;
    ns.nd_ns_target = dst;
    pktbuf_push_tail(&pktbuf, &ns, sizeof(ns));

    // TODO: Figure out how NUD works with children.
    if (has_gua && neigh->rpl && neigh->rpl->is_parent) {
        memset(&aro, 0, sizeof(aro));
        aro.type = NDP_OPT_ARO;
        aro.len  = sizeof(aro) / 8;
        aro.lifetime_minutes = UINT16_MAX;
        memcpy(aro.eui64, ipv6->eui64, 8);
        pktbuf_push_tail(&pktbuf, &aro, sizeof(aro));
    }

    ns.nd_ns_cksum = ipv6_cksum(&src, &dst, IPPROTO_ICMPV6,
                                pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    memcpy(pktbuf_head(&pktbuf) + offsetof(struct nd_neighbor_solicit, nd_ns_cksum),
           &ns.nd_ns_cksum, sizeof(ns.nd_ns_cksum));

    TRACE(TR_ICMP, "tx-icmp %-9s dst=%s", has_gua ? "ns(aro)" : "ns", tr_ipv6(dst.s6_addr));
    neigh->ns_handle = ipv6_sendto_mac(ipv6, &pktbuf, IPPROTO_ICMPV6, 255, &src, &dst);
    pktbuf_free(&pktbuf);
}

void ipv6_nud_confirm_ns(struct ipv6_ctx *ipv6, int handle, bool success)
{
    struct ipv6_neigh *neigh;

    BUG_ON(handle < 0);
    SLIST_FOREACH(neigh, &ipv6->neigh_cache, link)
        if (neigh->ns_handle == handle)
            break;
    if (!neigh)
        return;
    neigh->ns_handle = -1;
    if (success)
        ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_REACHABLE);
}

static void ipv6_nud_probe(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    // MAX_UNICAST_SOLICIT = 3
    if (neigh->nud_probe_count >= 3) {
        //   RFC 4861 7.3.3. Node Behavior
        // If no response is received after waiting RetransTimer milliseconds
        // after sending the MAX_UNICAST_SOLICIT solicitations, retransmissions
        // cease and the entry SHOULD be deleted.
        ipv6_neigh_del(ipv6, neigh);
    } else {
        ipv6_send_ns(ipv6, neigh);
        neigh->nud_probe_count++;
        timer_start_rel(&ipv6->timer_group, &neigh->nud_timer, ipv6->probe_delay_ms);
    }
}

static void ipv6_nud_expire(struct timer_group *group, struct timer_entry *timer)
{
    struct ipv6_neigh *neigh = container_of(timer, struct ipv6_neigh, nud_timer);
    struct ipv6_ctx *ipv6 = container_of(group, struct ipv6_ctx, timer_group);

    switch (neigh->nud_state) {
    case IPV6_NUD_REACHABLE:
        ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_STALE);
        break;
    case IPV6_NUD_DELAY:
        ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_PROBE);
        break;
    case IPV6_NUD_PROBE:
        ipv6_nud_probe(ipv6, neigh);
        break;
    default:
        BUG();
    }
}

void ipv6_nud_set_state(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh, int state)
{
    uint64_t reach_ms;

    timer_stop(&ipv6->timer_group, &neigh->nud_timer);
    neigh->nud_state = state;
    neigh->nud_probe_count = 0;
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 set %s %s",
          tr_ipv6(neigh->gua.s6_addr), tr_nud_state(neigh->nud_state));
    switch (state) {
    case IPV6_NUD_REACHABLE:
        // MIN_RANDOM_FACTOR = 0.5, MAX_RANDOM_FACTOR = 1.5
        reach_ms = randf_range(0.5 * ipv6->reach_base_ms,
                               1.5 * ipv6->reach_base_ms);
        timer_start_rel(&ipv6->timer_group, &neigh->nud_timer, reach_ms);
        break;
    case IPV6_NUD_STALE:
        break;
    case IPV6_NUD_DELAY:
        // DELAY_FIRST_PROBE_TIME = 5s
        timer_start_rel(&ipv6->timer_group, &neigh->nud_timer, 5 * 1000);
        break;
    case IPV6_NUD_PROBE:
        ipv6_nud_probe(ipv6, neigh);
        break;
    default:
        BUG();
    }
}

struct ipv6_neigh *ipv6_neigh_get_from_gua(const struct ipv6_ctx *ipv6,
                                           const struct in6_addr *gua)
{
    struct ipv6_neigh *neigh;

    return SLIST_FIND(neigh, &ipv6->neigh_cache, link,
                      IN6_ARE_ADDR_EQUAL(&neigh->gua, gua));
}

struct ipv6_neigh *ipv6_neigh_get_from_eui64(const struct ipv6_ctx *ipv6,
                                             const uint8_t eui64[8])
{
    struct ipv6_neigh *neigh;

    return SLIST_FIND(neigh, &ipv6->neigh_cache, link,
                      !memcmp(neigh->eui64, eui64, 8));
}

struct ipv6_neigh *ipv6_neigh_fetch(struct ipv6_ctx *ipv6,
                                    const struct in6_addr *gua,
                                    const uint8_t eui64[8])
{
    struct ipv6_neigh *neigh;

    neigh = ipv6_neigh_get_from_eui64(ipv6, eui64);
    if (neigh) {
        if (IN6_ARE_ADDR_EQUAL(&neigh->gua, gua))
            return neigh;
        WARN("neigh-ipv6 overwrite");
        ipv6_neigh_del(ipv6, neigh);
    }
    neigh = ipv6_neigh_get_from_gua(ipv6, gua);
    if (neigh) {
        if (!memcmp(neigh->eui64, eui64, 8))
            return neigh;
        WARN("neigh-ipv6 overwrite");
        ipv6_neigh_del(ipv6, neigh);
    }

    neigh = zalloc(sizeof(*neigh));
    SLIST_INSERT_HEAD(&ipv6->neigh_cache, neigh, link);
    neigh->gua = *gua;
    memcpy(neigh->eui64, eui64, 8);
    neigh->nud_timer.callback = ipv6_nud_expire;
    neigh->ns_handle = -1;
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 add %s eui64=%s",
          tr_ipv6(neigh->gua.s6_addr), tr_eui64(neigh->eui64));
    ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_REACHABLE);
    return neigh;
}

void ipv6_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    timer_stop(&ipv6->timer_group, &neigh->nud_timer);
    SLIST_REMOVE(&ipv6->neigh_cache, neigh, ipv6_neigh, link);
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 del %s eui64=%s",
          tr_ipv6(neigh->gua.s6_addr), tr_eui64(neigh->eui64));
    if (neigh->rpl)
        rpl_neigh_del(ipv6, neigh);
    free(neigh);
}
