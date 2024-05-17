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
#include <netinet/icmp6.h>

#include "common/bits.h"
#include "common/ipv6_cksum.h"
#include "common/memutils.h"
#include "common/named_values.h"
#include "common/pktbuf.h"
#include "common/rand.h"
#include "common/specs/icmpv6.h"
#include "wsrd/ipv6/ipv6.h"
#include "wsrd/ipv6/ndp.h"
#include "wsrd/ipv6/ndp_pkt.h"
#include "wsrd/ipv6/rpl.h"

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

void ipv6_nud_probe(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    // MAX_UNICAST_SOLICIT = 3
    if (neigh->nud_probe_count >= 3) {
        //   RFC 4861 7.3.3. Node Behavior
        // If no response is received after waiting RetransTimer milliseconds
        // after sending the MAX_UNICAST_SOLICIT solicitations, retransmissions
        // cease and the entry SHOULD be deleted.
        ipv6_neigh_del(ipv6, neigh);
    } else {
        // TODO: send unicast NS
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
          tr_ipv6(neigh->ipv6_addr.s6_addr), tr_nud_state(neigh->nud_state));
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

struct ipv6_neigh *ipv6_neigh_get(struct ipv6_ctx *ipv6,
                                  const struct in6_addr *ipv6_addr)
{
    struct ipv6_neigh *neigh;

    SLIST_FOREACH(neigh, &ipv6->neigh_cache, link)
        if (IN6_ARE_ADDR_EQUAL(&neigh->ipv6_addr, ipv6_addr))
            return neigh;
    return NULL;
}

struct ipv6_neigh *ipv6_neigh_add(struct ipv6_ctx *ipv6,
                                  const struct in6_addr *ipv6_addr,
                                  const uint8_t eui64[64])
{
    struct ipv6_neigh *neigh = zalloc(sizeof(*neigh));

    SLIST_INSERT_HEAD(&ipv6->neigh_cache, neigh, link);
    neigh->ipv6_addr = *ipv6_addr;
    memcpy(neigh->eui64, eui64, 8);
    neigh->nud_timer.callback = ipv6_nud_expire;
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 add %s eui64=%s",
          tr_ipv6(neigh->ipv6_addr.s6_addr), tr_eui64(neigh->eui64));
    ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_REACHABLE);
    return neigh;
}

void ipv6_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    timer_stop(&ipv6->timer_group, &neigh->nud_timer);
    SLIST_REMOVE(&ipv6->neigh_cache, neigh, ipv6_neigh, link);
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 del %s eui64=%s",
          tr_ipv6(neigh->ipv6_addr.s6_addr), tr_eui64(neigh->eui64));
    if (neigh->rpl_neigh)
        rpl_neigh_del(ipv6, neigh);
    free(neigh);
}

void ipv6_send_ns_aro(struct ipv6_ctx *ipv6, struct in6_addr *dst)
{
    struct nd_neighbor_solicit ns = {
        .nd_ns_type   = ND_NEIGHBOR_SOLICIT,
        .nd_ns_target = *dst,
    };
    struct ndp_opt_earo aro = {
        .type = ICMPV6_OPT_ADDR_REGISTRATION,
        .len  = sizeof(aro) / 8,
        .lifetime_minutes = UINT16_MAX,
    };
    struct pktbuf pktbuf = { };

    BUG_ON(IN6_IS_ADDR_UNSPECIFIED(&ipv6->addr_uc_global));

    pktbuf_push_tail(&pktbuf, &ns, sizeof(ns));
    memcpy(aro.eui64, ipv6->eui64, 8);
    pktbuf_push_tail(&pktbuf, &aro, sizeof(aro));

    ns.nd_ns_cksum = ipv6_cksum(&ipv6->addr_uc_global, dst, IPPROTO_ICMPV6,
                                pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    memcpy(pktbuf_head(&pktbuf) + offsetof(struct nd_neighbor_solicit, nd_ns_cksum),
           &ns.nd_ns_cksum, sizeof(ns.nd_ns_cksum));

    //   RFC 6775 4.1. Address Registration Option
    // [...] the address that is to be registered MUST be the IPv6 source
    // address of the NS message.
    TRACE(TR_ICMP, "tx-icmp ns(aro) dst=%s", tr_ipv6(dst->s6_addr));
    // TODO: send to IPv6
    // TODO: handle confirmation (ARO failure and link-layer ACK)
    pktbuf_free(&pktbuf);
}
