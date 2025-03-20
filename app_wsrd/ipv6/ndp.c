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
#include <netinet/icmp6.h>
#include <errno.h>

#include "common/ipv6/ipv6_cksum.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/bits.h"
#include "common/iobuf.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/named_values.h"
#include "common/netinet_in_extra.h"
#include "common/pktbuf.h"
#include "common/rand.h"
#include "common/sys_queue_extra.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ndp.h"
#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/ndp.h"
#include "app_wsrd/ipv6/rpl.h"
#include "app_wsrd/app/join_state.h"

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
        ENTRY(UNREACHABLE),
#undef ENTRY
        { }
    };

    return val_to_str(state, table, "UNKNOWN");
}

static void ndp_opt_push(struct pktbuf *pktbuf, uint8_t type,
                         const void *buf, size_t buf_len)
{
    struct nd_opt_hdr opt = {
        .nd_opt_type = type,
        .nd_opt_len  = (sizeof(opt) + buf_len) / 8,
    };

    BUG_ON((sizeof(opt) + buf_len) % 8);
    pktbuf_push_tail(pktbuf, &opt, sizeof(opt));
    pktbuf_push_tail(pktbuf, buf, buf_len);
}

int ipv6_send_ns_aro(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh, uint16_t lifetime_minutes)
{
    struct nd_neighbor_solicit *ns;
    struct pktbuf pktbuf = { };
    struct in6_addr src, dst;
    struct ndp_opt_earo aro;
    int handle;

    if (neigh->ns_handle >= 0) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: ns already in progress for %s",
              "ns(aro)", tr_ipv6(neigh->gua.s6_addr));
        return neigh->ns_handle;
    }

    BUG_ON(IN6_IS_ADDR_UNSPECIFIED(&ipv6->dhcp.iaaddr.ipv6));

    //   RFC 6775 4.1. Address Registration Option
    // [...] the address that is to be registered MUST be the IPv6 source
    // address of the NS message.
    src = ipv6->dhcp.iaaddr.ipv6;
    dst = neigh->gua;

    ns = pktbuf_push_tail(&pktbuf, NULL, sizeof(*ns));
    ns->nd_ns_type   = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_target = dst;

    memset(&aro, 0, sizeof(aro));
    aro.lifetime_minutes = UINT16_MAX;
    aro.eui64 = ipv6->eui64.be64;
    ndp_opt_push(&pktbuf, NDP_OPT_ARO, &aro, sizeof(aro));

    ns = (struct nd_neighbor_solicit *)pktbuf_head(&pktbuf);
    ns->nd_ns_cksum = ipv6_cksum(&src, &dst, IPPROTO_ICMPV6,
                                 pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));

    TRACE(TR_ICMP, "tx-icmp %-9s dst=%s lifetime=%ds", "ns(aro)", tr_ipv6(dst.s6_addr), lifetime_minutes * 60);
    handle = ipv6_sendto_mac(ipv6, &pktbuf, IPPROTO_ICMPV6, 255, &src, &dst);
    pktbuf_free(&pktbuf);
    return handle;
}

static int ipv6_send_ns(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    struct nd_neighbor_solicit *ns;
    struct pktbuf pktbuf = { };
    struct in6_addr src, dst;
    int handle;

    if (neigh->ns_handle >= 0) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: ns already in progress for %s",
              "ns", tr_ipv6(neigh->gua.s6_addr));
        return neigh->ns_handle;
    }

    src = ipv6_prefix_linklocal;
    ipv6_addr_conv_iid_eui64(src.s6_addr + 8, ipv6->eui64.u8);
    dst = ipv6_prefix_linklocal;
    ipv6_addr_conv_iid_eui64(dst.s6_addr + 8, neigh->eui64.u8);

    ns = pktbuf_push_tail(&pktbuf, NULL, sizeof(*ns));
    ns->nd_ns_type   = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_target = dst;
    ns->nd_ns_cksum  = ipv6_cksum(&src, &dst, IPPROTO_ICMPV6,
                                  pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));

    TRACE(TR_ICMP, "tx-icmp %-9s dst=%s", "ns", tr_ipv6(dst.s6_addr));
    handle = ipv6_sendto_mac(ipv6, &pktbuf, IPPROTO_ICMPV6, 255, &src, &dst);
    pktbuf_free(&pktbuf);
    return handle;
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
    if (success) {
        ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_REACHABLE);
        /*
         *   RFC 6775 5.5. Registration and Neighbor Unreachability Detection
         * Even if the host doesn't have data to send, but is expecting others
         * to try to send packets to the host, the host needs to maintain its
         * NCEs in the routers. This is done by sending NS messages with an ARO
         * to the router well in advance of the Registration Lifetime expiring.
         *
         * Note: we give a 5 minute window for retries.
         * We assume that if the neighbor is not our parent anymore that a
         * NS(ARO) lifetime 0 has already been sent.
         */
        if (neigh->rpl && neigh->rpl->is_parent) {
            WARN_ON(!timer_stopped(&neigh->aro_lifetime));
            timer_start_rel(&ipv6->timer_group, &neigh->own_aro_timer,
                            ipv6->aro_lifetime_ms - 5 * 60 * 1000);
        }
        // TODO: do not call for registration refresh
        if (neigh->rpl && neigh->rpl->is_parent)
            rpl_start_dao(ipv6);
    }
}

static void ipv6_nud_probe(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    // MAX_UNICAST_SOLICIT = 3
    if (neigh->nud_probe_count >= 3) {
        /*
         *   RFC 4861 7.3.3. Node Behavior
         * If no response is received after waiting RetransTimer milliseconds
         * after sending the MAX_UNICAST_SOLICIT solicitations, retransmissions
         * cease and the entry SHOULD be deleted.
         *   RFC 6775 6. Router Behavior for 6LRs and 6LBRs
         * [...] if NUD on the router determines that the host is UNREACHABLE
         * (based on the logic in [RFC4861]), the NCE SHOULD NOT be deleted but
         * rather retained until the Registration Lifetime expires.
         */
        if (timer_stopped(&neigh->aro_lifetime))
            ipv6_neigh_del(ipv6, neigh);
        else
            ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_UNREACHABLE);
    } else {
        /*
         *   RFC 6775 4.1. Address Registration Option
         * [...]
         * Thus, it can be included in the unicast NS messages that a
         * host sends as part of NUD to determine that it can still reach
         * a default router.
         */
        if (neigh->rpl && neigh->rpl->is_parent && !IN6_IS_ADDR_UNSPECIFIED(&ipv6->dhcp.iaaddr.ipv6))
            neigh->ns_handle = ipv6_send_ns_aro(ipv6, neigh, ipv6->aro_lifetime_ms / 1000 / 60);
        else
            neigh->ns_handle = ipv6_send_ns(ipv6, neigh);
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
    case IPV6_NUD_UNREACHABLE:
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

static void ipv6_neigh_aro_expire(struct timer_group *group, struct timer_entry *timer)
{
    struct ipv6_neigh *nce = container_of(timer, struct ipv6_neigh, aro_lifetime);
    struct ipv6_ctx *ipv6 = container_of(group, struct ipv6_ctx, timer_group);

    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 aro %s expire", tr_ipv6(nce->gua.s6_addr));
    // NOTE: Keep neighbor if it has associated RPL data.
    if (nce->nud_state == IPV6_NUD_UNREACHABLE || !nce->rpl)
        ipv6_neigh_del(ipv6, nce);
}

static void ipv6_own_aro_refresh(struct timer_group *group, struct timer_entry *timer)
{
    struct ipv6_neigh *neigh = container_of(timer, struct ipv6_neigh, own_aro_timer);
    struct ipv6_ctx *ipv6 = container_of(group, struct ipv6_ctx, timer_group);

    BUG_ON(!neigh->rpl || !neigh->rpl->is_parent);
    ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_PROBE);
}

static int ipv6_recv_ns_aro(struct ipv6_ctx *ipv6,
                            const void *buf, size_t buf_len,
                            const struct in6_addr *src)
{
    const struct ndp_opt_earo *aro;
    struct ipv6_neigh *nce;
    struct eui64 eui64;

    if (buf_len != sizeof(struct ndp_opt_earo)) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "ns(aro)");
        return -EINVAL;
    }
    aro = buf;

    /*
     *   RFC 6775 4.1. Address Registration Option
     * [...] the address that is to be registered MUST be the IPv6 source
     * address of the NS message.
     */
    if (!IN6_IS_ADDR_UC_GLOBAL(src)) {
        TRACE(TR_DROP, "drop %-9s: unsupported src=%s",
              "ns(aro)", tr_ipv6(src->s6_addr));
        return -ENOTSUP;
    }

    /*
     *   RFC 6775 6.5.3. Updating the Neighbor Cache
     * If the ARO did not result in a duplicate address being detected [...]
     * the router creates (if it didn't exist) or updates (otherwise) an NCE
     * for the IPv6 source address of the NS.
     */
    eui64.be64 = aro->eui64;
    nce = ipv6_neigh_fetch(ipv6, src, &eui64);
    WARN_ON(!timer_stopped(&nce->own_aro_timer));
    timer_start_rel(&ipv6->timer_group, &nce->aro_lifetime,
                    (uint64_t)ntohs(aro->lifetime_minutes) * 60 * 1000);
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 aro %s set lifetime=%umin",
          tr_ipv6(src->s6_addr), (int)(timer_duration_ms(&nce->aro_lifetime) / 1000 / 60));
    return 0;
}

void ipv6_neigh_aro_refresh(struct ipv6_ctx *ipv6,
                            const struct eui64 *src_eui64,
                            const struct in6_addr *src)
{
    struct ipv6_neigh *nce;

    nce = ipv6_neigh_get_from_eui64(ipv6, src_eui64);
    if (!nce || !IN6_ARE_ADDR_EQUAL(&nce->gua, src))
        return;
    if (timer_stopped(&nce->aro_lifetime))
        return;
    timer_start_rel(&ipv6->timer_group, &nce->aro_lifetime,
                    timer_duration_ms(&nce->aro_lifetime));
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 aro %s set lifetime=%umin (refresh)",
          tr_ipv6(src->s6_addr), (int)(timer_duration_ms(&nce->aro_lifetime) / 1000 / 60));
}

void ipv6_recv_ns(struct ipv6_ctx *ipv6,
                  const void *buf, size_t buf_len,
                  const struct in6_addr *src)
{
    struct in6_addr addr_linklocal = ipv6_prefix_linklocal;
    const struct nd_neighbor_solicit *ns;
    const struct nd_opt_hdr *opt;
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };

    TRACE(TR_ICMP, "rx-icmp %-9s src=%s", "ns", tr_ipv6(src->s6_addr));

    // RFC 4861 7.1.1. Validation of Neighbor Solicitations
    ns = iobuf_pop_data_ptr(&iobuf, sizeof(struct nd_neighbor_solicit));
    if (!ns || ns->nd_ns_code != 0 || IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target)) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "ns");
        return;
    }

    // RFC 4861 7.2.3. Receipt of Neighbor Solicitations
    ipv6_addr_conv_iid_eui64(addr_linklocal.s6_addr + 8, ipv6->eui64.u8);
    if (!IN6_ARE_ADDR_EQUAL(&ns->nd_ns_target, &ipv6->dhcp.iaaddr.ipv6) &&
        !IN6_ARE_ADDR_EQUAL(&ns->nd_ns_target, &addr_linklocal)) {
        TRACE(TR_DROP, "drop %-9s: invalid target=%s", "ns", tr_ipv6(ns->nd_ns_target.s6_addr));
        return;
    }

    while (iobuf_remaining_size(&iobuf)) {
        opt = iobuf_pop_data_ptr(&iobuf, sizeof(struct nd_opt_hdr));
        if (!opt || !opt->nd_opt_len ||
            !iobuf_pop_data_ptr(&iobuf, opt->nd_opt_len * 8 - sizeof(struct nd_opt_hdr))) {
            TRACE(TR_DROP, "drop %-9s: malformed packet", "ns");
            return;
        }
        switch (opt->nd_opt_type) {
        case NDP_OPT_ARO:
            ipv6_recv_ns_aro(ipv6, opt + 1, opt->nd_opt_len * 8 - sizeof(struct nd_opt_hdr), src);
            break;
        /*
         *   Wi-SUN FAN 1.1v09 6.2.3.1.4.1 FFN Neighbor Discovery
         * An FFN MUST NOT implement Neighbor Solicitation with the Source
         * Link-Layer Address Option (SLLAO)
         */
        case ND_OPT_SOURCE_LINKADDR:
        default:
            TRACE(TR_IGNORE, "ignore %-9s: unsupported opt=%u", "ns", opt->nd_opt_type);
            continue;
        }
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
                                             const struct eui64 *eui64)
{
    struct ipv6_neigh *neigh;

    return SLIST_FIND(neigh, &ipv6->neigh_cache, link,
                      eui64_eq(&neigh->eui64, eui64));
}

struct ipv6_neigh *ipv6_neigh_fetch(struct ipv6_ctx *ipv6,
                                    const struct in6_addr *gua,
                                    const struct eui64 *eui64)
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
        if (eui64_eq(&neigh->eui64, eui64))
            return neigh;
        WARN("neigh-ipv6 overwrite");
        ipv6_neigh_del(ipv6, neigh);
    }

    neigh = zalloc(sizeof(*neigh));
    SLIST_INSERT_HEAD(&ipv6->neigh_cache, neigh, link);
    neigh->gua = *gua;
    neigh->eui64 = *eui64;
    neigh->nud_timer.callback = ipv6_nud_expire;
    neigh->aro_lifetime.callback = ipv6_neigh_aro_expire;
    neigh->own_aro_timer.callback = ipv6_own_aro_refresh;
    neigh->ns_handle = -1;
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 add %s eui64=%s",
          tr_ipv6(neigh->gua.s6_addr), tr_eui64(neigh->eui64.u8));
    ipv6_nud_set_state(ipv6, neigh, IPV6_NUD_REACHABLE);
    return neigh;
}

void ipv6_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh)
{
    timer_stop(&ipv6->timer_group, &neigh->nud_timer);
    timer_stop(&ipv6->timer_group, &neigh->aro_lifetime);
    timer_stop(&ipv6->timer_group, &neigh->own_aro_timer);
    SLIST_REMOVE(&ipv6->neigh_cache, neigh, ipv6_neigh, link);
    TRACE(TR_NEIGH_IPV6, "neigh-ipv6 del %s eui64=%s",
          tr_ipv6(neigh->gua.s6_addr), tr_eui64(neigh->eui64.u8));
    if (neigh->rpl)
        rpl_neigh_del(ipv6, neigh);
    free(neigh);
}

void ipv6_neigh_clean(struct ipv6_ctx *ipv6)
{
    struct ipv6_neigh *neigh;
    struct ipv6_neigh *tmp;

    SLIST_FOREACH_SAFE(neigh, &ipv6->neigh_cache, link, tmp)
        ipv6_neigh_del(ipv6, neigh);
}
