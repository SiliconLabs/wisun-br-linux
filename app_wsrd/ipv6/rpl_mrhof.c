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
#include <math.h>

#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/rpl.h"
#include "common/ws/ws_neigh.h"
#include "common/mathutils.h"
#include "common/log.h"

#include "rpl_mrhof.h"

static float rpl_mrhof_etx(const struct rpl_mrhof *mrhof, const struct ipv6_neigh *nce)
{
    struct ws_neigh *neigh = ws_neigh_get(mrhof->ws_neigh_table, nce->eui64);

    return neigh ? neigh->etx : NAN;
}

// RFC 6719 3.1. Computing the Path Cost
static float rpl_mrhof_path_cost(const struct ipv6_ctx *ipv6, const struct ipv6_neigh *nce)
{
    const struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    float etx;

    etx = rpl_mrhof_etx(mrhof, nce);

    /*
     * If the selected metric is a link metric and the metric of the link
     * to a neighbor is not available, the path cost for the path through
     * that neighbor SHOULD be set to MAX_PATH_COST.
     */
    if (isnan(etx))
        return mrhof->max_path_cost;
    /*
     * A non-root node computes a neighbor's path cost by adding two
     * components:
     * 1. If the selected metric is a link metric, the selected metric for
     *    the link to the candidate neighbor. [...]
     * 2. [...] ETX is the selected metric -- use the Rank advertised by
     *    that neighbor as the second component.
     */
    return etx + ntohs(nce->rpl->dio.rank);
}

// RFC 6719 3.2.2. Parent Selection Algorithm
void rpl_mrhof_select_parent(struct ipv6_ctx *ipv6)
{
    struct ipv6_neigh *pref_parent_cur = rpl_neigh_pref_parent(ipv6);
    struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    struct ipv6_neigh *pref_parent_new = NULL;
    float cur_min_path_cost;
    struct ipv6_neigh *nce;
    float pref_path_cost;
    float path_cost;
    float etx;

    // Compute min path cost of current parent to reflect changes on ETX/Rank
    if (pref_parent_cur)
        cur_min_path_cost = rpl_mrhof_path_cost(ipv6, pref_parent_cur);
    else
        cur_min_path_cost = mrhof->max_path_cost;

    /*
     * A node MUST select the candidate neighbor with the lowest path cost as
     * its preferred parent [...]
     */
    pref_path_cost = mrhof->max_path_cost;
    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl)
            continue;
        // TODO: refuse neighbors with higher rank than self

        etx = rpl_mrhof_etx(mrhof, nce);
        if (isnan(etx)) {
            /*
             *   Wi-SUN FAN 1.1v08 6.3.4.6.3.2.4 FFN Join State 4: Configure Routing
             * The FFN MUST perform unicast Neighbor Discovery (Neighbor
             * Solicit using its link local IPv6 address) with all FFNs from
             * which it has received a RPL DIO (thereby collecting ETX and
             * bi-directional RSL for the neighbor).
             */
            ipv6_nud_set_state(ipv6, nce, IPV6_NUD_PROBE);
            continue;
        }

        /*
         * If the selected metric for a link is greater than MAX_LINK_METRIC,
         * the node SHOULD exclude that link from consideration during parent
         * selection.
         */
        if (etx > mrhof->max_link_metric)
            continue;

        path_cost = rpl_mrhof_path_cost(ipv6, nce);
        if (path_cost >= pref_path_cost)
            continue;
        pref_path_cost  = path_cost;
        pref_parent_new = nce;
    }

    if (pref_parent_new == pref_parent_cur)
        return;

    /*
     * If the smallest path cost for paths through the candidate neighbors is
     * smaller than cur_min_path_cost by less than PARENT_SWITCH_THRESHOLD, the
     * node MAY continue to use the current preferred parent.
     */
    if (pref_path_cost + mrhof->parent_switch_threshold > cur_min_path_cost)
        return;

    if (pref_parent_cur)
        pref_parent_cur->rpl->is_parent = false;
    if (pref_parent_new) {
        pref_parent_new->rpl->is_parent = true;
        TRACE(TR_RPL, "rpl: parent select %s", tr_ipv6(pref_parent_new->gua.s6_addr));
    }
    if (pref_parent_new && !pref_parent_cur)
        TRACE(TR_RPL, "rpl: select inst-id=%u dodag-ver=%u dodag-id=%s",
              pref_parent_new->rpl->dio.instance_id,
              pref_parent_new->rpl->dio.dodag_verno,
              tr_ipv6(pref_parent_new->rpl->dio.dodag_id.s6_addr));
    /*
     *   Wi-SUN FAN 1.1v09 - 6.2.3.1.4.1 FFN Neighbor Discovery
     * If an FFN decides to change its parent or leave the network, it is
     * RECOMMENDED that the FFN attempt to de-register with its current
     * parent by sending an NS(ARO) with zero lifetime (see also [RFC6775]
     * Section 5.5).
     */
    // FIXME: Send NS(ARO) with 0 lifetime on DAO-ACK of new parent
    if (pref_parent_cur) {
        timer_stop(&ipv6->timer_group, &pref_parent_cur->aro_timer);
        ipv6_send_ns_aro(ipv6, pref_parent_cur, 0);
    }
    // If we do not have a GUA, the NS(ARO) will be sent after receiving one
    if (pref_parent_new && !IN6_IS_ADDR_UNSPECIFIED(&ipv6->dhcp.iaaddr.ipv6))
        ipv6_nud_set_state(ipv6, pref_parent_new, IPV6_NUD_PROBE);
    if (mrhof->on_pref_parent_change)
        mrhof->on_pref_parent_change(mrhof, pref_parent_new);
    // TODO: support secondary parents
}

static uint16_t rpl_mrhof_path_rank(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce)
{
    float path_cost;

    /*
     *   RFC 6719 3.3. Computing Rank
     * Once a non-root node selects its parent set, it can use the following
     * table to covert the path cost of a parent (written as Cost in the
     * table) to a Rank value:
     *     +------------------+------------+
     *     | Node/link Metric |    Rank    |
     *     +------------------+------------+
     *     |     Hop-Count    |    Cost    |
     *     |      Latency     | Cost/65536 |
     *     |        ETX       |    Cost    |
     *     +------------------+------------+
     */
    path_cost = rpl_mrhof_path_cost(ipv6, nce);
    // NOTE: Overflow during float to int conversion is undefined behavior.
    return MIN(path_cost, (float)UINT16_MAX);
}

// RFC 6719 3.3. Computing Rank
uint16_t rpl_mrhof_rank(struct ipv6_ctx *ipv6)
{
    uint16_t min_hop_rank_inc, max_rank_inc;
    struct ipv6_neigh *nce, *worst_neigh;
    uint16_t rank = RPL_RANK_INFINITE;
    uint16_t worst_rank;

    /*
     * A node sets its Rank to the maximum of three values:
     *
     * 1. The Rank calculated for the path through the preferred parent.
     */
    nce = rpl_neigh_pref_parent(ipv6);
    if (!nce)
        return RPL_RANK_INFINITE;
    rank = rpl_mrhof_path_rank(ipv6, nce);

    min_hop_rank_inc = ntohs(nce->rpl->config.min_hop_rank_inc);
    max_rank_inc     = ntohs(nce->rpl->config.max_rank_inc);

    /*
     * 2. The Rank of the member of the parent set with the highest advertised
     *    Rank, rounded to the next higher integral Rank, i.e., to
     *    MinHopRankIncrease * (1 + floor(Rank/MinHopRankIncrease)).
     */
    worst_rank  = 0;
    worst_neigh = NULL;
    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl || !nce->rpl->is_parent)
            continue;
        if (worst_rank >= ntohs(nce->rpl->dio.rank))
            continue;
        worst_neigh = nce;
        worst_rank  = ntohs(worst_neigh->rpl->dio.rank);
    }
    rank = MAX(rank, min_hop_rank_inc * (worst_rank / min_hop_rank_inc + 1));

    /*
     * 3. The largest calculated Rank among paths through the parent set, minus
     *    MaxRankIncrease.
     */
    worst_rank = 0;
    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl || !nce->rpl->is_parent)
            continue;
        worst_rank = MAX(worst_rank, rpl_mrhof_path_rank(ipv6, nce));
    }
    rank = MAX(rank, worst_rank - max_rank_inc);

    return rank;
}
