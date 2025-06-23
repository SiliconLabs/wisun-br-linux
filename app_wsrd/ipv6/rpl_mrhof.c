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
#include "common/ipv6/ipv6_addr.h"
#include "common/ws/ws_neigh.h"
#include "common/mathutils.h"
#include "common/dbus.h"
#include "common/log.h"

#include "rpl_mrhof.h"

float rpl_mrhof_etx(const struct ipv6_ctx *ipv6, const struct ipv6_neigh *nce)
{
    struct ws_neigh *neigh = ws_neigh_get(ipv6->rpl.mrhof.ws_neigh_table, &nce->eui64);

    return neigh ? neigh->etx : NAN;
}

// RFC 6719 3.1. Computing the Path Cost
static float rpl_mrhof_path_cost(const struct ipv6_ctx *ipv6, const struct ipv6_neigh *nce)
{
    const struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    float etx;

    etx = rpl_mrhof_etx(ipv6, nce);

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

static bool rpl_mrhof_candidate_rsl_is_valid(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce)
{
    struct ws_neigh *neigh = ws_neigh_get(ipv6->rpl.mrhof.ws_neigh_table, &nce->eui64);
    int device_min_sens_dbm = ipv6->rpl.mrhof.device_min_sens_dbm;
    int threshold;

    if (!neigh || isnan(neigh->rsl_out_dbm))
        return false;

    BUG_ON(isnan(neigh->rsl_in_dbm_unsecured));

    /*
     *   Wi-SUN FAN 1.1v09 6.2.3.1.6.3 Upward Route Formation
     * a. For an FFN to be admitted to the candidate parent set, both its
     *    node-to-neighbor and neighbor-to-node RSL EWMA values should exceed
     *    (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERESIS).
     * b. For an FFN to be removed from the candidate parent set, both its
     *    node-to-neighbor and neighbor-to node RSL EWMA values should fall
     *    below (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD - CAND_PARENT_HYSTERESIS).
     */
    if (!nce->rpl->rsl_valid) {
        threshold = device_min_sens_dbm + WS_CAND_PARENT_THRESHOLD_DB + WS_CAND_PARENT_HYSTERESIS_DB;
        return neigh->rsl_in_dbm_unsecured > threshold && neigh->rsl_out_dbm > threshold;
    } else {
        threshold = device_min_sens_dbm + WS_CAND_PARENT_THRESHOLD_DB - WS_CAND_PARENT_HYSTERESIS_DB;
        return !(neigh->rsl_in_dbm_unsecured < threshold && neigh->rsl_out_dbm < threshold);
    }
}

// RFC 6719 3.2.2. Parent Selection Algorithm
struct ipv6_neigh *rpl_mrhof_select_parent(struct ipv6_ctx *ipv6)
{
    struct ipv6_neigh *pref_parent_cur = rpl_neigh_pref_parent(ipv6);
    struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    struct ipv6_neigh *pref_parent_new = NULL;
    float cur_min_path_cost;
    struct ipv6_neigh *nce;
    float pref_path_cost;
    const char *discard;
    float path_cost;
    float etx;

    // Compute min path cost of current parent to reflect changes on ETX/Rank
    if (pref_parent_cur && timer_stopped(&pref_parent_cur->rpl->deny_timer))
        cur_min_path_cost = rpl_mrhof_path_cost(ipv6, pref_parent_cur);
    else
        cur_min_path_cost = mrhof->max_path_cost;

    TRACE(TR_RPL, "rpl: selecting parent cur=%s min-path-cost=%.0f max-link-metric=%.0f",
          pref_parent_cur ? tr_ipv6(pref_parent_cur->gua.s6_addr) : "none",
          cur_min_path_cost, mrhof->max_link_metric);

    /*
     * A node MUST select the candidate neighbor with the lowest path cost as
     * its preferred parent [...]
     */
    pref_path_cost = mrhof->max_path_cost;
    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl)
            continue;
        // TODO: refuse neighbors with higher rank than self

        discard = NULL;
        etx = rpl_mrhof_etx(ipv6, nce);
        path_cost = rpl_mrhof_path_cost(ipv6, nce);
        if (isnan(etx)) {
            /*
             *   Wi-SUN FAN 1.1v08 6.3.4.6.3.2.4 FFN Join State 4: Configure Routing
             * The FFN MUST perform unicast Neighbor Discovery (Neighbor
             * Solicit using its link local IPv6 address) with all FFNs from
             * which it has received a RPL DIO (thereby collecting ETX and
             * bi-directional RSL for the neighbor).
             */
            if (nce->nud_state != IPV6_NUD_PROBE)
                ipv6_nud_set_state(ipv6, nce, IPV6_NUD_PROBE);
            discard = "etx";
        }

        nce->rpl->rsl_valid = rpl_mrhof_candidate_rsl_is_valid(ipv6, nce);
        if (!nce->rpl->rsl_valid)
            discard = "rsl";

        /*
         * If the selected metric for a link is greater than MAX_LINK_METRIC,
         * the node SHOULD exclude that link from consideration during parent
         * selection.
         */
        if (etx > mrhof->max_link_metric)
            discard = "etx";

        if (!timer_stopped(&nce->rpl->deny_timer))
            discard = "denied";
        if (discard) {
            TRACE(TR_RPL, "rpl:   candidate %-45s etx=%-4.0f rank=%-5u path-cost=%-5.0f (discard %s)",
                  tr_ipv6(nce->gua.s6_addr), etx, ntohs(nce->rpl->dio.rank), path_cost, discard);
            continue;
        } else {
            TRACE(TR_RPL, "rpl:   candidate %-45s etx=%-4.0f rank=%-5u path-cost=%.0f",
                  tr_ipv6(nce->gua.s6_addr), etx, ntohs(nce->rpl->dio.rank), path_cost);
        }
        if (path_cost >= pref_path_cost)
            continue;
        pref_path_cost  = path_cost;
        pref_parent_new = nce;
    }

    if (pref_parent_new == pref_parent_cur && cur_min_path_cost < mrhof->max_path_cost) {
        TRACE(TR_RPL, "rpl: parent select %s (keep)", pref_parent_new ? tr_ipv6(pref_parent_new->gua.s6_addr) : "none");
        return pref_parent_cur;
    }

    /*
     * If the smallest path cost for paths through the candidate neighbors is
     * smaller than cur_min_path_cost by less than PARENT_SWITCH_THRESHOLD, the
     * node MAY continue to use the current preferred parent.
     */
    if (cur_min_path_cost < mrhof->max_path_cost &&
        pref_path_cost + mrhof->parent_switch_threshold > cur_min_path_cost) {
        BUG_ON(!pref_parent_cur); // we should always have a current parent here
        TRACE(TR_RPL, "rpl: discard %s: path-cost=%.0f + thresh=%.0f > min-path-cost=%.0f",
              pref_parent_new ? tr_ipv6(pref_parent_new->gua.s6_addr) : "none", pref_path_cost,
              mrhof->parent_switch_threshold, cur_min_path_cost);
        TRACE(TR_RPL, "rpl: parent select %s (keep)", tr_ipv6(pref_parent_cur->gua.s6_addr));
        return pref_parent_cur;
    }

    if (pref_parent_cur)
        pref_parent_cur->rpl->is_parent = false;
    if (pref_parent_new) {
        pref_parent_new->rpl->is_parent = true;
        TRACE(TR_RPL, "rpl: parent select %s", tr_ipv6(pref_parent_new->gua.s6_addr));
    } else {
        TRACE(TR_RPL, "rpl: parent select none");
    }
    return pref_parent_new;
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

/*
 * RFC 6719 3.3. Computing Rank
 * If single_parent is not NULL, computes the rank as if the neighbor was the
 * only parent.
 */
uint16_t rpl_mrhof_rank(struct ipv6_ctx *ipv6, struct ipv6_neigh *single_parent)
{
    uint16_t min_hop_rank_inc, max_rank_inc;
    uint16_t rank = RPL_RANK_INFINITE;
    struct ipv6_neigh *worst_neigh;
    uint16_t worst_rank = 0;
    struct ipv6_neigh *nce;

    /*
     * A node sets its Rank to the maximum of three values:
     *
     * 1. The Rank calculated for the path through the preferred parent.
     */
    nce = single_parent ? : rpl_neigh_pref_parent(ipv6);
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
    if (!single_parent) {
        SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
            if (!nce->rpl || !nce->rpl->is_parent)
                continue;
            if (worst_rank >= ntohs(nce->rpl->dio.rank))
                continue;
            worst_neigh = nce;
            worst_rank  = ntohs(worst_neigh->rpl->dio.rank);
        }
    } else {
        worst_rank = ntohs(single_parent->rpl->dio.rank);
    }
    rank = MAX(rank, min_hop_rank_inc * (worst_rank / min_hop_rank_inc + 1));

    /*
     * 3. The largest calculated Rank among paths through the parent set, minus
     *    MaxRankIncrease.
     */
    if (!single_parent) {
        worst_rank = 0;
        SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
            if (!nce->rpl || !nce->rpl->is_parent)
                continue;
            worst_rank = MAX(worst_rank, rpl_mrhof_path_rank(ipv6, nce));
        }
    } else {
        worst_rank = rpl_mrhof_path_rank(ipv6, single_parent);
    }
    rank = MAX(rank, worst_rank - max_rank_inc);

    return rank;
}
