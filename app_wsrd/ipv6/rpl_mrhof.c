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
#include <math.h>

#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/rpl.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/ws/ws_neigh.h"
#include "common/named_values.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/seqno.h"
#include "common/dbus.h"
#include "common/log.h"

#include "rpl_mrhof.h"

static const char *tr_path_ctl(uint8_t path_ctl)
{
    static const struct name_value rpl_path_ctl_names[RPL_PARENTS_MAX] = {
        { "preferred",  RPL_PATH_CTL_PREFERRED },
        { "secondary",  RPL_PATH_CTL_SECONDARY },
    };

    return val_to_str(path_ctl, rpl_path_ctl_names, "??");
}

float rpl_mrhof_etx(const struct ipv6_ctx *ipv6, const struct ipv6_neigh *nce)
{
    struct ws_neigh *neigh = ws_neigh_get(ipv6->rpl.mrhof.ws_neigh_table, &nce->eui64);

    return neigh ? neigh->ws_etx.etx : NAN;
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

bool rpl_mrhof_candidate_rsl_is_valid(struct ipv6_ctx *ipv6, struct ws_neigh *neigh)
{
    BUG_ON(!neigh);
    BUG_ON(isnan(neigh->rsl_in_dbm_unsecured));

    return neigh->rsl_in_dbm_unsecured >= ipv6->rpl.mrhof.device_min_sens_dbm;
}

/*
 *   RFC 6550 8.2.2.4.  Rank and Movement within a DODAG Version
 * Let L be the lowest Rank within a DODAG Version that a given node has
 * advertised. Within the same DODAG Version, that node MUST NOT advertise
 * an effective Rank higher than L + DAGMaxRankIncrease.
 * NOTE: to avoid discarding all candidates with a higher rank when
 * MaxRankIncrease is set to 0, the rank limit is set to the upper DAGRank.
 */
uint16_t rpl_mrhof_get_rank_limit(struct rpl_mrhof *mrhof, uint16_t max_rank_inc, uint16_t min_hop_rank_inc)
{
    uint16_t max_dag_rank;
    uint32_t rank_limit;

    max_dag_rank = rpl_dag_rank(min_hop_rank_inc, add16sat(mrhof->lowest_advertised_rank, max_rank_inc));
    rank_limit = (max_dag_rank + 1) * min_hop_rank_inc;
    if (rank_limit >= UINT16_MAX)
        return RPL_RANK_INFINITE;
    return rank_limit - 1;
}

static const char *rpl_mrhof_is_candidate(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce)
{
    struct ws_neigh *neigh = ws_neigh_get(ipv6->rpl.mrhof.ws_neigh_table, &nce->eui64);

    BUG_ON(!nce->rpl);
    if (!neigh)
        return "15.4-neigh";
    if (!nce->rpl->rsl_valid)
        nce->rpl->rsl_valid = rpl_mrhof_candidate_rsl_is_valid(ipv6, neigh);
    if (!nce->rpl->rsl_valid)
        return "rsl";
    if (!timer_stopped(&nce->rpl->deny_timer))
        return "denied";
    if (ipv6_neigh_is_child(nce))
        return "child";
    return NULL;
}

static bool rpl_mrhof_is_probe_needed(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce)
{
    const char *discard;
    float etx;

    discard = rpl_mrhof_is_candidate(ipv6, nce);
    if (discard)
        return false;
    etx = rpl_mrhof_etx(ipv6, nce);
    if (isnan(etx))
        return true;
    return false;
}

const char *rpl_mrhof_validate_candidate(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce,
                                         uint16_t rank_limit, float etx_max, int dodag_verno)
{
    const char *discard;
    uint16_t new_rank;
    float etx;

    discard = rpl_mrhof_is_candidate(ipv6, nce);
    if (discard)
        return discard;
    new_rank = rpl_mrhof_path_rank(ipv6, nce);
    etx = rpl_mrhof_etx(ipv6, nce);
    if (isnan(etx)) {
        if (etx_max == WS_ETX_MAX)
            return NULL;
        return "etx";
    }
    /*
     * If the selected metric for a link is greater than MAX_LINK_METRIC,
     * the node SHOULD exclude that link from consideration during parent
     * selection.
     */
    if (etx > etx_max)
        return "etx";
    if (new_rank > rank_limit || new_rank == RPL_RANK_INFINITE)
        return "rank";
    if (dodag_verno != -1 && seqno_cmp8(nce->rpl->dio.dodag_verno, dodag_verno) != 0)
        return "dodag-verno";
    return NULL;
}

/*
 * NOTE: Since we restrict ourselves from advancing to the next DAGRank, we may
 * still want to know if candidates that would make us increase our rank as
 * such exist around us. This allows us to detect situations where no suitable
 * parent exists within the allowed rank range, and take appropriate action.
 */
bool rpl_mrhof_has_candidates(struct ipv6_ctx *ipv6)
{
    struct ipv6_neigh *nce;

    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl)
            continue;
        if (!rpl_mrhof_validate_candidate(ipv6, nce, RPL_RANK_INFINITE, ipv6->rpl.mrhof.max_link_metric, -1))
            return true;
    }
    return false;
}

static struct ipv6_neigh *rpl_mrhof_select_best_candidate(struct ipv6_ctx *ipv6, struct ipv6_neigh *parent_cur,
                                                          float cur_min_path_cost, uint16_t rank_limit)
{
    struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    float pref_path_cost = mrhof->max_path_cost;
    struct ipv6_neigh *parent_new = NULL;
    struct ipv6_neigh *nce;
    const char *discard;
    uint16_t new_rank;
    float path_cost;
    float etx;

    /*
     * A node MUST select the candidate neighbor with the lowest path cost as
     * its preferred parent [...]
     */
    TRACE(TR_RPL, "rpl:   %-45s | %-11s | %-4s | %-5s | %-9s | %-8s | %s",
          "candidate", "dodag-verno", "etx", "rank", "path-cost", "new-rank", "discard");

    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl || nce->rpl->path_ctl)
            continue;

        etx = rpl_mrhof_etx(ipv6, nce);
        path_cost = rpl_mrhof_path_cost(ipv6, nce);
        new_rank = rpl_mrhof_path_rank(ipv6, nce);
        discard = rpl_mrhof_validate_candidate(ipv6, nce, rank_limit, ipv6->rpl.mrhof.max_link_metric,
                                               ipv6->rpl.dodag_verno);

        /*
         *   Wi-SUN FAN 1.1v08 6.3.4.6.3.2.4 FFN Join State 4: Configure Routing
         * The FFN MUST perform unicast Neighbor Discovery (Neighbor Solicit
         * using its link local IPv6 address) with all FFNs from which it has
         * received a RPL DIO (thereby collecting ETX and bi-directional RSL
         * for the neighbor).
         */
        if (discard && nce->nud_state != IPV6_NUD_PROBE &&
            rpl_mrhof_is_probe_needed(ipv6, nce))
            ipv6_nud_set_state(ipv6, nce, IPV6_NUD_PROBE);

        TRACE(TR_RPL, "rpl:   %-45s | %-11u | %-4.0f | %-5u | %-9.0f | %-8u | %s",
              tr_ipv6(nce->gua.s6_addr), nce->rpl->dio.dodag_verno, etx, ntohs(nce->rpl->dio.rank),
              path_cost, new_rank, discard ? discard : "");
        if (discard)
            continue;
        if (path_cost >= pref_path_cost)
            continue;
        pref_path_cost = path_cost;
        parent_new = nce;
    }

    if (parent_new == parent_cur && cur_min_path_cost < mrhof->max_path_cost) {
        TRACE(TR_RPL, "rpl: parent select %s (keep)", parent_new ? tr_ipv6(parent_new->gua.s6_addr) : "none");
        return parent_cur;
    }

    /*
     * If the smallest path cost for paths through the candidate neighbors is
     * smaller than cur_min_path_cost by less than PARENT_SWITCH_THRESHOLD, the
     * node MAY continue to use the current preferred parent.
     */
    if (cur_min_path_cost < mrhof->max_path_cost && pref_path_cost < mrhof->max_path_cost &&
        pref_path_cost + mrhof->parent_switch_threshold > cur_min_path_cost) {
        BUG_ON(!parent_cur); // we should always have a current parent here
        if (!seqno_cmp8(parent_cur->rpl->dio.dodag_verno, ipv6->rpl.dodag_verno)) {
            TRACE(TR_RPL, "rpl: discard %s: path-cost=%.0f + thresh=%.0f > min-path-cost=%.0f",
                  parent_new ? tr_ipv6(parent_new->gua.s6_addr) : "none", pref_path_cost,
                  mrhof->parent_switch_threshold, cur_min_path_cost);
            TRACE(TR_RPL, "rpl: parent select %s (keep)", tr_ipv6(parent_cur->gua.s6_addr));
            return parent_cur;
        }
    }

    /*
     * NOTE: Try keeping the current parent if no other candidate with a better
     * ETX was found. This mechanism is only useful when the rank limit is not
     * set: therefore, it won't work on secondary parent selection.
     */
    if (!parent_new && parent_cur) {
        discard = rpl_mrhof_validate_candidate(ipv6, parent_cur, rank_limit, WS_ETX_MAX, ipv6->rpl.dodag_verno);
        if (!discard) {
            TRACE(TR_RPL, "rpl: parent select %s (keep etx > %.0f)", tr_ipv6(parent_cur->gua.s6_addr),
                  ipv6->rpl.mrhof.max_link_metric);
            return parent_cur;
        }
    }

    if (parent_new)
        TRACE(TR_RPL, "rpl: parent select %s", tr_ipv6(parent_new->gua.s6_addr));
    else
        TRACE(TR_RPL, "rpl: parent select none");
    return parent_new;
}

// RFC 6719 3.2.2. Parent Selection Algorithm
void rpl_mrhof_select_parents(struct ipv6_ctx *ipv6)
{
    struct ipv6_neigh *parents_cur[RPL_PARENTS_MAX] = { };
    struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    int dtsn_best = ipv6->rpl.dtsn;
    struct ipv6_neigh *parent_new;
    float cur_min_path_cost;
    uint32_t rank_limit;

    rpl_get_parents(ipv6, parents_cur);
    for (int i = 0; i < ARRAY_SIZE(parents_cur); i++) {
        // Reset all path controls to allow re-selection
        if (parents_cur[i])
            parents_cur[i]->rpl->path_ctl = 0;
    }

    if (parents_cur[0])
        rank_limit = rpl_mrhof_get_rank_limit(mrhof, ntohs(parents_cur[0]->rpl->config.max_rank_inc),
                                              ntohs(parents_cur[0]->rpl->config.min_hop_rank_inc));
    else
        rank_limit = RPL_RANK_INFINITE;

    for (int i = 0; i < ARRAY_SIZE(rpl_path_ctl_table); i++) {
        if (!(rpl_path_ctl_table[i] & RPL_PATH_CTL_PREFERRED)) {
            BUG_ON(!parents_cur[0]);
            rank_limit = rpl_mrhof_get_rank_limit(mrhof, ntohs(parents_cur[0]->rpl->config.max_rank_inc),
                                                  ntohs(parents_cur[0]->rpl->config.min_hop_rank_inc));
            /*
             * NOTE: If we have no rank limit, set it to our DagRank + 1 through
             * our preferred parent.
             */
            if (rank_limit == RPL_RANK_INFINITE) {
                rank_limit = rpl_dag_rank(ntohs(parents_cur[0]->rpl->config.min_hop_rank_inc),
                                          rpl_mrhof_path_rank(ipv6, parents_cur[0]));
                rank_limit = (rank_limit + 1) * ntohs(parents_cur[0]->rpl->config.min_hop_rank_inc) - 1;
                if (rank_limit >= UINT16_MAX)
                    rank_limit = RPL_RANK_INFINITE;
            }
        }

        /*
         * NOTE: MRHOF hysteresis is applied on all parents to prevent swapping
         * too often.
         */
        cur_min_path_cost = mrhof->max_path_cost;
        if (parents_cur[i] && timer_stopped(&parents_cur[i]->rpl->deny_timer) && !parents_cur[i]->rpl->path_ctl)
            cur_min_path_cost = rpl_mrhof_path_cost(ipv6, parents_cur[i]);

        TRACE(TR_RPL, "rpl: selecting %s parent cur=%s dodag-verno=%d min-path-cost=%.0f max-link-metric=%.0f rank-limit=%u",
              tr_path_ctl(rpl_path_ctl_table[i]), parents_cur[i] ? tr_ipv6(parents_cur[i]->gua.s6_addr) : "none",
              ipv6->rpl.dodag_verno, cur_min_path_cost, ipv6->rpl.mrhof.max_link_metric, rank_limit);

        parent_new = rpl_mrhof_select_best_candidate(ipv6, parents_cur[i], cur_min_path_cost, rank_limit);
        if (!parent_new && rpl_path_ctl_table[i] == RPL_PATH_CTL_PREFERRED && rank_limit != RPL_RANK_INFINITE) {
            ipv6->rpl.mrhof.lowest_advertised_rank = RPL_RANK_INFINITE;
            rank_limit = RPL_RANK_INFINITE;
            TRACE(TR_RPL, "rpl: no %s parent selected, retry with rank-limit=%u",
                  tr_path_ctl(rpl_path_ctl_table[i]), rank_limit);
            parent_new = rpl_mrhof_select_best_candidate(ipv6, parents_cur[i], cur_min_path_cost, rank_limit);
        }
        parents_cur[i] = parent_new;
        if (!parents_cur[i])
            break;
        parents_cur[i]->rpl->path_ctl = rpl_path_ctl_table[i];
        if (dtsn_best == -1 || seqno_cmp8(parents_cur[i]->rpl->dio.dtsn, dtsn_best) > 0)
            dtsn_best = parents_cur[i]->rpl->dio.dtsn;
        if (ipv6->rpl.dodag_verno == -1) {
            ipv6->rpl.dodag_verno = parents_cur[i]->rpl->dio.dodag_verno;
            TRACE(TR_RPL, "rpl: set dodag-verno=%u", ipv6->rpl.dodag_verno);
        }
    }
    /*
     *   RFC 6550 9.6 Triggering DAO Messages
     * In Non-Storing mode, if a node hears one of its DAO parents increment
     * its DTSN, the node MUST increment its own DTSN.
     */
    if (dtsn_best != ipv6->rpl.dtsn) {
        ipv6->rpl.dtsn = dtsn_best;
        TRACE(TR_RPL, "rpl: set dtsn=%u", ipv6->rpl.dtsn);
    }
}

uint16_t rpl_mrhof_path_rank(const struct ipv6_ctx *ipv6,
                             const struct ipv6_neigh *nce)
{
    uint16_t path_rank;
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
    path_rank = MIN(path_cost, (float)UINT16_MAX);

    /*
     * The Rank associated with a path through a member of the parent set is
     * the maximum of two values. The first is the corresponding Rank value
     * calculated with the table above, the second is that nodes' advertised
     * Rank plus MinHopRankIncrease.
     */
    return MAX(path_rank, add16sat(ntohs(nce->rpl->dio.rank),
                                   ntohs(nce->rpl->config.min_hop_rank_inc)));
}

// RFC 6719 3.3. Computing Rank
uint16_t rpl_mrhof_rank(struct ipv6_ctx *ipv6)
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
    nce = rpl_neigh_get_parent(ipv6, RPL_PATH_CTL_PREFERRED);
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
    SLIST_FOREACH(nce, &ipv6->neigh_cache, link) {
        if (!nce->rpl || !nce->rpl->path_ctl)
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
        if (!nce->rpl || !nce->rpl->path_ctl)
            continue;
        worst_rank = MAX(worst_rank, rpl_mrhof_path_rank(ipv6, nce));
    }
    rank = MAX(rank, worst_rank - max_rank_inc);

    return rank;
}
