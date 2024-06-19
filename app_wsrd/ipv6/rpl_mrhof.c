#include <math.h>

#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/rpl.h"
#include "common/mathutils.h"
#include "common/log.h"
#include "common/ws_neigh.h"

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
    return etx + ntohs(nce->rpl->dio_base.rank);
}

// RFC 6719 3.2.2. Parent Selection Algorithm
void rpl_mrhof_select_parent(struct ipv6_ctx *ipv6)
{
    struct rpl_mrhof *mrhof = &ipv6->rpl.mrhof;
    struct ipv6_neigh *pref_parent_new = NULL;
    struct ipv6_neigh *pref_parent_cur;
    struct ipv6_neigh *nce;
    float pref_path_cost;
    float path_cost;
    float etx;

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

    /*
     * If the smallest path cost for paths through the candidate neighbors is
     * smaller than cur_min_path_cost by less than PARENT_SWITCH_THRESHOLD, the
     * node MAY continue to use the current preferred parent.
     */
    if (pref_path_cost + mrhof->parent_switch_threshold > mrhof->cur_min_path_cost)
        return;
    mrhof->cur_min_path_cost = pref_path_cost;

    pref_parent_cur = rpl_neigh_pref_parent(ipv6);
    if (pref_parent_new == pref_parent_cur)
        return;

    if (pref_parent_cur)
        pref_parent_cur->rpl->is_parent = false;
    if (pref_parent_new) {
        pref_parent_new->rpl->is_parent = true;
        TRACE(TR_RPL, "rpl: parent select %s", tr_ipv6(pref_parent_new->gua.s6_addr));
    }
    if (pref_parent_new && !pref_parent_cur)
        TRACE(TR_RPL, "rpl: select inst-id=%u dodag-ver=%u dodag-id=%s",
              pref_parent_new->rpl->dio_base.instance_id,
              pref_parent_new->rpl->dio_base.dodag_verno,
              tr_ipv6(pref_parent_new->rpl->dio_base.dodag_id.s6_addr));
    if (mrhof->on_pref_parent_change)
        mrhof->on_pref_parent_change(mrhof, pref_parent_new);
    // TODO: support secondary parents
}
