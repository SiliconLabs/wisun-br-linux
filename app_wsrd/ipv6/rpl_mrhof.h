/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef RPL_MRHOF_H
#define RPL_MRHOF_H

#include <stdint.h>

#include "common/bits.h"
#include "common/specs/rpl.h"

/*
 * RFC 6719: The Minimum Rank with Hysteresis Objective Function
 * Wi-SUN FAN 1.1v08 6.2.3.1.6 Routing
 */

struct ws_neigh;
struct ipv6_ctx;
struct ipv6_neigh;
struct ws_neigh_table;

enum rpl_cand_status {
    RPL_CAND_OK,
    RPL_CAND_DISCARD_ETX,
    RPL_CAND_DISCARD_RSL,
    RPL_CAND_DISCARD_DENY,
    RPL_CAND_DISCARD_CHILD,
    RPL_CAND_DISCARD_L2,
    RPL_CAND_DISCARD_RANK,
    RPL_CAND_DISCARD_VERNO,
    RPL_CAND_DISCARD_PREF,
    RPL_CAND_DISCARD_DODAGID,
};

struct rpl_mrhof {
    float max_link_metric;
    float max_path_cost;
    float parent_switch_threshold;
    int device_min_sens_dbm;

    uint16_t lowest_advertised_rank;

    // Required for retrieving link metrics.
    const struct ws_neigh_table *ws_neigh_table;

    void (*on_pref_parent_change)(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh);
};

float rpl_mrhof_etx(const struct ipv6_ctx *ipv6, const struct ipv6_neigh *nce);
uint16_t rpl_mrhof_get_rank_limit(struct rpl_mrhof *mrhof, uint16_t max_rank_inc, uint16_t min_hop_rank_inc);
enum rpl_cand_status rpl_cand_is_acceptable(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce);
bool rpl_mrhof_has_candidates(struct ipv6_ctx *ipv6);
void rpl_mrhof_select_parents(struct ipv6_ctx *ipv6);
uint16_t rpl_mrhof_path_rank(const struct ipv6_ctx *ipv6,
                             const struct ipv6_neigh *nce);
uint16_t rpl_mrhof_rank(struct ipv6_ctx *ipv6);

#endif
