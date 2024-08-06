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

#include "common/bits.h"
#include "common/specs/rpl.h"

/*
 * RFC 6719: The Minimum Rank with Hysteresis Objective Function
 * Wi-SUN FAN 1.1v08 6.2.3.1.6 Routing
 */

struct ipv6_ctx;
struct ipv6_neigh;
struct ws_neigh_table;

struct rpl_mrhof {
    float max_link_metric;
    float max_path_cost;
    float parent_switch_threshold;

    float cand_parent_threshold;
    float cand_parent_hysteresis;

    float cur_min_path_cost;

    // Required for retrieving link metrics.
    const struct ws_neigh_table *ws_neigh_table;

    void (*on_pref_parent_change)(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh);
};

void rpl_mrhof_select_parent(struct ipv6_ctx *ipv6);

#endif
