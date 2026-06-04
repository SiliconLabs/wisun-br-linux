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
#ifndef RPL_NODE_H
#define RPL_NODE_H

#include <netinet/in.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

#include "app_wsrd/ipv6/rpl_mrhof.h"
#include "common/specs/rpl.h"
#include "common/rfc8415_txalg.h"
#include "common/trickle.h"

struct ipv6_ctx;
struct ipv6_neigh;
struct timer_ctxt;

#define RPL_RANK_INFINITE UINT16_MAX
#define RPL_PARENT_UPDATE_DELAY_MS (10 * 1000) // 10s

/*
 *   Wi-SUN FAN 1.1v10 6.2.3.1.6.4 Downward Route Formation
 * The Path Control field MUST be populated to correctly rank the priority of
 * each Transit Information Option (i.e., the preferred parent is indicated as
 * the single member of PC1, the first alternate parent set as the single
 * member of PC2, etc.).
 */
#define RPL_PATH_CTL_PREFERRED FIELD_PREP(RPL_MASK_PATH_CTL_PC1, 1)
#define RPL_PATH_CTL_SECONDARY FIELD_PREP(RPL_MASK_PATH_CTL_PC2, 1)
#define RPL_PARENTS_MAX 2

extern const uint8_t rpl_path_ctl_table[RPL_PARENTS_MAX];

struct rpl_neigh {
    struct rpl_dio dio;
    struct rpl_opt_config config;
    uint8_t path_ctl;
    uint8_t path_ctl_acked;
    struct timer_entry deny_timer;
    bool rsl_valid;
    /*
     * Candidate preference: determines whether the neighbor is actively probed
     * in order to maintain metrics up-to-date. Set to a negative value during
     * candidate update to indicate that the neighbor was already a candidate.
     */
    int cand_pref;
};

/*
 * Parent selection logic when dis_txalg is not running:
 * 1. On DIO RX from a new sender
 * 2. On DIO RX from a known sender with updated values
 * 3. When a neighbor is denied (most likely, our current parent)
 * 4. On ETX update
 *
 * Parent selection timing when dis_txalg is running:
 * 1. Before sending DIS: when dis_txalg.tx() is called.
 * 2. RPL_PARENT_UPDATE_DELAY_MS after the last DIS transmission.
 *
 * This enables:
 * - Fast parent selection if any is eligible after sending unicast DIS.
 * - Time to receive and process multicast DIO responses.
 *
 * Notes:
 * - The dis_txalg timing parameters directly control how frequently
 *   parent selection can occur when dis_txalg is running.
 * - No parent selection is done without sending at least one DIS wave.
 */
struct rpl_ctx {
    int fd;
    bool compat;

    struct trickle       dio_trickle;
    struct trickle_cfg   dio_trickle_cfg;
    /*
     * Integrator is responsible for implementing dis_txalg.tx, which should
     * call rpl_send_dis() a limited number of times.
     */
    struct rfc8415_txalg dis_txalg;
    struct rfc8415_txalg dao_txalg;
    struct timer_entry   dao_refresh_timer;
    struct timer_entry parent_update_timer;
    uint8_t path_seq; // Serves as both path seqno and dao seqno
    int path_seq_last_tx; // -1 if not set
    struct in6_addr dodag_id;
    int dodag_verno; // -1 if not set
    int dtsn; // -1 if not set
    uint16_t last_advertised_rank; // Last rank advertised in a DIO
    struct rpl_mrhof mrhof;

    void (*on_dao_ack)(struct ipv6_ctx *ipv6);
};

void rpl_start(struct ipv6_ctx *ipv6);
void rpl_stop(struct ipv6_ctx *ipv6);
void rpl_recv(struct ipv6_ctx *ipv6);
void rpl_send_dio(struct ipv6_ctx *ipv6, struct ipv6_neigh *parent, const struct in6_addr *dst);
void rpl_start_dio(struct ipv6_ctx *ipv6);
void rpl_start_dis(struct ipv6_ctx *ipv6);
void rpl_stop_dis(struct ipv6_ctx *ipv6);
void rpl_send_dis(struct ipv6_ctx *ipv6, const struct in6_addr *dst);
void rpl_send_dao_no_path(struct ipv6_ctx *ipv6);
void rpl_start_dao(struct ipv6_ctx *ipv6);

void rpl_unregister_from_parent(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce);

void rpl_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce);
void rpl_get_parents(struct ipv6_ctx *ipv6, struct ipv6_neigh *parents[RPL_PARENTS_MAX]);
struct ipv6_neigh *rpl_neigh_get_parent(struct ipv6_ctx *ipv6, uint8_t path_ctl);
bool rpl_has_acked_parent(struct ipv6_ctx *ipv6);
bool rpl_can_update_parent(struct ipv6_ctx *ipv6);
void rpl_update_parents(struct ipv6_ctx *ipv6);
void rpl_neigh_deny(struct ipv6_ctx *ipv6, struct ipv6_neigh *neigh);

#endif
