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

struct rpl_neigh {
    struct rpl_dio dio;
    struct rpl_opt_config config;
    bool is_parent;
    bool dao_ack_received;
};

struct rpl_ctx {
    int fd;

    struct trickle       dio_trickle;
    struct trickle_cfg   dio_trickle_cfg;
    struct rfc8415_txalg dis_txalg;
    struct rfc8415_txalg dao_txalg;
    uint8_t dao_seq;
    struct rpl_mrhof mrhof;

    void (*on_dao_ack)(struct ipv6_ctx *ipv6);
};

void rpl_start(struct ipv6_ctx *ipv6);
void rpl_stop(struct ipv6_ctx *ipv6);
void rpl_recv(struct ipv6_ctx *ipv6);
void rpl_start_dio(struct ipv6_ctx *ipv6);
void rpl_start_dis(struct ipv6_ctx *ipv6);
void rpl_start_dao(struct ipv6_ctx *ipv6);

void rpl_neigh_del(struct ipv6_ctx *ipv6, struct ipv6_neigh *nce);
struct ipv6_neigh *rpl_neigh_pref_parent(struct ipv6_ctx *ipv6);

#endif
