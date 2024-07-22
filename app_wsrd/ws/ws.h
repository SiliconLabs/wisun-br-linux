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
#ifndef WSRD_WS_H
#define WSRD_WS_H

#include <sys/queue.h>
#include <stddef.h>
#include <stdint.h>

#include "common/ws_ie.h"
#include "common/ws_neigh.h"
#include "common/ws_types.h"
#include "app_wsrd/supplicant/supplicant.h"
#include "app_wsrd/ipv6/ipv6.h"

struct rcp_tx_cnf;
struct rcp_rx_ind;

// Frame sent to the RCP and waiting for a confirmation.
struct ws_frame_ctx {
    uint8_t handle;
    uint8_t type;
    uint8_t dst[8];
    SLIST_ENTRY(ws_frame_ctx) link;
};

// Define struct ws_frame_list
SLIST_HEAD(ws_frame_ctx_list, ws_frame_ctx);

struct ws_ctx {
    char     netname[WS_NETNAME_LEN];
    uint16_t pan_id; // 0xffff if not set
    int pan_version; // -1 if not set
    struct ws_phy_config  phy;
    struct ws_fhss_config fhss;
    struct ws_neigh_table neigh_table;

    uint8_t  seqno;
    uint8_t  handle_next;
    struct ws_frame_ctx_list frame_ctx_list;
    uint8_t  edfe_src[8];

    struct ipv6_ctx ipv6;

    struct supplicant_ctx supp;
    uint8_t eapol_target_eui64[8];
    uint8_t gak_index;
};

void ws_recv_ind(struct ws_ctx *ws, const struct rcp_rx_ind *ind);
void ws_recv_cnf(struct ws_ctx *ws, const struct rcp_tx_cnf *cnf);

int ws_send_data(struct ws_ctx *ws, const void *pkt, size_t pkt_len, const uint8_t dst[8]);
void ws_send_eapol(struct ws_ctx *ws, uint8_t kmp_id, const void *pkt, size_t pkt_len, const uint8_t dst[8]);

#endif
