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
#ifndef WS_INTERFACE_H
#define WS_INTERFACE_H
#include <inttypes.h>

#include "common/ieee802154_frame.h"
#include "common/crypto/ws_keys.h"
#include "common/ws/ws_ie_list.h"
#include "common/ws/ws_neigh.h"
#include "common/ws/ws_types.h"
#include "common/rcp_api.h"
#include "common/iobuf.h"

struct eui64;

struct wh_ie_list {
    bool utt;
    bool bt;
    bool fc;
    bool rsl;
    const struct eui64 *ea;
    bool lutt;
    bool lbt;
    bool nr;
    bool lus;
    bool flus;
    bool lbs;
    bool lnd;
    bool lto;
    bool panid;
    bool lbc;
    bool sl_utt;
};

struct wp_ie_list {
    bool us;
    bool bs;
    struct ws_pan_ie *pan;
    bool netname;
    bool panver;
    bool gtkhash;
    bool lgtkhash;
    bool lfnver;
    bool lcp;
    bool lbats;
    bool pom;
    bool jm;
};

struct ws_send_req {
    struct wh_ie_list wh_ies;
    struct wp_ie_list wp_ies;
    uint8_t frame_type;
    uint8_t fhss_type;
    uint8_t gak_index;
    uint16_t multiplex_id;
    const struct eui64 *dst;
    const void *pkt;
    size_t pkt_len;
};

// Frame sent to the RCP and waiting for a confirmation.
struct ws_frame_ctx {
    uint8_t handle;
    uint8_t type;
    struct eui64 dst;
    SLIST_ENTRY(ws_frame_ctx) link;
};

// Define struct ws_frame_list
SLIST_HEAD(ws_frame_ctx_list, ws_frame_ctx);

struct ws_ind {
    const struct rcp_rx_ind *hif;
    struct ieee802154_hdr hdr;
    struct iobuf_read ie_hdr;
    struct iobuf_read ie_wp;
    struct iobuf_read ie_mpx;
    struct ws_neigh *neigh;
};

struct ws_ctx {
    struct rcp rcp;

    char     netname[WS_NETNAME_LEN];
    uint16_t pan_id; // 0xffff if not set
    int pan_version; // -1 if not set
    /*
     * The following does NOT reflect the locally owned GTKs.
     * It is a copy of the latest GTKHASH-IE.
     */
    uint8_t gtkhash[WS_GTK_COUNT][8];
    struct ws_ie_list ie_list; // PAN-Wide/FFN-Wide IEs

    struct ws_jm_ie jm;

    struct ws_phy_config  phy;
    struct ws_fhss_config fhss;
    struct ws_neigh_table neigh_table;

    uint8_t seqno;
    uint8_t  handle_next;
    struct ws_frame_ctx_list frame_ctx_list;
    struct eui64 edfe_src;
    int     eapol_relay_fd;
    uint8_t gak_index;

    void (*on_recv_ind)(struct ws_ctx *ws, struct ws_ind *ind);
    void (*on_recv_cnf)(struct ws_ctx *ws, struct ws_frame_ctx *frame_ctx, const struct rcp_tx_cnf *cnf);
};

void ws_if_recv_ind(struct rcp *rcp, const struct rcp_rx_ind *hif_ind);
void ws_if_recv_cnf(struct rcp *rcp, const struct rcp_tx_cnf *cnf);

int ws_if_send_data(struct ws_ctx *ws,
                    const void *pkt, size_t pkt_len,
                    const struct eui64 *dst);
void ws_if_send_eapol(struct ws_ctx *ws, uint8_t kmp_id,
                      const void *pkt, size_t pkt_len,
                      const struct eui64 *dst,
                      const struct eui64 *ea);
void ws_if_send_pas(struct ws_ctx *ws);
void ws_if_send_pa(struct ws_ctx *ws, uint16_t pan_size, uint16_t routing_cost);
void ws_if_send_pcs(struct ws_ctx *ws);
void ws_if_send_pc(struct ws_ctx *ws);
void ws_if_send(struct ws_ctx *ws, struct ws_send_req *req);

#endif
