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
#include "common/ws_types.h"
#include "common/ws_neigh.h"
#include "common/rcp_api.h"
#include "common/iobuf.h"

struct wh_ie_list {
    bool utt:   1;
    bool bt:    1;
    bool fc:    1;
    bool rsl:   1;
    bool ea:    1;
    bool lutt:  1;
    bool lbt:   1;
    bool nr:    1;
    bool lus:   1;
    bool flus:  1;
    bool lbs:   1;
    bool lnd:   1;
    bool lto:   1;
    bool panid: 1;
    bool lbc:   1;
};

struct wp_ie_list {
    bool us:       1;
    bool bs:       1;
    bool pan:      1;
    bool netname:  1;
    bool panver:   1;
    bool gtkhash:  1;
    bool lgtkhash: 1;
    bool lfnver:   1;
    bool lcp:      1;
    bool lbats:    1;
    bool pom:      1;
    bool jm:       1;
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

    struct ws_phy_config  phy;
    struct ws_fhss_config fhss;
    struct ws_neigh_table neigh_table;

    uint8_t seqno;
    uint8_t  handle_next;
    struct ws_frame_ctx_list frame_ctx_list;
    struct eui64 edfe_src;
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
                      const struct eui64 *dst);
void ws_if_send_pas(struct ws_ctx *ws);
void ws_if_send_pcs(struct ws_ctx *ws);

#endif
