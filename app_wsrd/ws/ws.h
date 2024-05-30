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

#include <stddef.h>
#include <stdint.h>

#include "common/ws_ie.h"
#include "common/ws_neigh.h"
#include "common/ws_types.h"
#include "app_wsrd/ipv6/ipv6.h"

struct rcp_rx_ind;

struct ws_ctx {
    char     netname[WS_NETNAME_LEN];
    uint16_t pan_id; // 0xffff if not set
    int pan_version; // -1 if not set
    struct ws_phy_config  phy;
    struct ws_fhss_config fhss;
    struct ws_neigh_table neigh_table;

    uint8_t  seqno;

    struct ipv6_ctx ipv6;
};

void ws_recv_ind(struct ws_ctx *ws, const struct rcp_rx_ind *ind);

void ws_send_data(struct ws_ctx *ws, const void *pkt, size_t pkt_len, const uint8_t dst[8]);

#endif
