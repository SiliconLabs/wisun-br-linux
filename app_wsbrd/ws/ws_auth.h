/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WS_AUTH_H
#define WS_AUTH_H

#include "common/crypto/ws_keys.h"

struct eui64;
struct net_if;
struct wsbrd_conf;

void ws_auth_init(struct net_if *net_if, const struct wsbrd_conf *conf);

int  ws_auth_fd_eapol_relay(struct net_if *net_if);
void ws_auth_recv_eapol_relay(struct net_if *net_if);
int  ws_auth_fd_radius(struct net_if *net_if);
void ws_auth_recv_radius(struct net_if *net_if);

const uint8_t *ws_auth_gtk(struct net_if *net_if, int key_index);
void ws_auth_gtkhash(struct net_if *net_if, uint8_t gtkhash[WS_GTK_COUNT][8]);
void ws_auth_lgtkhash(struct net_if *net_if, uint8_t lgtkhash[WS_LGTK_COUNT][8]);
uint8_t ws_auth_lgtk_index(struct net_if *net_if);

bool ws_auth_is_1st_msg(struct net_if *net_if, const void *buf, size_t buf_len);

int ws_auth_revoke_pmk(struct net_if *net_if, const struct eui64 *eui64);

#endif
