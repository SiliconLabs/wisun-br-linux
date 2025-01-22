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
#include <string.h>

#include "app_wsbrd/app/commandline.h"
#include "app_wsbrd/net/protocol.h"
#include "common/authenticator/authenticator.h"
#include "common/authenticator/authenticator_radius.h"
#include "common/ws/eapol_relay.h"
#include "common/mbedtls_extra.h"
#include "common/string_extra.h"

#include "ws_auth.h"

void ws_auth_init(struct net_if *net_if, const struct wsbrd_conf *conf, const char ifname[IF_NAMESIZE])
{
    for (int i = 0; i < WS_GTK_COUNT; i++)
        if (memzcmp(conf->auth_cfg.gtk_init[i], 16))
            FATAL(2, "unsupported \"gtk[%d]\"", i);
    for (int i = 0; i < WS_LGTK_COUNT; i++)
        if (memzcmp(conf->auth_cfg.gtk_init[i + WS_GTK_COUNT], 16))
            FATAL(2, "unsupported \"lgtk[%d]\"", i);
    net_if->auth->eapol_relay_fd = eapol_relay_start(ifname);
    auth_start(net_if->auth, &net_if->rcp->eui64, conf->enable_lfn);
}

int ws_auth_fd_eapol_relay(struct net_if *net_if)
{
    return net_if->auth->eapol_relay_fd;
}

void ws_auth_recv_eapol_relay(struct net_if *net_if)
{
    struct in6_addr eapol_target;
    struct auth_supp_ctx *supp;
    struct eui64 supp_eui64;
    uint8_t buf[1500];
    ssize_t buf_len;
    uint8_t kmp_id;

    buf_len = eapol_relay_recv(net_if->auth->eapol_relay_fd, buf, sizeof(buf),
                               &eapol_target, &supp_eui64, &kmp_id);
    if (buf_len < 0)
        return;
    supp = auth_fetch_supp(net_if->auth, &supp_eui64);
    supp->eapol_target = eapol_target;
    auth_recv_eapol(net_if->auth, kmp_id, &supp_eui64, buf, buf_len);
}

int ws_auth_fd_radius(struct net_if *net_if)
{
    return net_if->auth->radius_fd;
}

void ws_auth_recv_radius(struct net_if *net_if)
{
    radius_recv(net_if->auth);
}

const uint8_t *ws_auth_gtk(struct net_if *net_if, int key_index)
{
    return net_if->auth->gtks[key_index - 1].key;
}

static void ws_auth_gtkhash_common(const struct auth_ctx *auth, uint8_t gtkhash[][8], int offset, int count)
{
    uint8_t sha256[32];

    for (int i = 0; i < count; i++) {
        if (timer_stopped(&auth->gtks[i + offset].expiration_timer)) {
            memset(gtkhash[i], 0, 8);
        } else {
            xmbedtls_sha256(auth->gtks[i + offset].key, 16, sha256, 0);
            memcpy(gtkhash[i], sha256 + 24, 8);
        }
    }
}

void ws_auth_gtkhash(struct net_if *net_if, uint8_t gtkhash[WS_GTK_COUNT][8])
{
    ws_auth_gtkhash_common(net_if->auth, gtkhash, 0, WS_GTK_COUNT);
}

void ws_auth_lgtkhash(struct net_if *net_if, uint8_t lgtkhash[WS_LGTK_COUNT][8])
{
    ws_auth_gtkhash_common(net_if->auth, lgtkhash, WS_GTK_COUNT, WS_LGTK_COUNT);
}

uint8_t ws_auth_lgtk_index(struct net_if *net_if)
{
    return net_if->auth->lgtk_group.slot_active - WS_GTK_COUNT;
}

bool ws_auth_is_1st_msg(struct net_if *net_if, const void *buf, size_t buf_len)
{
    return true; // TODO
}

int ws_auth_revoke_pmk(struct net_if *net_if, const struct eui64 *eui64)
{
    return auth_revoke_pmk(net_if->auth, eui64);
}
