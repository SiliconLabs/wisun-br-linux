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
#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <sys/queue.h>
#include <stdint.h>

#include "common/crypto/ws_keys.h"
#include "common/ieee802154_frame.h"
#include "common/pktbuf.h"
#include "common/timer.h"

struct auth_supp_ctx {
    struct eui64 eui64;
    bool is_lfn;

    // Retransmissions
    struct timer_entry rt_timer;
    uint8_t rt_count;
    struct pktbuf rt_buffer;
    uint8_t rt_kmp_id;

    // 4WH and 2WH
    uint8_t last_installed_key_slot;
    uint8_t gtkl;
    uint8_t lgtkl;
    uint8_t  pmk[32]; // stored in cleartext in RAM
    uint64_t pmk_expiration_s;
    uint8_t  ptk[48];
    uint8_t  tptk[48];
    uint64_t ptk_expiration_s;
    uint8_t anonce[32];
    uint8_t snonce[32];
    int64_t replay_counter;

    SLIST_ENTRY(auth_supp_ctx) link;
};

// Declare struct auth_supp_ctx_list
SLIST_HEAD(auth_supp_ctx_list, auth_supp_ctx);

struct auth_cfg {
    int gtk_expire_offset_s;
    int gtk_new_install_required; // Percentage of GTK_EXPIRE_OFFSET
    int gtk_new_activation_time;  // Fraction of GTK_EXPIRE_OFFSET
    int ptk_lifetime_s;
};

struct auth_ctx {
    struct eui64 eui64;

    const struct auth_cfg *cfg;
    struct ws_gtk gtks[4];
    struct timer_entry gtk_activation_timer;
    struct timer_entry gtk_install_timer;
    uint8_t cur_slot;
    uint8_t next_slot;

    struct auth_supp_ctx_list supplicants;
    struct timer_group timer_group;

    void (*sendto_mac)(struct auth_ctx *ctx, uint8_t kmp_id, const void *pkt,
                       size_t pkt_len, const struct eui64 *dst);
    void (*on_gtk_change)(struct auth_ctx *ctx, const uint8_t gtk[16], uint8_t index, bool activate);

    // Called on rx of 4wh msg 4 and gkh msg 2
    void (*on_supp_gtk_installed)(struct auth_ctx *ctx, const struct eui64 *eui64, uint8_t index);
};

void auth_set_supp_pmk(struct auth_ctx *ctx, const struct eui64 *eui64, const uint8_t pmk[32]);
bool auth_get_supp_tk(struct auth_ctx *ctx, const struct eui64 *eui64, uint8_t tk[16]);

void auth_send_eapol(struct auth_ctx *ctx, const struct eui64 *dst, uint8_t kmp_id, struct pktbuf *buf);
void auth_recv_eapol(struct auth_ctx *ctx, uint8_t kmp_id, const struct eui64 *eui64,
                     const uint8_t *buf, size_t buf_len);
void auth_start(struct auth_ctx *ctx, const struct eui64 *eui64);

#endif
