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

#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <stdint.h>

#include "common/crypto/ws_keys.h"
#include "common/crypto/tls.h"
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
    uint8_t rt_kmp_id; // 0 is used for RADIUS retransmissions

    // 4WH and 2WH
    int     last_installed_key_slot;
    uint8_t gtkl;
    uint8_t lgtkl;
    struct tls_pmk pmk;
    uint8_t  ptk[48];
    uint8_t  tptk[48];
    uint64_t ptk_expiration_s;
    uint8_t  anonce[32];
    uint8_t  snonce[32];

    uint8_t eap_id;

    int     radius_id;
    uint8_t radius_auth[16];
    uint8_t radius_state[253];
    uint8_t radius_state_len;

    SLIST_ENTRY(auth_supp_ctx) link;
};

// Declare struct auth_supp_ctx_list
SLIST_HEAD(auth_supp_ctx_list, auth_supp_ctx);

struct auth_cfg {
    int gtk_expire_offset_s;
    int gtk_new_install_required; // Percentage of GTK_EXPIRE_OFFSET
    int gtk_new_activation_time;  // Fraction of GTK_EXPIRE_OFFSET
    int pmk_lifetime_s; // 0 for infinite
    int ptk_lifetime_s;
    struct iovec ca_cert;
    struct iovec cert;
    struct iovec key;
    struct sockaddr_storage radius_addr;
    char radius_secret[256];
};

struct auth_ctx {
    struct eui64 eui64;

    struct tls_ctx tls;

    const struct auth_cfg *cfg;
    struct ws_gtk gtks[4];
    struct timer_entry gtk_activation_timer;
    struct timer_entry gtk_install_timer;
    uint8_t cur_slot;
    uint8_t next_slot;

    int     radius_fd;
    uint8_t radius_id_next;

    struct auth_supp_ctx_list supplicants;
    struct timer_group timer_group;
    uint64_t timeout_ms;

    void (*sendto_mac)(struct auth_ctx *auth, uint8_t kmp_id, const void *pkt,
                       size_t pkt_len, const struct eui64 *dst);
    void (*on_gtk_change)(struct auth_ctx *auth, const uint8_t gtk[16], uint8_t index, bool activate);

    // Called on rx of 4wh msg 4 and gkh msg 2
    void (*on_supp_gtk_installed)(struct auth_ctx *auth, const struct eui64 *eui64, uint8_t index);
};

struct auth_supp_ctx *auth_fetch_supp(struct auth_ctx *auth, const struct eui64 *eui64);

bool auth_get_supp_tk(struct auth_ctx *auth, const struct eui64 *eui64, uint8_t tk[16]);

void auth_rt_timer_start(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                         uint8_t kmp_id, const void *buf, size_t buf_len);
void auth_send_eapol(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                     uint8_t kmp_id, const void *buf, size_t buf_len);
void auth_recv_eapol(struct auth_ctx *auth, uint8_t kmp_id, const struct eui64 *eui64,
                     const uint8_t *buf, size_t buf_len);
void auth_start(struct auth_ctx *auth, const struct eui64 *eui64);

#endif
