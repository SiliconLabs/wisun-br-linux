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
#ifndef SUPPLICANT_H
#define SUPPLICANT_H

/*
 * Wi-SUN defines "EAPOL Over 802.15.4" (See Wi-SUN FAN 1.1v08 - 6.5.2.1 EAPOL
 * Over 802.15.4) which is based on several specifications from the IEEE and the
 * IETF.
 * The following diagram summarizes the usage of these specifications and their
 * links.
 *
 *   MPX +- KMP +- MKA - EAPoL - EAP - EAP-TLS - TLS
 *    |      |- 4WH - EAPoL
 *    |      `- GKH - EAPoL
 *    `- 6LoWPAN
 *
 * IEEE 802.15.9: MPX, KMP
 * IEEE 802.11:   MKA, 4WH, GKH
 * IEEE 802.1X:   EAPoL
 * RFC 3748:      EAP
 * RFC 5216:      EAP-TLS
 * RFC 5246:      TLS (1.2)
 */

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

#include <netinet/in.h>
#include <stdbool.h>

#include "common/crypto/ws_keys.h"
#include "common/crypto/tls.h"
#include "common/rfc8415_txalg.h"
#include "common/pktbuf.h"
#include "common/timer.h"

struct supp_ctx {
    uint8_t eui64[8];
    bool running;

    struct tls_client_ctx tls_client;
    struct tls_ctx tls;

    bool eap_tls_start_received;

    // EAP-TLS TX Fragmentation
    int fragment_id;

    // EAP-TLS RX Fragmentation
    uint32_t expected_rx_len;

    // EAP Retransmission
    struct pktbuf rt_buffer;
    int     last_eap_identifier;
    uint8_t last_tx_eap_type;

    // 4WH and 2WH
    struct ws_gtk gtks[WS_GTK_COUNT + WS_LGTK_COUNT];
    uint8_t authenticator_eui64[8];
    uint8_t anonce[32];
    uint8_t snonce[32];

    struct rfc8415_txalg key_request_txalg;
    struct timer_entry   failure_timer;
    struct timer_group   timer_group;
    /*
     * Arbitrary timeout between authentication steps:
     *   - TX EAP Response  -> RX EAP Request
     *   - RX EAP Success   -> RX 4WH Message 1
     *   - TX 4WH Message 2 -> RX 4WH Message 3
     * supp.on_failure() is called when this timer expires.
     */
    uint64_t timeout_ms;

    void (*sendto_mac)(struct supp_ctx *supp, uint8_t kmp_id, const void *pkt,
                       size_t pkt_len, const uint8_t dst[8]);
    uint8_t *(*get_target)(struct supp_ctx *supp);
    void (*on_gtk_change)(struct supp_ctx *supp, const uint8_t gtk[16], uint8_t index);
    void (*on_failure)(struct supp_ctx *supp);
};

void supp_init(struct supp_ctx *supp, struct iovec *ca_cert, struct iovec *cert, struct iovec *key,
               const uint8_t eui64[8]);
void supp_reset(struct supp_ctx *supp);
bool supp_gtkhash_mismatch(struct supp_ctx *supp, const uint8_t gtkhash[8], uint8_t key_index);
void supp_start_key_request(struct supp_ctx *supp);

void supp_recv_eapol(struct supp_ctx *supp, uint8_t kmp_id, const uint8_t *buf, size_t buf_len,
                     const uint8_t authenticator_eui64[8]);
void supp_send_eapol(struct supp_ctx *supp, uint8_t kmp_id, const void *buf, size_t buf_len);

void supp_on_eap_success(struct supp_ctx *supp);

#endif
