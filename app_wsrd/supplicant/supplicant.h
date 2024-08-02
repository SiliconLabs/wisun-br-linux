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

#include "common/rfc8415_txalg.h"
#include "common/pktbuf.h"
#include "common/timer.h"

struct ws_gtk {
    uint8_t slot;
    uint8_t gtk[16];
    struct timer_entry expiration_timer;
};

struct supplicant_ctx {
    uint8_t eui64[8];
    bool running;

    struct mbedtls_ssl_config  ssl_config;
    struct mbedtls_ssl_context ssl_ctx;
    struct mbedtls_entropy_context  entropy;
    struct mbedtls_ctr_drbg_context ctr_drbg;
    struct mbedtls_x509_crt   ca_cert;
    struct mbedtls_x509_crt   cert;
    struct mbedtls_pk_context key;

    bool eap_tls_start_received;

    // EAP-TLS TX Fragmentation
    struct pktbuf tx_buffer;
    int fragment_id;

    // EAP-TLS RX Fragmentation
    struct pktbuf rx_buffer;
    uint32_t expected_rx_len;

    // EAP Retransmission
    struct pktbuf rt_buffer;
    int     last_eap_identifier;
    uint8_t last_tx_eap_type;

    // 4WH and 2WH
    struct ws_gtk gtks[7];
    uint8_t authenticator_eui64[8];
    int64_t replay_counter;
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t pmk[32]; // stored in cleartext in RAM

    /*
     * +-----------------------------------------------------------+
     * |                Pairwise Transient Key (PTK)               |
     * +-----------------------------------------------------------+
     * | KCK (16 bytes) | KEK (16 bytes) | Temporal Key (16 bytes) |
     * +-----------------------------------------------------------+
     *
     * where,
     * KCK = Key Confirmation Key
     * KEK = Key Encryption Key
     */
    uint8_t ptk[48];

    struct rfc8415_txalg key_request_txalg;
    struct timer_entry   failure_timer;

    void (*sendto_mac)(struct supplicant_ctx *supp, uint8_t kmp_id, const void *pkt,
                       size_t pkt_len, const uint8_t dst[8]);
    uint8_t *(*get_target)(struct supplicant_ctx *supp);
    void (*on_gtk_change)(struct supplicant_ctx *supp, const uint8_t gtk[16], uint8_t index);
    void (*on_failure)(struct supplicant_ctx *supp);
};

void supp_init(struct supplicant_ctx *supp, struct iovec *ca_cert, struct iovec *cert, struct iovec *key,
               const uint8_t eui64[8]);
void supp_reset(struct supplicant_ctx *supp);
void supp_eap_tls_reset(struct supplicant_ctx *supp);
bool supp_has_gtk(struct supplicant_ctx *supp, uint8_t gtkhash[8], uint8_t gtk_index);
void supp_start_key_request(struct supplicant_ctx *supp);

void supp_recv_eapol(struct supplicant_ctx *supp, uint8_t kmp_id, const uint8_t *buf, size_t buf_len,
                     const uint8_t authenticator_eui64[8]);
void supp_send_eapol(struct supplicant_ctx *supp, uint8_t kmp_id, struct pktbuf *buf);

void supp_on_eap_success(struct supplicant_ctx *supp);

#endif
