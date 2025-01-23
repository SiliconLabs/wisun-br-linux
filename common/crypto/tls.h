/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef TLS_H
#define TLS_H

#include <sys/uio.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

#include "common/pktbuf.h"

struct tls_pmk {
    uint8_t  key[32]; // stored in cleartext in RAM
    int64_t  replay_counter; // reset when pmk is established
    uint64_t installation_s; // not used by supplicant
};

struct tls_ptk {
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
    uint8_t  key[48];
    uint64_t expiration_s; // not used by supplicant
    /*
     *   IEEE 802.11-2020, 12.7.9 RSNA Supplicant key management state machine
     * - TPTK. This variable represents the current PTK until message 3 of the
     *         4-way handshake arrives and is verified.
     *
     * [...]
     *
     * NOTE 1 — TPTK is used to stop attackers changing the PTK on the Supplicant
     * by sending the first message of the 4-way handshake.
     */
    uint8_t tkey[48];
};

struct tls_io {
    struct pktbuf tx;
    struct pktbuf rx;
};

struct tls_client_ctx {
    struct mbedtls_ssl_context ssl_ctx;
    struct tls_pmk pmk;
    struct tls_ptk ptk;
    struct tls_io io;
};

struct tls_ctx {
    struct mbedtls_ssl_config  ssl_config;
    struct mbedtls_entropy_context  entropy;
    struct mbedtls_ctr_drbg_context ctr_drbg;
    struct mbedtls_x509_crt   ca_cert;
    struct mbedtls_x509_crt   cert;
    struct mbedtls_pk_context key;
};

int tls_send(void *ctx, const unsigned char *buf, size_t len);
int tls_recv(void *ctx, unsigned char *buf, size_t len);
void tls_install_pmk(struct tls_pmk *pmk, const uint8_t key[32]);
void tls_init_client(struct tls_ctx *tls, struct tls_client_ctx *tls_client);
void tls_init(struct tls_ctx *tls, int endpoint, const struct iovec *ca_cert, const struct iovec *cert,
              const struct iovec *key);

#endif
