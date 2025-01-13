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

struct tls_io {
    struct pktbuf tx;
    struct pktbuf rx;
};

struct tls_client_ctx {
    struct mbedtls_ssl_context ssl_ctx;
    struct tls_pmk pmk;
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
void tls_export_keys(void *p_expkey, mbedtls_ssl_key_export_type type, const unsigned char *secret,
                     size_t secret_len, const unsigned char client_random[32],
                     const unsigned char server_random[32], mbedtls_tls_prf_types tls_prf_type);
void tls_init_client(struct tls_ctx *tls, struct tls_client_ctx *tls_client);
void tls_init(struct tls_ctx *tls, int endpoint, const struct iovec *ca_cert, const struct iovec *cert,
              const struct iovec *key);

#endif
