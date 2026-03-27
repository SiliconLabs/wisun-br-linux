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

#include "common/config.h"
#include "common/pktbuf.h"

struct tls_client_ctx {
    struct mbedtls_ssl_context ssl_ctx;
    struct pktbuf io_tx;
    struct pktbuf io_rx;
};

struct tls_ctx {
    struct mbedtls_ssl_config  ssl_config;
    struct mbedtls_entropy_context  entropy;
    struct mbedtls_ctr_drbg_context ctr_drbg;
    struct mbedtls_x509_crt   ca_cert;
    struct mbedtls_x509_crt   cert;
    struct mbedtls_pk_context key;
};

struct tls_cfg {
    struct iovec ca_cert;
    struct iovec cert;
    struct iovec key;
};

extern const struct option_struct tls_opts[];

int tls_send(void *ctx, const unsigned char *buf, size_t len);
int tls_recv(void *ctx, unsigned char *buf, size_t len);
void tls_free_client(struct tls_client_ctx *tls_client);
void tls_init_client(struct tls_ctx *tls, struct tls_client_ctx *tls_client,
                     mbedtls_ssl_export_keys_t *f_export_keys,
                     void *p_export_keys);
int tls_load_pem(struct mbedtls_x509_crt *cert, const uint8_t *buf, size_t buf_len);
void tls_debug(void *ctx, int level, const char *file, int line, const char *string);
void tls_init(struct tls_ctx *tls, int endpoint, const struct tls_cfg *cfg);

#endif
