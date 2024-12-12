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

struct tls_ctx {
    struct mbedtls_ssl_config  ssl_config;
    struct mbedtls_entropy_context  entropy;
    struct mbedtls_ctr_drbg_context ctr_drbg;
    struct mbedtls_x509_crt   ca_cert;
    struct mbedtls_x509_crt   cert;
    struct mbedtls_pk_context key;
};

void tls_init(struct tls_ctx *tls, int endpoint, const struct iovec *ca_cert, const struct iovec *cert,
              const struct iovec *key);

#endif
