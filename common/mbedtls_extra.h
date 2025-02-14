/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef MBEDTLS_EXTRA_H
#define MBEDTLS_EXTRA_H

/*
 * Provides some functions that may not be available depending on mbedtls
 * version and configuration.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef HAVE_MBEDTLS
#include "common/log.h"

#include <mbedtls/build_info.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/pem.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>

#if MBEDTLS_VERSION_NUMBER < 0x03020000
static inline bool mbedtls_ssl_is_handshake_over(struct mbedtls_ssl_context *ssl_ctx) {
    return ssl_ctx->private_state == MBEDTLS_SSL_HANDSHAKE_OVER;
}

static inline const unsigned char *mbedtls_pem_get_buffer(mbedtls_pem_context *ctx, size_t *buflen)
{
    *buflen = ctx->MBEDTLS_PRIVATE(buflen);
    return ctx->MBEDTLS_PRIVATE(buf);
}
#endif

#define XMBEDTLS(func, ...) do {                     \
    int ret;                                         \
                                                     \
    ret = mbedtls_##func(__VA_ARGS__);               \
    FATAL_ON(ret < 0, 2, "%s: mbedtls_%s: %s",       \
             __func__, #func, tr_mbedtls_err(-ret)); \
} while (0)

#define xmbedtls_md_setup(ctx, md_info, hmac)                       XMBEDTLS(md_setup, ctx, md_info, hmac)
#define xmbedtls_md_hmac_starts(ctx, key, keylen)                   XMBEDTLS(md_hmac_starts, ctx, key, keylen)
#define xmbedtls_md_hmac_update(ctx, input, ilen)                   XMBEDTLS(md_hmac_update, ctx, input, ilen)
#define xmbedtls_md_hmac_finish(ctx, output)                        XMBEDTLS(md_hmac_finish, ctx, output)
#define xmbedtls_md_hmac(md_info, key, keylen, input, ilen, output) XMBEDTLS(md_hmac, md_info, key, keylen, input, ilen, output)
#define xmbedtls_md5_starts(ctx)                                    XMBEDTLS(md5_starts, ctx)
#define xmbedtls_md5_update(ctx, input, ilen)                       XMBEDTLS(md5_update, ctx, input, ilen)
#define xmbedtls_md5_finish(ctx, output)                            XMBEDTLS(md5_finish, ctx, output)
#define xmbedtls_sha256_starts(ctx, is224)                          XMBEDTLS(sha256_starts, ctx, is224)
#define xmbedtls_sha256_update(ctx, input, ilen)                    XMBEDTLS(sha256_update, ctx, input, ilen)
#define xmbedtls_sha256_finish(ctx, output)                         XMBEDTLS(sha256_finish, ctx, output)
#define xmbedtls_sha256(input, ilen, output, is224)                 XMBEDTLS(sha256, input, ilen, output, is224)

#endif

#ifdef MBEDTLS_ERROR_C
#include <mbedtls/error.h>
#else
static inline void mbedtls_strerror(int err, char *out, size_t out_len)
{
    snprintf(out, out_len, "-0x%04x", -err);
}
#endif

#endif
