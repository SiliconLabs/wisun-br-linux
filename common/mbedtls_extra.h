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
#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>

#if MBEDTLS_VERSION_NUMBER < 0x03020000
static inline bool mbedtls_ssl_is_handshake_over(struct mbedtls_ssl_context *ssl_ctx) {
    return ssl_ctx->private_state == MBEDTLS_SSL_HANDSHAKE_OVER;
}
#endif

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
