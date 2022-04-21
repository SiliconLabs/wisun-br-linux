/*
 * Copyright (c) 2006-2020, Pelion and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef NS_SHA256_H_
#define NS_SHA256_H_

#include <string.h>
#include <mbedtls/sha256.h>

typedef mbedtls_sha256_context ns_sha256_context;

static inline void ns_sha256_init(ns_sha256_context *ctx)
{
    mbedtls_sha256_init(ctx);
}

static inline void ns_sha256_free(ns_sha256_context *ctx)
{
    mbedtls_sha256_free(ctx);
}

static inline void ns_sha256_clone(ns_sha256_context *dst,
                                   const ns_sha256_context *src)
{
    mbedtls_sha256_clone(dst, src);
}

static inline void ns_sha256_starts(ns_sha256_context *ctx)
{
#if (MBEDTLS_VERSION_MAJOR >= 3)
    (void)mbedtls_sha256_starts(ctx, 0);
#else
    (void)mbedtls_sha256_starts_ret(ctx, 0);
#endif
}

static inline void ns_sha256_update(ns_sha256_context *ctx, const void *input,
                                    size_t ilen)
{
#if (MBEDTLS_VERSION_MAJOR >= 3)
    (void)mbedtls_sha256_update(ctx, input, ilen);
#else
    (void)mbedtls_sha256_update_ret(ctx, input, ilen);
#endif
}

static inline void ns_sha256_finish(ns_sha256_context *ctx, void *output)
{
#if (MBEDTLS_VERSION_MAJOR >= 3)
    (void)mbedtls_sha256_finish(ctx, output);
#else
    (void)mbedtls_sha256_finish_ret(ctx, output);
#endif
}

static inline void ns_sha256(const void *input, size_t ilen, void *output)
{
#if (MBEDTLS_VERSION_MAJOR >= 3)
    (void)mbedtls_sha256(input, ilen, output, 0);
#else
    (void)mbedtls_sha256_ret(input, ilen, output, 0);
#endif
}

/* Extensions to standard mbed TLS - output the first bits of a hash only */
/* Number of bits must be a multiple of 32, and <=256 */
static inline void ns_sha256_finish_nbits(ns_sha256_context *ctx, void *output, unsigned obits)
{
    if (obits == 256) {
#if (MBEDTLS_VERSION_MAJOR >= 3)
        (void)mbedtls_sha256_finish(ctx, output);
#else
        (void)mbedtls_sha256_finish_ret(ctx, output);
#endif
    } else {
        uint8_t sha256[32];
#if (MBEDTLS_VERSION_MAJOR >= 3)
        (void)mbedtls_sha256_finish(ctx, sha256);
#else
        (void)mbedtls_sha256_finish_ret(ctx, sha256);
#endif
        memcpy(output, sha256, obits / 8);
    }
}

static inline void ns_sha256_nbits(const void *input, size_t ilen, void *output, unsigned obits)
{
    if (obits == 256) {
#if (MBEDTLS_VERSION_MAJOR >= 3)
        (void)mbedtls_sha256(input, ilen, output, 0);
#else
        (void)mbedtls_sha256_ret(input, ilen, output, 0);
#endif
    } else {
        uint8_t sha256[32];
#if (MBEDTLS_VERSION_MAJOR >= 3)
        (void)mbedtls_sha256(input, ilen, sha256, 0);
#else
        (void)mbedtls_sha256_ret(input, ilen, sha256, 0);
#endif
        memcpy(output, sha256, obits / 8);
    }
}



#endif /* NS_SHA256_H_ */
