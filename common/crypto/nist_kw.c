/*
 * Copyright (c) 2016-2019, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <mbedtls/nist_kw.h>

#include "nist_kw.h"

int nist_kw_core(bool is_wrap, const uint8_t *key, size_t key_bits,
                 const uint8_t *input, size_t input_size,
                 uint8_t *output, size_t output_size)
{
    mbedtls_nist_kw_context ctx;
    size_t output_len = 0;
    int ret;

    mbedtls_nist_kw_init(&ctx);
    ret = mbedtls_nist_kw_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_bits, is_wrap);
    if (ret)
        goto end;

    if (is_wrap)
        ret = mbedtls_nist_kw_wrap(&ctx, MBEDTLS_KW_MODE_KW, input, input_size,
                                   output, &output_len, output_size);
    else
        ret = mbedtls_nist_kw_unwrap(&ctx, MBEDTLS_KW_MODE_KW, input, input_size,
                                     output, &output_len, output_size);
    if (ret)
        goto end;

end:
    mbedtls_nist_kw_free(&ctx);
    return output_len ? : -EINVAL;
}

int nist_kw_unwrap(const uint8_t *key, size_t key_bits,
                   const uint8_t *input, size_t input_size,
                   uint8_t *output, size_t output_size)
{
    return nist_kw_core(false, key, key_bits, input, input_size, output, output_size);
}

int nist_kw_wrap(const uint8_t *key, size_t key_bits,
                 const uint8_t *input, size_t input_size,
                 uint8_t *output, size_t output_size)
{
    return nist_kw_core(true, key, key_bits, input, input_size, output, output_size);
}

