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

#include <string.h>
#include <stdint.h>
#include <mbedtls/version.h>
#include <mbedtls/nist_kw.h>
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "service_libs/nist_aes_kw/nist_aes_kw.h"

#define TRACE_GROUP "naes"

int8_t nist_aes_key_wrap(uint8_t is_wrap, const uint8_t *key, int16_t key_bits, const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len)
{
    int8_t ret_val = 0;
    mbedtls_nist_kw_context ctx;

    mbedtls_nist_kw_init(&ctx);

    if (mbedtls_nist_kw_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_bits, is_wrap) != 0) {
        ret_val = -1;
        goto error;
    }

    size_t out_size = *output_len;

    if (is_wrap) {
        if (mbedtls_nist_kw_wrap(&ctx, MBEDTLS_KW_MODE_KW, input, input_len, output, output_len, out_size) != 0) {
            ret_val = -1;
            goto error;
        }
    } else {
        if (mbedtls_nist_kw_unwrap(&ctx, MBEDTLS_KW_MODE_KW, input, input_len, output, output_len, out_size) != 0) {
            ret_val = -1;
            goto error;
        }
    }

error:
    mbedtls_nist_kw_free(&ctx);

    return ret_val;
}

