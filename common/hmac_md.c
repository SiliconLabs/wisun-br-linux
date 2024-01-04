/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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
#include <errno.h>
#include <mbedtls/md.h>

#include "common/endian.h"
#include "common/log.h"

#include "hmac_md.h"

static int hmac_md_calc(mbedtls_md_type_t md_type,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *result, size_t result_len)
{
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t ctx;
    uint8_t result_value[20];
    int ret;

    BUG_ON(result_len > 20);
    mbedtls_md_init(&ctx);
    md_info = mbedtls_md_info_from_type(md_type);
    ret = mbedtls_md_setup(&ctx, md_info, 1);
    if (ret)
        goto error;
    ret = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (ret)
        goto error;
    ret = mbedtls_md_hmac_update(&ctx, data, data_len);
    if (ret)
        goto error;
    mbedtls_md_hmac_finish(&ctx, result_value);
    if (ret)
        goto error;
    mbedtls_md_free(&ctx);
    memcpy(result, result_value, result_len);

    return 0;

error:
    mbedtls_md_free(&ctx);
    return -EINVAL;
}

int hmac_md_sha1(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *result, size_t result_len)
{
    return hmac_md_calc(MBEDTLS_MD_SHA1, key, key_len, data, data_len, result, result_len);
}

int hmac_md_md5(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *result, size_t result_len)
{
    return hmac_md_calc(MBEDTLS_MD_MD5, key, key_len, data, data_len, result, result_len);
}
