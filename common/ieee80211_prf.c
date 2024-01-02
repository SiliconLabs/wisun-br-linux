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
#include <mbedtls/md.h>
#include "common/log_legacy.h"
#include "common/hmac_md.h"

#include "ieee80211_prf.h"

int ieee80211_prf(const uint8_t *key, size_t key_len, const char *label,
                  const uint8_t *input, size_t input_len,
                  uint8_t *result, size_t result_size)
{
    int num_bits = result_size * 8;
    int buffer_len = strlen(label) + 1 + input_len + 1;
    uint8_t buffer[buffer_len];
    int res_len = 160 / 8 * (num_bits + 159) / 160;
    uint8_t res_raw[res_len];
    uint8_t *res_ptr = res_raw;
    int ret;
    int i;

    BUG_ON(result_size > res_len);
    strcpy((char *)buffer, label);                        // A
    buffer[strlen(label) + 1] = 0;                        // Y
    memcpy(buffer + strlen(label) + 1, input, input_len); // B
    for (i = 0; i < (num_bits + 159) / 160; i++) {
        buffer[strlen(label) + 1 + input_len] = i;        // X
        ret = hmac_md_sha1(key, key_len, buffer, buffer_len, res_ptr, 20);
        if (ret < 0)
            return ret;
        res_ptr += 160 / 8;
    }

    memcpy(result, res_raw, result_size);
    return 0;
}
