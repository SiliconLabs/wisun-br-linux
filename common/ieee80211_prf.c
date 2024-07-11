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
#include "common/time_extra.h"
#include "common/rand.h"
#include "common/log.h"
#include "common/hmac_md.h"
#include "common/mathutils.h"

#include "ieee80211_prf.h"

int ieee80211_prf(const uint8_t *key, size_t key_len, const char *label,
                  const uint8_t *data, size_t data_len,
                  uint8_t *result, size_t result_size)
{
    // Original algorithm works on block of 160 bits. This implementation refers
    // to 20 bytes instead.
    int input_len = strlen(label) + 1 + data_len + 1;
    int output_len = roundup(result_size, 20);
    uint8_t input[input_len];
    uint8_t output[output_len];
    int ret, i;

    BUG_ON(result_size > output_len);
    strcpy((char *)input, label);                      // A
    input[strlen(label) + 1] = 0;                      // Y
    memcpy(input + strlen(label) + 1, data, data_len); // B
    for (i = 0; i < output_len / 20; i++) {
        input[strlen(label) + 1 + data_len] = i;       // X
        ret = hmac_md_sha1(key, key_len, input, input_len, output + i * 20, 20);
        if (ret < 0)
            return ret;
    }

    memcpy(result, output, result_size);
    return 0;
}

void ieee80211_generate_nonce(const uint8_t eui64[8], uint8_t nonce_out[32])
{
    struct {
        uint8_t  eui64[8];
        uint64_t now;
    } data = {
        .now = time_now_ms(CLOCK_REALTIME),
    };
    uint8_t random[32];

    memcpy(data.eui64, eui64, sizeof(data.eui64));
    rand_get_n_bytes_random(random, sizeof(random));
    ieee80211_prf(random, sizeof(random), "Init Counter", (const uint8_t *)&data, sizeof(data), nonce_out, 32);
}
