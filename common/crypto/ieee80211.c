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
#include "common/specs/ieee80211.h"
#include "common/specs/eapol.h"
#include "common/crypto/hmac_md.h"
#include "common/time_extra.h"
#include "common/rand.h"
#include "common/log.h"
#include "common/mathutils.h"
#include "common/mbedtls_extra.h"
#include "common/eapol.h"

#include "ieee80211.h"

bool ieee80211_is_mic_valid(const uint8_t ptk[48], const struct eapol_key_frame *frame,
                            const uint8_t *data, size_t data_len)
{
    struct eapol_hdr eapol = {
        .protocol_version   = EAPOL_PROTOCOL_VERSION,
        .packet_type        = EAPOL_PACKET_TYPE_KEY,
        .packet_body_length = htobe16(sizeof(*frame) + data_len),
    };
    mbedtls_md_context_t sha1;
    uint8_t hmac[20] = { };

    mbedtls_md_init(&sha1);
    xmbedtls_md_setup(&sha1, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    xmbedtls_md_hmac_starts(&sha1, ieee80211_kck(ptk), IEEE80211_AKM_1_KCK_LEN_BYTES);
    xmbedtls_md_hmac_update(&sha1, (uint8_t *)&eapol, sizeof(eapol));
    xmbedtls_md_hmac_update(&sha1, (uint8_t *)frame, offsetof(struct eapol_key_frame, mic));
    xmbedtls_md_hmac_update(&sha1, hmac, sizeof(frame->mic));
    xmbedtls_md_hmac_update(&sha1, (uint8_t *)frame + offsetof(struct eapol_key_frame, mic) + sizeof(frame->mic),
                            sizeof(*frame) - offsetof(struct eapol_key_frame, mic) - sizeof(frame->mic));
    xmbedtls_md_hmac_update(&sha1, data, data_len);
    xmbedtls_md_hmac_finish(&sha1, hmac);
    mbedtls_md_free(&sha1);
    return !memcmp(hmac, frame->mic, sizeof(frame->mic));
}

void ieee80211_prf(const uint8_t *key, size_t key_len, const char *label,
                   const uint8_t *data, size_t data_len,
                   uint8_t *result, size_t result_size)
{
    // Original algorithm works on block of 160 bits. This implementation refers
    // to 20 bytes instead.
    mbedtls_md_context_t sha1;
    uint8_t hmac[20];

    mbedtls_md_init(&sha1);
    xmbedtls_md_setup(&sha1, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    for (uint8_t i = 0; i < roundup(result_size, 20) / 20; i++) {
        xmbedtls_md_hmac_starts(&sha1, key, key_len);
        xmbedtls_md_hmac_update(&sha1, (uint8_t *)label, strlen(label) + 1); // A + Y
        xmbedtls_md_hmac_update(&sha1, data, data_len);                      // B
        xmbedtls_md_hmac_update(&sha1, &i, 1);                               // X
        xmbedtls_md_hmac_finish(&sha1, hmac);
        memcpy(result + i * 20, hmac, MIN(20, result_size - i * 20));
    }
    mbedtls_md_free(&sha1);
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

void ieee80211_derive_ptk384(const uint8_t pmk[32], const uint8_t auth_eui64[8], const uint8_t supp_eui64[8],
                             const uint8_t auth_nonce[32], const uint8_t supp_nonce[32], uint8_t ptk[48])
{
    struct {
        uint8_t min_eui64[8];
        uint8_t max_eui64[8];
        uint8_t min_nonce[32];
        uint8_t max_nonce[32];
    } data;

    memcpy(data.min_eui64, auth_eui64, sizeof(data.min_eui64));
    memcpy(data.max_eui64, supp_eui64, sizeof(data.max_eui64));
    memcpy(data.min_nonce, auth_nonce, sizeof(data.min_nonce));
    memcpy(data.max_nonce, supp_nonce, sizeof(data.max_nonce));

    if (memcmp(auth_eui64, supp_eui64, 8) > 0) {
        memcpy(data.min_eui64, supp_eui64, sizeof(data.min_eui64));
        memcpy(data.max_eui64, auth_eui64, sizeof(data.max_eui64));
    }
    if (memcmp(auth_nonce, supp_nonce, 32) > 0) {
        memcpy(data.min_nonce, supp_nonce, sizeof(data.min_nonce));
        memcpy(data.max_nonce, auth_nonce, sizeof(data.max_nonce));
    }
    ieee80211_prf(pmk, 32, "Pairwise key expansion", (const uint8_t *)&data, sizeof(data), ptk, 48);
}

void ieee80211_derive_pmkid(const uint8_t pmk[32], const uint8_t auth_eui64[8], const uint8_t supp_eui64[8],
                            uint8_t pmkid[16])
{
    struct {
        uint8_t pmk_name[8];
        uint8_t auth_eui64[8];
        uint8_t supp_eui64[8];
    } data = {
        .pmk_name = "PMK Name",
    };

    memcpy(data.auth_eui64, auth_eui64, sizeof(data.auth_eui64));
    memcpy(data.supp_eui64, supp_eui64, sizeof(data.supp_eui64));
    hmac_md_sha1(pmk, 32, (const uint8_t *)&data, sizeof(data), pmkid, 16);
}
