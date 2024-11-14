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
#include <stdlib.h>
#include <inttypes.h>
#include <mbedtls/sha256.h>
#if MBEDTLS_VERSION_MAJOR > 2
#include <mbedtls/compat-2.x.h>
#endif
#include "common/crypto/ieee80211.h"
#include "common/crypto/hmac_md.h"
#include "common/crypto/nist_kw.h"
#include "common/rand.h"
#include "common/trickle_legacy.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "net/protocol.h"
#include "ws/ws_config.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/kmp/kmp_addr.h"
#include "security/kmp/kmp_api.h"
#include "security/pana/pana_eap_header.h"
#include "security/eapol/eapol_helper.h"
#include "security/eapol/kde_helper.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "security/protocols/sec_prot.h"

#include "security/protocols/sec_prot_lib.h"

#define TRACE_GROUP "secl"

void sec_prot_init(sec_prot_common_t *data)
{
    data->state = SEC_STATE_INIT;
    data->result = SEC_RESULT_OK;
    data->ticks = SEC_INIT_TIMEOUT;
    data->trickle_running = false;
}

void sec_prot_timer_timeout_handle(sec_prot_t *prot, sec_prot_common_t *data, const trickle_legacy_params_t *trickle_params, uint16_t ticks)
{
    if (data->trickle_running && trickle_params) {
        bool running = trickle_legacy_running(&data->trickle_timer, trickle_params);

        // Checks for trickle timer expiration */
        if (trickle_legacy_tick(&data->trickle_timer, trickle_params, ticks)) {
            sec_prot_result_set(data, SEC_RESULT_TIMEOUT);
            prot->state_machine(prot);
        }

        // Checks if maximum number of trickle timer expirations has happened
        if (running && !trickle_legacy_running(&data->trickle_timer, trickle_params)) {
            sec_prot_result_set(data, SEC_RESULT_TIMEOUT);
            sec_prot_state_set(prot, data, SEC_STATE_FINISH);
        }
    }

    if (data->ticks > ticks) {
        data->ticks -= ticks;
    } else {
        if (data->state != SEC_STATE_FINISHED)
            tr_info("prot timeout, state: %i", data->state);
        data->ticks = 0;
        sec_prot_result_set(data, SEC_RESULT_TIMEOUT);
        if (data->state == SEC_STATE_INIT) {
            sec_prot_state_set(prot, data, SEC_STATE_FINISHED);
        } else {
            sec_prot_state_set(prot, data, SEC_STATE_FINISH);
        }
    }
}

void sec_prot_timer_trickle_start(sec_prot_common_t *data, const trickle_legacy_params_t *trickle_params)
{
    trickle_legacy_start(&data->trickle_timer, "SECURITY", trickle_params);
    trickle_legacy_inconsistent(&data->trickle_timer, trickle_params);
    data->trickle_running = true;
}

void sec_prot_timer_trickle_stop(sec_prot_common_t *data)
{
    trickle_legacy_stop(&data->trickle_timer);
    data->trickle_running = false;
}

void sec_prot_state_set(sec_prot_t *prot, sec_prot_common_t *data, uint8_t state)
{
    switch (state) {
        case SEC_STATE_FINISH:
            if (data->state == SEC_STATE_FINISHED) {
                // Already, do not update state;
            } else {
                data->state = SEC_STATE_FINISH;
            }
            data->trickle_running = false;
            data->ticks = SEC_FINISHED_TIMEOUT;

            // Go to SEC_STATE_FINISH or SEC_STATE_FINISHED
            prot->state_machine(prot);
            return;

        case SEC_STATE_FINISHED:
            // If not already on finished state
            if (data->state != SEC_STATE_FINISHED) {
                // Wait for timeout
                data->ticks = SEC_FINISHED_TIMEOUT;
            }
            data->trickle_running = false;

            // Disables receiving of messages when state machine sets SEC_STATE_FINISHED
            prot->receive_disable(prot);

            // Clear result
            sec_prot_result_set(data, SEC_RESULT_OK);
            break;

        case SEC_STATE_INIT:
            data->state = SEC_STATE_INIT;
            prot->state_machine(prot);
            return;

        default:
            break;
    }

    data->state = state;
}

uint8_t sec_prot_state_get(sec_prot_common_t *data)
{
    return data->state;
}

void sec_prot_result_set(sec_prot_common_t *data, sec_prot_result_e result)
{
    data->result = result;
}

sec_prot_result_e sec_prot_result_get(sec_prot_common_t *data)
{
    return data->result;
}

bool sec_prot_result_timeout_check(sec_prot_common_t *data)
{
    if (data->result == SEC_RESULT_TIMEOUT) {
        data->result = SEC_RESULT_OK;
        return true;
    }
    return false;
}

bool sec_prot_result_ok_check(sec_prot_common_t *data)
{
    if (data->result == SEC_RESULT_OK) {
        return true;
    }
    return false;
}

void sec_prot_default_timeout_set(sec_prot_common_t *data)
{
    data->ticks = SEC_TOTAL_TIMEOUT;
}

void sec_prot_lib_nonce_generate(uint8_t *nonce)
{
    // Use randlib
    rand_get_n_bytes_random(nonce, EAPOL_KEY_NONCE_LEN);
}

/*
 * From IEEE 802.11 how to init nonce calculation by using non-secure random
 *
 * PRF-256(Random number, “Init Counter”, Local MAC Address || Time)
 */
void sec_prot_lib_nonce_init(uint8_t *nonce, uint8_t *eui64, uint64_t time)
{
    uint8_t random[EAPOL_KEY_NONCE_LEN];
    uint8_t buffer[EUI64_LEN + sizeof(uint64_t)];

    memcpy(buffer + 0, eui64, EUI64_LEN);
    memcpy(buffer + EUI64_LEN, &time, sizeof(uint64_t));
    rand_get_n_bytes_random(random, EAPOL_KEY_NONCE_LEN);
    ieee80211_prf(random, EAPOL_KEY_NONCE_LEN, "Init Counter", buffer, sizeof(buffer), nonce, EAPOL_KEY_NONCE_LEN);
}

/*
 * PTK = PRF-384(PMK, “Pairwise key expansion”, Min(AUTH EUI-64, SUP EUI-64) ||
 *       Max(AUTH EUI-64, SUP EUI-64) || Min (Anonce, Snonce) || Max(Anonce, Snonce))
 *
 * PMK is 256 bits, PTK is 382 bits
 */
void sec_prot_lib_ptk_calc(const uint8_t *pmk, const uint8_t *eui64_1, const uint8_t *eui64_2, const uint8_t *nonce1, const uint8_t *nonce2, uint8_t *ptk)
{
    uint8_t buffer[EUI64_LEN + EUI64_LEN + EAPOL_KEY_NONCE_LEN + EAPOL_KEY_NONCE_LEN];
    const uint8_t *min_eui64 = eui64_1;
    const uint8_t *max_eui64 = eui64_2;
    const uint8_t *min_nonce = nonce1;
    const uint8_t *max_nonce = nonce2;

    if (memcmp(eui64_1, eui64_2, EUI64_LEN) > 0) {
        min_eui64 = eui64_2;
        max_eui64 = eui64_1;
    }
    if (memcmp(nonce1, nonce2, EAPOL_KEY_NONCE_LEN) > 0) {
        min_nonce = nonce2;
        max_nonce = nonce1;
    }

    memcpy(buffer, min_eui64, EUI64_LEN);
    memcpy(buffer + EUI64_LEN, max_eui64, EUI64_LEN);
    memcpy(buffer + EUI64_LEN + EUI64_LEN, min_nonce, EAPOL_KEY_NONCE_LEN);
    memcpy(buffer + EUI64_LEN + EUI64_LEN + EAPOL_KEY_NONCE_LEN, max_nonce, EAPOL_KEY_NONCE_LEN);

    ieee80211_prf(pmk, PMK_LEN, "Pairwise key expansion", buffer, sizeof(buffer), ptk, PTK_LEN);

#ifdef EXTRA_DEBUG_INFO
    tr_debug("PTK EUI: %s %s", tr_eui64(eui64_1), tr_eui64(eui64_2));
    tr_debug("PTK NONCE: %s %s", trace_array(nonce1, 32), trace_array(nonce2, 32));
    tr_debug("PTK: %s", trace_array(ptk, PTK_LEN));
#endif
}

int8_t sec_prot_lib_pmkid_calc(const uint8_t *pmk, const uint8_t *auth_eui64, const uint8_t *supp_eui64, uint8_t *pmkid)
{
    const uint8_t pmk_string_val[] = {"PMK Name"};
    const uint8_t pmk_string_val_len = sizeof(pmk_string_val) - 1;

    uint8_t data_len = pmk_string_val_len + EUI64_LEN + EUI64_LEN;
    uint8_t data[data_len];
    uint8_t *ptr = data;
    memcpy(ptr, pmk_string_val, pmk_string_val_len);
    ptr += pmk_string_val_len;
    memcpy(ptr, auth_eui64, EUI64_LEN);
    ptr += EUI64_LEN;
    memcpy(ptr, supp_eui64, EUI64_LEN);

    hmac_md_sha1(pmk, PMK_LEN, data, data_len, pmkid, PMKID_LEN);

    tr_debug("PMKID %s EUI-64 %s %s", trace_array(pmkid, PMKID_LEN), tr_eui64(auth_eui64), tr_eui64(supp_eui64));
    return 0;
}

int8_t sec_prot_lib_ptkid_calc(const uint8_t *ptk, const uint8_t *auth_eui64, const uint8_t *supp_eui64, uint8_t *ptkid)
{
    const uint8_t ptk_string_val[] = {"PTK Name"};
    const uint8_t ptk_string_val_len = sizeof(ptk_string_val) - 1;

    uint8_t data_len = ptk_string_val_len + EUI64_LEN + EUI64_LEN;
    uint8_t data[data_len];
    uint8_t *ptr = data;
    memcpy(ptr, ptk_string_val, ptk_string_val_len);
    ptr += ptk_string_val_len;
    memcpy(ptr, auth_eui64, EUI64_LEN);
    ptr += EUI64_LEN;
    memcpy(ptr, supp_eui64, EUI64_LEN);

    hmac_md_sha1(ptk, PTK_LEN, data, data_len, ptkid, PTKID_LEN);

    tr_info("PTKID %s EUI-64 %s %s", trace_array(ptkid, PTKID_LEN), tr_eui64(auth_eui64), tr_eui64(supp_eui64));
    return 0;
}

uint8_t *sec_prot_lib_message_build(uint8_t *ptk, uint8_t *kde, uint16_t kde_len, eapol_pdu_t *eapol_pdu, uint16_t eapol_pdu_size, uint8_t header_size)
{
    uint8_t *eapol_pdu_frame = malloc(header_size + eapol_pdu_size);

    if (!eapol_pdu_frame) {
        return NULL;
    }

    uint8_t *eapol_kde = eapol_write_pdu_frame(eapol_pdu_frame + header_size, eapol_pdu);

    if (kde) {
        if (eapol_pdu->msg.key.key_information.encrypted_key_data) {
            int output_len = nist_kw_wrap(&ptk[KEK_INDEX], 128,
                                             kde, kde_len - 8,
                                             eapol_kde, kde_len);
            if (output_len != kde_len) {
                free(eapol_pdu_frame);
                return NULL;
            }
        } else {
            memcpy(eapol_kde, kde, kde_len);
        }
    }

    if (eapol_pdu->msg.key.key_information.key_mic) {
        uint8_t mic[EAPOL_KEY_MIC_LEN];
        hmac_md_sha1(ptk, KCK_LEN, eapol_pdu_frame + header_size, eapol_pdu_size, mic, EAPOL_KEY_MIC_LEN);
        eapol_write_key_packet_mic(eapol_pdu_frame + header_size, mic);
    }

    return eapol_pdu_frame;
}

uint8_t *sec_prot_lib_message_handle(uint8_t *ptk, uint16_t *kde_len, eapol_pdu_t *eapol_pdu)
{
    if (eapol_pdu->msg.key.key_data_length == 0 || eapol_pdu->msg.key.key_data == NULL) {
        return NULL;
    }

    const uint8_t *key_data = eapol_pdu->msg.key.key_data;
    uint16_t key_data_len = eapol_pdu->msg.key.key_data_length;

    uint8_t *kde = malloc(key_data_len);
    *kde_len = key_data_len;

    if (kde) {
        if (eapol_pdu->msg.key.key_information.encrypted_key_data) {
            int output_len = nist_kw_unwrap(&ptk[KEK_INDEX], 128,
                                            key_data, key_data_len,
                                            kde, eapol_pdu->msg.key.key_data_length);
            if (output_len != key_data_len - 8) {
                tr_error("Decrypt failed");
                free(kde);
                return NULL;
            }
            *kde_len = output_len;
        } else {
            memcpy(kde, key_data, *kde_len);
        }

        return kde;
    }

    return NULL;
}

int8_t sec_prot_lib_mic_validate(uint8_t *ptk, const uint8_t *mic, uint8_t *pdu, uint8_t pdu_size)
{
    uint8_t recv_mic[EAPOL_KEY_MIC_LEN];
    memcpy(recv_mic, mic, EAPOL_KEY_MIC_LEN);

    eapol_write_key_packet_mic(pdu, 0);

    uint8_t calc_mic[EAPOL_KEY_MIC_LEN];
    hmac_md_sha1(ptk, EAPOL_KEY_MIC_LEN, pdu, pdu_size, calc_mic, EAPOL_KEY_MIC_LEN);
    if (memcmp(recv_mic, calc_mic, EAPOL_KEY_MIC_LEN) != 0) {
        tr_error("MIC invalid");
        return -1;
    }
    return 0;
}

int8_t sec_prot_lib_pmkid_generate(sec_prot_t *prot, uint8_t *pmkid, bool is_auth, bool alt_remote_eui64_use, uint8_t *used_remote_eui64)
{
    uint8_t *pmk = sec_prot_keys_pmk_get(prot->sec_keys);
    if (!pmk) {
        return -1;
    }

    uint8_t local_eui64[8];
    uint8_t remote_eui64[8];
    // Tries to get the EUI-64 that is validated by PTK procedure or bound to supplicant entry
    uint8_t *remote_eui64_ptr = sec_prot_keys_ptk_eui_64_get(prot->sec_keys);
    if (remote_eui64_ptr && !alt_remote_eui64_use) {
        memcpy(remote_eui64, remote_eui64_ptr, 8);
        prot->addr_get(prot, local_eui64, NULL);
    } else {
        // If request is for alternative EUI-64, but PTK EUI-64 is not present, returns failure
        if (alt_remote_eui64_use && !remote_eui64_ptr) {
            return -1;
        }
        // If validated EUI-64 is not present, use the remote EUI-64
        prot->addr_get(prot, local_eui64, remote_eui64);
    }

    if (used_remote_eui64 != NULL) {
        memcpy(used_remote_eui64, remote_eui64, 8);
    }

    if (is_auth) {
        return sec_prot_lib_pmkid_calc(pmk, local_eui64, remote_eui64, pmkid);
    } else {
        return sec_prot_lib_pmkid_calc(pmk, remote_eui64, local_eui64, pmkid);
    }
}

int8_t sec_prot_lib_ptkid_generate(sec_prot_t *prot, uint8_t *ptkid, bool is_auth)
{
    uint8_t local_eui64[8];
    prot->addr_get(prot, local_eui64, NULL);
    uint8_t *ptk = sec_prot_keys_ptk_get(prot->sec_keys);
    if (!ptk) {
        return -1;
    }
    // Uses always the EUI-64 that is validated by PTK procedure or bound to supplicant entry
    uint8_t *remote_eui64 = sec_prot_keys_ptk_eui_64_get(prot->sec_keys);
    if (!remote_eui64) {
        return -1;
    }

    if (is_auth) {
        return sec_prot_lib_ptkid_calc(ptk, local_eui64, remote_eui64, ptkid);
    } else {
        return sec_prot_lib_ptkid_calc(ptk, remote_eui64, local_eui64, ptkid);
    }
}

int8_t sec_prot_lib_gtkhash_generate(uint8_t *gtk, uint8_t *gtk_hash)
{
    int8_t ret_val = 0;

    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    if (mbedtls_sha256_starts_ret(&ctx, 0) != 0) {
        ret_val = -1;
        goto error;
    }

    if (mbedtls_sha256_update_ret(&ctx, gtk, 16) != 0) {
        ret_val = -1;
        goto error;
    }

    uint8_t output[32];

    if (mbedtls_sha256_finish_ret(&ctx, output) != 0) {
        ret_val = -1;
        goto error;
    }

    memcpy(gtk_hash, &output[24], 8);

error:
    mbedtls_sha256_free(&ctx);

    return ret_val;
}

uint8_t *sec_prot_remote_eui_64_addr_get(sec_prot_t *prot)
{
    if (prot->sec_keys && prot->sec_keys->ptk_eui_64_set) {
        return prot->sec_keys->ptk_eui_64;
    } else {
        static uint8_t remote_eui64[8];
        memset(remote_eui64, 0, 8);
        prot->addr_get(prot, NULL, (uint8_t *) &remote_eui64);
        return remote_eui64;
    }
}

