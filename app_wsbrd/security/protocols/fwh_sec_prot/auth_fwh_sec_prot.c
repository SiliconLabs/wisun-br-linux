/*
 * Copyright (c) 2016-2021, Pelion and affiliates.
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
#include "common/crypto/hmac_md.h"
#include "common/log.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/nist_kw.h"
#include "common/specs/ws.h"

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

#include "security/protocols/fwh_sec_prot/auth_fwh_sec_prot.h"

#define TRACE_GROUP "afwh"

typedef enum {
    FWH_STATE_INIT = SEC_STATE_INIT,
    FWH_STATE_CREATE_REQ = SEC_STATE_CREATE_REQ,
    FWH_STATE_MESSAGE_2 = SEC_STATE_FIRST,
    FWH_STATE_MESSAGE_4,
    FWH_STATE_FINISH = SEC_STATE_FINISH,
    FWH_STATE_FINISHED = SEC_STATE_FINISHED
} fwh_sec_prot_state_e;

typedef enum {
    FWH_MESSAGE_UNKNOWN = 0,
    FWH_MESSAGE_1,
    FWH_MESSAGE_2,
    FWH_MESSAGE_3,
    FWH_MESSAGE_4
} fwh_sec_prot_msg_e;

typedef struct fwh_sec_prot_int {
    sec_prot_common_t             common;                      /**< Common data */
    eapol_pdu_t                   recv_eapol_pdu;              /**< Received EAPOL PDU */
    fwh_sec_prot_msg_e            recv_msg;                    /**< Received message */
    uint8_t                       nonce[EAPOL_KEY_NONCE_LEN];  /**< Authenticator nonce */
    uint8_t                       new_ptk[PTK_LEN];            /**< PTK (384 bits) */
    uint8_t                       remote_eui64[8];             /**< Remote EUI-64 used to calculate PTK */
    void                          *recv_pdu;                   /**< received pdu */
    uint16_t                      recv_size;                   /**< received pdu size */
} fwh_sec_prot_int_t;

static uint16_t auth_fwh_sec_prot_size(void);
static int8_t auth_fwh_sec_prot_init(sec_prot_t *prot);

static void auth_fwh_sec_prot_create_request(sec_prot_t *prot, sec_prot_keys_t *sec_keys);
static void auth_fwh_sec_prot_release(sec_prot_t *prot);
static int8_t auth_fwh_sec_prot_receive(sec_prot_t *prot, const void *pdu, uint16_t size);
static fwh_sec_prot_msg_e auth_fwh_sec_prot_message_get(eapol_pdu_t *eapol_pdu, sec_prot_keys_t *sec_keys);
static void auth_fwh_sec_prot_state_machine(sec_prot_t *prot);

static int8_t auth_fwh_sec_prot_message_send(sec_prot_t *prot, fwh_sec_prot_msg_e msg, bool retry);
static int8_t auth_fwh_sec_prot_auth_completed_send(sec_prot_t *prot);
static void auth_fwh_sec_prot_timer_timeout(sec_prot_t *prot, uint16_t ticks);

static int8_t auth_fwh_sec_prot_ptk_generate(sec_prot_t *prot, sec_prot_keys_t *sec_keys);
static int8_t auth_fwh_sec_prot_mic_validate(sec_prot_t *prot);

#define fwh_sec_prot_get(prot) (fwh_sec_prot_int_t *) &prot->data

int8_t auth_fwh_sec_prot_register(kmp_service_t *service)
{
    if (!service) {
        return -1;
    }

    if (kmp_service_sec_protocol_register(service, IEEE_802_11_4WH, auth_fwh_sec_prot_size, auth_fwh_sec_prot_init) < 0) {
        return -1;
    }

    return 0;
}

static uint16_t auth_fwh_sec_prot_size(void)
{
    return sizeof(fwh_sec_prot_int_t);
}

static int8_t auth_fwh_sec_prot_init(sec_prot_t *prot)
{
    prot->create_req = auth_fwh_sec_prot_create_request;
    prot->create_resp = 0;
    prot->receive = auth_fwh_sec_prot_receive;
    prot->release = auth_fwh_sec_prot_release;
    prot->state_machine = auth_fwh_sec_prot_state_machine;
    prot->timer_timeout = auth_fwh_sec_prot_timer_timeout;

    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);
    sec_prot_init(&data->common);
    sec_prot_state_set(prot, &data->common, FWH_STATE_INIT);

    data->common.ticks = 15 * 10; // 15 seconds

    uint8_t eui64[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    sec_prot_lib_nonce_init(data->nonce, eui64, 1000);

    return 0;
}

static void auth_fwh_sec_prot_release(sec_prot_t *prot)
{
    // No op at the moment
    (void) prot;
}

static void auth_fwh_sec_prot_create_request(sec_prot_t *prot, sec_prot_keys_t *sec_keys)
{
    prot->sec_keys = sec_keys;

    // Call state machine
    prot->state_machine_call(prot);
}

static int8_t auth_fwh_sec_prot_receive(sec_prot_t *prot, const void *pdu, uint16_t size)
{
    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);
    int8_t ret_val = -1;

    // Decoding is successful
    if (eapol_parse_pdu_header(pdu, size, &data->recv_eapol_pdu)) {
        // Get message
        data->recv_msg = auth_fwh_sec_prot_message_get(&data->recv_eapol_pdu, prot->sec_keys);
        if (data->recv_msg != FWH_MESSAGE_UNKNOWN) {
            TRACE(TR_EAP, "rx-eap  %-9s src:%s",
                  (data->recv_msg == FWH_MESSAGE_2) ? "4wh-2" : "4wh-4",
                  tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));

            // Call state machine
            data->recv_pdu = (uint8_t *)pdu; // FIXME
            data->recv_size = size;
            prot->state_machine(prot);
        } else {
            tr_error("4WH: recv error, eui-64: %s", tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));
        }
        ret_val = 0;
    } else {
        tr_error("4WH: recv error, eui-64: %s", tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));
    }

    memset(&data->recv_eapol_pdu, 0, sizeof(eapol_pdu_t));
    data->recv_msg = FWH_MESSAGE_UNKNOWN;
    data->recv_pdu = 0;
    data->recv_size = 0;

    return ret_val;
}

static fwh_sec_prot_msg_e auth_fwh_sec_prot_message_get(eapol_pdu_t *eapol_pdu, sec_prot_keys_t *sec_keys)
{
    fwh_sec_prot_msg_e msg = FWH_MESSAGE_UNKNOWN;

    if (!eapol_pdu->msg.key.key_information.pairwise_key) {
        // This is mismatch between KMP ID indicating 802.11/4WH and key type
        return FWH_MESSAGE_UNKNOWN;
    }

    uint8_t key_mask = eapol_pdu_key_mask_get(eapol_pdu);

    switch (key_mask) {
        case KEY_INFO_KEY_MIC:
            // Only accept message from supplicant with expected replay counter
            if (eapol_pdu->msg.key.replay_counter == sec_prot_keys_pmk_replay_cnt_get(sec_keys)) {
                msg = FWH_MESSAGE_2;
            }
            break;
        case KEY_INFO_KEY_MIC | KEY_INFO_SECURED_KEY_FRAME:
            // Only accept message from supplicant with expected replay counter
            if (eapol_pdu->msg.key.replay_counter == sec_prot_keys_pmk_replay_cnt_get(sec_keys)) {
                msg = FWH_MESSAGE_4;
            }
            break;
        default:
            break;
    }

    return msg;
}

static int8_t auth_fwh_sec_prot_message_send(sec_prot_t *prot, fwh_sec_prot_msg_e msg, bool retry)
{
    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);
    uint16_t kde_len = 0;
    int8_t ret;

    switch (msg) {
        case FWH_MESSAGE_1:
            kde_len = KDE_PMKID_LEN;
            break;
        case FWH_MESSAGE_3:
            kde_len = KDE_GTK_LEN + KDE_LIFETIME_LEN + KDE_GTKL_LEN;
            kde_len = kde_len + 8; // One 64 bit block for AES Key Wrap
            kde_len = kde_padded_length_calc(kde_len);
            break;
        default:
            break;
    }

    uint8_t *kde_start = malloc(kde_len);

    if (!kde_start) {
        return -1;
    }

    uint8_t *kde_end = kde_start;

    switch (msg) {
        case FWH_MESSAGE_1: {
            uint8_t pmkid[PMKID_LEN];
            if (sec_prot_lib_pmkid_generate(prot, pmkid, true, false, NULL) < 0) {
                free(kde_start);
                return -1;
            }
            kde_end = kde_pmkid_write(kde_end, pmkid);
        }
        break;
        case FWH_MESSAGE_3: {
            sec_prot_gtk_t *sec_gtks;
            uint8_t gtk_index, gtkl;
            uint32_t gtk_lifetime;
            uint8_t *gtk;

            if (prot->sec_keys->node_role == WS_NR_ROLE_LFN)
                sec_gtks = &prot->sec_keys->lgtks;
            else
                sec_gtks = &prot->sec_keys->gtks;
            gtk = sec_prot_keys_get_gtk_to_insert(sec_gtks, &gtk_index);
            if (!gtk) {
                // 4WH MUST contain a GTK, get active one
                gtk_index = sec_prot_keys_gtk_status_active_get(sec_gtks->keys);
                gtk = sec_prot_keys_gtk_get(sec_gtks->keys, gtk_index);
            }
            if (prot->sec_keys->node_role == WS_NR_ROLE_LFN)
                kde_end = kde_lgtk_write(kde_end, gtk_index, gtk);
            else
                kde_end = kde_gtk_write(kde_end, gtk_index, gtk);
            gtk_lifetime = sec_prot_keys_gtk_lifetime_get(sec_gtks->keys, gtk_index);
            kde_end = kde_lifetime_write(kde_end, gtk_lifetime);
            gtkl = sec_prot_keys_fresh_gtkl_get(sec_gtks->keys);
            if (prot->sec_keys->node_role == WS_NR_ROLE_LFN)
                kde_end = kde_lgtkl_write(kde_end, gtkl);
            else
                kde_end = kde_gtkl_write(kde_end, gtkl);
            kde_padding_write(kde_end, kde_start + kde_len);
        }
        break;
        default:
            break;
    }

    eapol_pdu_t eapol_pdu;
    uint16_t eapol_pdu_size = eapol_pdu_key_frame_init(&eapol_pdu, kde_len, NULL);

    eapol_pdu.msg.key.key_information.pairwise_key = true;

    switch (msg) {
        case FWH_MESSAGE_1:
            if (!sec_prot_keys_pmk_replay_cnt_increment(prot->sec_keys)) {
                free(kde_start);
                return 1;
            }
            eapol_pdu.msg.key.replay_counter = sec_prot_keys_pmk_replay_cnt_get(prot->sec_keys);
            eapol_pdu.msg.key.key_information.key_ack = true;
            eapol_pdu.msg.key.key_length = EAPOL_KEY_LEN;
            eapol_pdu.msg.key.key_nonce = data->nonce;
            break;
        case FWH_MESSAGE_3:
            if (!sec_prot_keys_pmk_replay_cnt_increment(prot->sec_keys)) {
                free(kde_start);
                return -1;
            }
            eapol_pdu.msg.key.replay_counter = sec_prot_keys_pmk_replay_cnt_get(prot->sec_keys);
            eapol_pdu.msg.key.key_information.install = true;
            eapol_pdu.msg.key.key_information.key_ack = true;
            eapol_pdu.msg.key.key_information.key_mic = true;
            eapol_pdu.msg.key.key_information.secured_key_frame = true;
            eapol_pdu.msg.key.key_information.encrypted_key_data = true;
            eapol_pdu.msg.key.key_nonce = data->nonce;
            eapol_pdu.msg.key.key_length = EAPOL_KEY_LEN;
            break;
        default:
            break;
    }

    uint8_t *eapol_pdu_frame = sec_prot_lib_message_build(data->new_ptk, kde_start, kde_len, &eapol_pdu, eapol_pdu_size, prot->header_size);

    free(kde_start);

    if (eapol_pdu_frame == NULL) {
        return -1;
    }

    TRACE(TR_EAP, "tx-eap  %-9s src:%s%s",
          (msg == FWH_MESSAGE_1) ? "4wh-1" : "4wh-3",
          tr_eui64(sec_prot_remote_eui_64_addr_get(prot)),
          retry ? " (retry)" : "");

    ret = prot->send(prot, eapol_pdu_frame, eapol_pdu_size + prot->header_size);
    free(eapol_pdu_frame);
    return ret;
}

static int8_t auth_fwh_sec_prot_auth_completed_send(sec_prot_t *prot)
{
    uint8_t *eapol_pdu_frame = malloc(prot->header_size);
    int8_t ret;

    // Send zero length message to relay which requests LLC to remove EAPOL temporary entry based on EUI-64
    ret = prot->send(prot, eapol_pdu_frame, prot->header_size);
    free(eapol_pdu_frame);
    return ret;
}

static void auth_fwh_sec_prot_timer_timeout(sec_prot_t *prot, uint16_t ticks)
{
    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);
    sec_prot_timer_timeout_handle(prot, &data->common, &prot->sec_cfg->prot_cfg.sec_prot_trickle_params, ticks);
}

static void auth_fwh_sec_prot_state_machine(sec_prot_t *prot)
{
    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);
    sec_prot_gtk_t *sec_gtks;

    // 4WH authenticator state machine
    switch (sec_prot_state_get(&data->common)) {
        case FWH_STATE_INIT:
            tr_debug("4WH: init");
            prot->timer_start(prot);
            sec_prot_state_set(prot, &data->common, FWH_STATE_CREATE_REQ);
            break;

        // Wait KMP-CREATE.request
        case FWH_STATE_CREATE_REQ:
            tr_debug("4WH: start, eui-64: %s", tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));

            // Set default timeout for the total maximum length of the negotiation
            sec_prot_default_timeout_set(&data->common);

            uint8_t *pmk = sec_prot_keys_pmk_get(prot->sec_keys);
            if (!pmk) { // If PMK is not set fails
                prot->create_conf(prot, SEC_RESULT_ERROR);
                sec_prot_state_set(prot, &data->common, FWH_STATE_FINISHED);
                return;
            }

            // KMP-CREATE.confirm
            prot->create_conf(prot, SEC_RESULT_OK);

            // Sends 4WH Message 1
            sec_prot_lib_nonce_generate(data->nonce);
            auth_fwh_sec_prot_message_send(prot, FWH_MESSAGE_1, false);

            // Start trickle timer to re-send if no response
            sec_prot_timer_trickle_start(&data->common, &prot->sec_cfg->prot_cfg.sec_prot_trickle_params);

            sec_prot_state_set(prot, &data->common, FWH_STATE_MESSAGE_2);
            break;

        // Wait 4WH message 2
        case FWH_STATE_MESSAGE_2:
            if (sec_prot_result_timeout_check(&data->common)) {
                // Re-sends 4WH Message 1
                sec_prot_lib_nonce_generate(data->nonce);
                auth_fwh_sec_prot_message_send(prot, FWH_MESSAGE_1, true);
            } else {
                if (data->recv_msg != FWH_MESSAGE_2) {
                    return;
                }

                if (auth_fwh_sec_prot_ptk_generate(prot, prot->sec_keys) < 0) {
                    return;
                }
                if (auth_fwh_sec_prot_mic_validate(prot) < 0) {
                    memset(data->new_ptk, 0, PTK_LEN);
                    return;
                }

                // Sends 4WH Message 3
                auth_fwh_sec_prot_message_send(prot, FWH_MESSAGE_3, false);

                // Start trickle timer to re-send if no response
                sec_prot_timer_trickle_start(&data->common, &prot->sec_cfg->prot_cfg.sec_prot_trickle_params);

                sec_prot_state_set(prot, &data->common, FWH_STATE_MESSAGE_4);
            }
            break;

        // Wait 4WH message 4
        case FWH_STATE_MESSAGE_4:
            if (sec_prot_result_timeout_check(&data->common)) {
                // Re-sends 4WH Message 3
                auth_fwh_sec_prot_message_send(prot, FWH_MESSAGE_3, true);
            } else {
                if (data->recv_msg != FWH_MESSAGE_4) {
                    return;
                }
                if (auth_fwh_sec_prot_mic_validate(prot) < 0) {
                    return;
                }
                if (prot->sec_keys->node_role == WS_NR_ROLE_LFN)
                    sec_gtks = &prot->sec_keys->lgtks;
                else
                    sec_gtks = &prot->sec_keys->gtks;
                // PTK is fresh for installing any GTKs
                sec_prot_keys_ptk_installed_gtk_hash_clear_all(sec_gtks);
                /* Store the hash for to-be installed GTK as used for the PTK, on 4WH
                   this stores only the hash in NVM and does not affect otherwise */
                sec_prot_keys_ptk_installed_gtk_hash_set(sec_gtks, true);
                // If GTK was inserted set it valid
                sec_prot_keys_gtkl_from_gtk_insert_index_set(sec_gtks);
                // Reset PTK mismatch
                sec_prot_keys_ptk_mismatch_reset(prot->sec_keys);
                // Update PTK
                sec_prot_keys_ptk_write(prot->sec_keys, data->new_ptk,
                                        prot->sec_keys->node_role == WS_NR_ROLE_LFN ?
                                        prot->sec_cfg->timing_lfn.ptk_lifetime_s :
                                        prot->sec_cfg->timing_ffn.ptk_lifetime_s);
                sec_prot_keys_ptk_eui_64_write(prot->sec_keys, data->remote_eui64);
                sec_prot_state_set(prot, &data->common, FWH_STATE_FINISH);
            }
            break;

        case FWH_STATE_FINISH:
            tr_debug("4WH: finish, eui-64: %s", tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));

            // KMP-FINISHED.indication,
            if (prot->finished_ind(prot, sec_prot_result_get(&data->common), 0)) {
                // Authentication completed (all GTKs inserted)
                auth_fwh_sec_prot_auth_completed_send(prot);
            }

            sec_prot_state_set(prot, &data->common, FWH_STATE_FINISHED);
            break;

        case FWH_STATE_FINISHED: {
            tr_debug("4WH: finished, eui-64: %s", tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));
            prot->timer_stop(prot);
            prot->finished(prot);
            break;
        }

        default:
            break;
    }
}

static int8_t auth_fwh_sec_prot_ptk_generate(sec_prot_t *prot, sec_prot_keys_t *sec_keys)
{
    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);

    uint8_t local_eui64[8];
    prot->addr_get(prot, local_eui64, data->remote_eui64);

    const uint8_t *remote_nonce = data->recv_eapol_pdu.msg.key.key_nonce;
    if (!remote_nonce) {
        tr_error("SNonce invalid");
        return 1;
    }

    uint8_t *pmk = sec_prot_keys_pmk_get(sec_keys);
    sec_prot_lib_ptk_calc(pmk, local_eui64, data->remote_eui64, data->nonce, remote_nonce, data->new_ptk);

    return 0;
}

static int8_t auth_fwh_sec_prot_mic_validate(sec_prot_t *prot)
{
    fwh_sec_prot_int_t *data = fwh_sec_prot_get(prot);
    return sec_prot_lib_mic_validate(data->new_ptk, data->recv_eapol_pdu.msg.key.key_mic, data->recv_pdu, data->recv_size);
}
