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
#include "common/log.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
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

#include "security/protocols/key_sec_prot/key_sec_prot.h"

#define TRACE_GROUP "ksep"

#define KEY_SEC_FINISHED_TIMEOUT                  1       // Finishes right away

typedef enum {
    KEY_STATE_INIT = SEC_STATE_INIT,
    KEY_STATE_CREATE_RESP = SEC_STATE_CREATE_RESP,
    KEY_STATE_INITIAL_KEY_RECEIVED,
    KEY_STATE_FINISH = SEC_STATE_FINISH,
    KEY_STATE_FINISHED = SEC_STATE_FINISHED
} key_sec_prot_state_e;

typedef struct key_sec_prot_int {
    sec_prot_common_t              common;       /**< Common data */
} key_sec_prot_int_t;

static uint16_t key_sec_prot_size(void);
static int8_t auth_key_sec_prot_init(sec_prot_t *prot);

static void key_sec_prot_create_response(sec_prot_t *prot, sec_prot_result_e result);
static void key_sec_prot_release(sec_prot_t *prot);
static int8_t key_sec_prot_receive(sec_prot_t *prot, const void *pdu, uint16_t size);
static void key_sec_prot_timer_timeout(sec_prot_t *prot, uint16_t ticks);

static void auth_key_sec_prot_state_machine(sec_prot_t *prot);

#define key_sec_prot_get(prot) (key_sec_prot_int_t *) &prot->data

int8_t auth_key_sec_prot_register(kmp_service_t *service)
{
    if (!service) {
        return -1;
    }

    kmp_service_sec_protocol_register(service, IEEE_802_1X_MKA_KEY,
                                      key_sec_prot_size,
                                      auth_key_sec_prot_init);
    kmp_service_sec_protocol_register(service, IEEE_802_11_GKH_KEY,
                                      key_sec_prot_size,
                                      auth_key_sec_prot_init);
    return 0;
}

static uint16_t key_sec_prot_size(void)
{
    return sizeof(key_sec_prot_int_t);
}

static int8_t auth_key_sec_prot_init(sec_prot_t *prot)
{
    prot->create_resp = key_sec_prot_create_response;
    prot->receive = key_sec_prot_receive;
    prot->release = key_sec_prot_release;
    prot->state_machine = auth_key_sec_prot_state_machine;
    prot->timer_timeout = key_sec_prot_timer_timeout;

    key_sec_prot_int_t *data = key_sec_prot_get(prot);
    sec_prot_init(&data->common);
    sec_prot_state_set(prot, &data->common, KEY_STATE_INIT);

    return 0;
}

static void key_sec_prot_release(sec_prot_t *prot)
{
    (void) prot;
}

static void key_sec_prot_create_response(sec_prot_t *prot, sec_prot_result_e result)
{
    key_sec_prot_int_t *data = key_sec_prot_get(prot);
    sec_prot_state_set(prot, &data->common, KEY_STATE_CREATE_RESP);

    sec_prot_result_set(&data->common, result);
    prot->state_machine_call(prot);
}

static int8_t key_sec_prot_receive(sec_prot_t *prot, const void *pdu, uint16_t size)
{
    eapol_pdu_t eapol_pdu;
    bool has_gtkl, has_lgtkl;
    key_sec_prot_int_t *data = key_sec_prot_get(prot);
    sec_prot_result_e result = SEC_RESULT_OK;

    TRACE(TR_EAP, "rx-eap  tls-init  src:%s",
          tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));

    // Decoding is successful
    if (eapol_parse_pdu_header(pdu, size, &eapol_pdu)) {
        if (eapol_pdu.packet_type != EAPOL_KEY_TYPE) {
            tr_info("not EAPOL-Key packet");
            prot->finished(prot);
            return -1;
        }

        uint16_t kde_len;
        uint8_t *kde = sec_prot_lib_message_handle(prot->sec_keys->ptk, &kde_len, &eapol_pdu);
        if (!kde) {
            tr_error("no KDEs");
            prot->finished(prot);
            return -1;
        }

        // Default assumption is that PMK and PTK are not valid
        prot->sec_keys->pmk_mismatch = true;
        prot->sec_keys->ptk_mismatch = true;

        // Checks if supplicant indicates that it has valid PMK
        uint8_t remote_keyid[KEYID_LEN];
        if (kde_pmkid_read(kde, kde_len, remote_keyid) >= 0) {
            tr_debug("recv PMKID: %s", trace_array(remote_keyid, 16));
            uint8_t pmkid[PMKID_LEN];
            if (sec_prot_lib_pmkid_generate(prot, pmkid, true, false, NULL) >= 0) {
                if (memcmp(remote_keyid, pmkid, PMKID_LEN) == 0) {
                    prot->sec_keys->pmk_mismatch = false;
                }
            }
        }

        // Checks if supplicant indicates that it has valid PTK
        if (kde_ptkid_read(kde, kde_len, remote_keyid) >= 0) {
            tr_debug("recv PTKID: %s", trace_array(remote_keyid, 16));
            uint8_t ptkid[PTKID_LEN];
            if (sec_prot_lib_ptkid_generate(prot, ptkid, true) >= 0) {
                if (memcmp(remote_keyid, ptkid, PTKID_LEN) == 0) {
                    prot->sec_keys->ptk_mismatch = false;
                }
            }
        }

        // Get the GTKL that supplicant indicates
        has_gtkl = (kde_gtkl_read(kde, kde_len, &prot->sec_keys->gtks.gtkl) >= 0);
        // Get the LGTKL that supplicant indicates (if any)
        has_lgtkl = (kde_lgtkl_read(kde, kde_len, &prot->sec_keys->lgtks.gtkl) >= 0);
        if (!has_gtkl && !has_lgtkl) {
            WARN("missing liveness KDE in EAPOL Key Request");
            // Assume the supplicant wants GTKs but not LGTKs. This is because
            // supplicants without LFN support may ignore LGTK handshakes,
            // forcing the authenticator to perform unecessary retries.
            prot->sec_keys->gtks.gtkl = 0x00;
            prot->sec_keys->lgtks.gtkl = 0x07;
        }

        // Get the Node Role that supplicant indicates
        uint8_t node_role;
        if (kde_node_role_read(kde, kde_len, &node_role) >= 0 &&
            ws_common_is_valid_nr(node_role)) {
            prot->sec_keys->node_role = node_role;
        } else {
            prot->sec_keys->node_role = WS_NR_ROLE_UNKNOWN;
        }

        tr_debug("PMK %s PTK %s NR %d GTKL %x LGTKL %x",
                 prot->sec_keys->pmk_mismatch ? "not live" : "live",
                 prot->sec_keys->ptk_mismatch ? "not live" : "live",
                 prot->sec_keys->node_role,
                 prot->sec_keys->gtks.gtkl,
                 prot->sec_keys->lgtks.gtkl);

        free(kde);
    } else {
        tr_error("Invalid");
        result = SEC_RESULT_ERROR;
    }

    sec_prot_result_set(&data->common, result);
    prot->state_machine(prot);

    if (result != SEC_RESULT_OK) {
        return -1;
    }

    return 0;
}

static void key_sec_prot_timer_timeout(sec_prot_t *prot, uint16_t ticks)
{
    key_sec_prot_int_t *data = key_sec_prot_get(prot);
    sec_prot_timer_timeout_handle(prot, &data->common, NULL, ticks);
}

static void auth_key_sec_prot_state_machine(sec_prot_t *prot)
{
    key_sec_prot_int_t *data = key_sec_prot_get(prot);

    switch (sec_prot_state_get(&data->common)) {
        case KEY_STATE_INIT:
            tr_debug("Initial-key init");
            sec_prot_state_set(prot, &data->common, KEY_STATE_INITIAL_KEY_RECEIVED);
            prot->timer_start(prot);
            break;

        case KEY_STATE_INITIAL_KEY_RECEIVED:
            if (!sec_prot_result_ok_check(&data->common)) {
                // Goes right away to finished
                sec_prot_state_set(prot, &data->common, KEY_STATE_FINISHED);
                return;
            }

            // Send KMP-CREATE.indication
            prot->create_ind(prot);
            sec_prot_state_set(prot, &data->common, KEY_STATE_CREATE_RESP);
            break;

        case KEY_STATE_CREATE_RESP:
            // Goes to finish state right away
            sec_prot_state_set(prot, &data->common, KEY_STATE_FINISH);
            break;

        case KEY_STATE_FINISH:
            // KMP-FINISHED.indication,
            prot->finished_ind(prot, sec_prot_result_get(&data->common), 0);
            sec_prot_state_set(prot, &data->common, KEY_STATE_FINISHED);
            data->common.ticks = KEY_SEC_FINISHED_TIMEOUT;
            break;

        case KEY_STATE_FINISHED: {
            tr_debug("Initial-key finished, eui-64: %s", tr_eui64(sec_prot_remote_eui_64_addr_get(prot)));
            prot->finished(prot);
            break;
        }

        default:
            break;
    }
}


