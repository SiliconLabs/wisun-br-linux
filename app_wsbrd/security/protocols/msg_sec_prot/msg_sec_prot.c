/*
 * Copyright (c) 2021, Pelion and affiliates.
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

#include "security/protocols/msg_sec_prot/msg_sec_prot.h"

typedef enum {
    MSG_STATE_INIT = SEC_STATE_INIT,
    MSG_STATE_CREATE_REQ = SEC_STATE_CREATE_REQ,
    MSG_STATE_FINISH = SEC_STATE_FINISH,
    MSG_STATE_FINISHED = SEC_STATE_FINISHED
} msg_sec_prot_state_e;

typedef struct msg_sec_prot_int {
    sec_prot_common_t              common;       /**< Common data */
} msg_sec_prot_int_t;

static uint16_t msg_sec_prot_size(void);
static int8_t msg_sec_prot_init(sec_prot_t *prot);
static void msg_sec_prot_release(sec_prot_t *prot);

static void msg_sec_prot_create_request(sec_prot_t *prot, sec_prot_keys_t *sec_keys);
static void msg_sec_prot_state_machine(sec_prot_t *prot);
static int8_t msg_sec_prot_auth_rejected_send(sec_prot_t *prot, sec_prot_keys_t *sec_keys);

#define msg_sec_prot_get(prot) (msg_sec_prot_int_t *) &prot->data

int8_t msg_sec_prot_register(kmp_service_t *service)
{
    if (!service) {
        return -1;
    }

    kmp_service_sec_protocol_register(service, MSG_PROT,
                                      msg_sec_prot_size,
                                      msg_sec_prot_init);
    return 0;
}

static uint16_t msg_sec_prot_size(void)
{
    return sizeof(msg_sec_prot_int_t);
}

static int8_t msg_sec_prot_init(sec_prot_t *prot)
{
    prot->create_req = msg_sec_prot_create_request;
    prot->release = msg_sec_prot_release;
    prot->state_machine = msg_sec_prot_state_machine;

    msg_sec_prot_int_t *data = msg_sec_prot_get(prot);
    sec_prot_init(&data->common);
    sec_prot_state_set(prot, &data->common, MSG_STATE_INIT);

    return 0;
}

static void msg_sec_prot_release(sec_prot_t *prot)
{
    (void) prot;
}

static void msg_sec_prot_create_request(sec_prot_t *prot, sec_prot_keys_t *sec_keys)
{
    (void) sec_keys;

    prot->state_machine(prot);
}

static int8_t msg_sec_prot_auth_rejected_send(sec_prot_t *prot, sec_prot_keys_t *sec_keys)
{
    (void) sec_keys;
    int8_t ret;

    uint8_t *eapol_pdu_frame = malloc(prot->header_size);

    // Send zero length message to relay which requests LLC to remove EAPOL temporary entry based on EUI-64
    ret = prot->send(prot, eapol_pdu_frame, prot->header_size);
    free(eapol_pdu_frame);
    return ret;
}

static void msg_sec_prot_state_machine(sec_prot_t *prot)
{
    msg_sec_prot_int_t *data = msg_sec_prot_get(prot);

    switch (sec_prot_state_get(&data->common)) {
        case MSG_STATE_INIT:
            sec_prot_state_set(prot, &data->common, MSG_STATE_CREATE_REQ);
            break;
        case MSG_STATE_CREATE_REQ:
            // KMP-CREATE.confirm
            prot->create_conf(prot, sec_prot_result_get(&data->common));
            // Authentication rejected (will continue only after new EAPOL Initial-Key)
            (void) msg_sec_prot_auth_rejected_send(prot, prot->sec_keys);
            sec_prot_state_set(prot, &data->common, MSG_STATE_FINISH);
            break;
        case MSG_STATE_FINISH:
            sec_prot_state_set(prot, &data->common, MSG_STATE_FINISHED);
        /* fall through */
        case MSG_STATE_FINISHED:
            prot->finished(prot);
            break;
        default:
            break;
    }
}
