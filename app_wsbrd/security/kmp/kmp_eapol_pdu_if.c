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
#include "common/ns_list.h"

#include "net/protocol.h"
#include "6lowpan/mac/mpx_api.h"
#include "ws/ws_eapol_pdu.h"
#include "ws/ws_config.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/kmp/kmp_addr.h"
#include "security/kmp/kmp_api.h"

#include "security/kmp/kmp_eapol_pdu_if.h"

#define EAPOL_PDU_IF_HEADER_SIZE                 1

typedef struct eapol_kmp_pdu {
    uint8_t kmp_id;                                   /**< Kmp id */
    uint8_t kmp_data;                                 /**< Kmp data e.g. eapol frame */
} eapol_kmp_pdu_t;

typedef struct kmp_eapol_pdu_if {
    kmp_service_t *kmp_service;                       /**< KMP service */
    struct net_if *interface_ptr;   /**< Interface pointer */
    ns_list_link_t link;                              /**< Link */
} kmp_eapol_pdu_if_t;

static NS_LIST_DEFINE(kmp_eapol_pdu_if_list, kmp_eapol_pdu_if_t, link);

static int8_t kmp_eapol_pdu_if_send(kmp_service_t *service, uint8_t instance_id, kmp_type_e kmp_id, const kmp_addr_t *addr, void *pdu, uint16_t size, uint8_t tx_identifier, uint8_t conn_number);
static int8_t kmp_eapol_pdu_if_tx_status(struct net_if *interface_ptr, eapol_pdu_tx_status_e tx_status, uint8_t tx_identifier);

int8_t kmp_eapol_pdu_if_register(kmp_service_t *service, struct net_if *interface_ptr)
{
    if (!service || !interface_ptr) {
        return -1;
    }

    ns_list_foreach(kmp_eapol_pdu_if_t, entry, &kmp_eapol_pdu_if_list) {
        if (entry->kmp_service == service || entry->interface_ptr == interface_ptr) {
            return -1;
        }
    }

    kmp_eapol_pdu_if_t *eapol_pdu_if = malloc(sizeof(kmp_eapol_pdu_if_t));
    if (!eapol_pdu_if) {
        return -1;
    }

    eapol_pdu_if->kmp_service = service;
    eapol_pdu_if->interface_ptr = interface_ptr;

    if (kmp_service_msg_if_register(service, 0, kmp_eapol_pdu_if_send, EAPOL_PDU_IF_HEADER_SIZE) < 0) {
        free(eapol_pdu_if);
        return -1;
    }

    ns_list_add_to_end(&kmp_eapol_pdu_if_list, eapol_pdu_if);

    return 0;
}

static int8_t kmp_eapol_pdu_if_send(kmp_service_t *service, uint8_t instance_id, kmp_type_e kmp_id, const kmp_addr_t *addr, void *pdu, uint16_t size, uint8_t tx_identifier, uint8_t conn_number)
{
    (void) instance_id; // Only one instance of eapol interface possible
    (void) conn_number; // Only one connection of eapol interface possible

    // No flags supported
    if (!service || !addr || !pdu) {
        return -1;
    }

    struct net_if *interface_ptr = NULL;

    ns_list_foreach(kmp_eapol_pdu_if_t, entry, &kmp_eapol_pdu_if_list) {
        if (entry->kmp_service == service) {
            interface_ptr = entry->interface_ptr;
            break;
        }
    }

    if (!interface_ptr) {
        return -1;
    }

    const uint8_t *eui_64 = kmp_address_eui_64_get(addr);
    if (!eui_64) {
        return -1;
    }

    uint8_t *ptr = pdu;
    *ptr = kmp_id;

    int8_t ret = ws_eapol_pdu_send_to_mpx(interface_ptr, eui_64, pdu, size, pdu, kmp_eapol_pdu_if_tx_status, tx_identifier);

    return ret;
}

static int8_t kmp_eapol_pdu_if_tx_status(struct net_if *interface_ptr, eapol_pdu_tx_status_e tx_status, uint8_t tx_identifier)
{
    kmp_service_t *service = NULL;

    ns_list_foreach(kmp_eapol_pdu_if_t, entry, &kmp_eapol_pdu_if_list) {
        if (entry->interface_ptr == interface_ptr) {
            service = entry->kmp_service;
            break;
        }
    }

    if (!service) {
        return -1;
    }

    kmp_tx_status_e kmp_tx_status;
    if (tx_status == EAPOL_PDU_TX_OK) {
        kmp_tx_status = KMP_TX_OK;
    } else if (tx_status == EAPOL_PDU_TX_ERR_TX_NO_ACK) {
        kmp_tx_status = KMP_TX_ERR_TX_NO_ACK;
    } else {
        kmp_tx_status = KMP_TX_ERR_UNSPEC;
    }

    int8_t ret = kmp_service_tx_status_indication(service, kmp_tx_status, tx_identifier);

    return ret;
}



