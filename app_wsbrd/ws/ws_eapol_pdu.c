/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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
#include "common/log_legacy.h"
#include "common/memutils.h"
#include "common/ns_list.h"
#include "common/specs/ipv6.h"

#include "net/protocol.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "ws/ws_config.h"
#include "ws/ws_llc.h"

#include "ws/ws_eapol_pdu.h"

#define TRACE_GROUP "wsep"

typedef struct eapol_pdu_msdu {
    void *data_ptr;
    void *buffer;
    ws_eapol_pdu_tx_status *tx_status;
    uint8_t tx_identifier;
    uint8_t handle;
    ns_list_link_t link;
} eapol_pdu_msdu_t;

typedef NS_LIST_HEAD(eapol_pdu_msdu_t, link) eapol_pdu_msdu_list_t;

typedef struct eapol_pdu_data {
    ws_eapol_pdu_receive *recv_cb;
    eapol_pdu_msdu_list_t msdu_list;                       /**< MSDU list */
    struct net_if *interface_ptr;        /**< Interface pointer */
    mpx_api_t *mpx_api;                                    /**< MPX api */
    uint16_t mpx_user_id;                                  /**< MPX user identifier */
    uint8_t msdu_handle;                                   /**< MSDU handle */
    ns_list_link_t link;                                   /**< Link */
} eapol_pdu_data_t;

static void ws_eapol_pdu_mpx_data_confirm(const mpx_api_t *api, const struct mcps_data_cnf *data);
static void ws_eapol_pdu_mpx_data_indication(const mpx_api_t *api, const struct mcps_data_ind *data);
static void ws_eapol_pdu_data_request_primitiv_set(mcps_data_req_t *dataReq, struct net_if *cur);
static eapol_pdu_data_t *ws_eapol_pdu_data_get(struct net_if *interface_ptr);

static NS_LIST_DEFINE(eapol_pdu_data_list, eapol_pdu_data_t, link);

void ws_eapol_pdu_init(struct net_if *interface_ptr)
{
    BUG_ON(!interface_ptr);

    if (ws_eapol_pdu_data_get(interface_ptr) != NULL)
        return;

    eapol_pdu_data_t *eapol_pdu_data = xalloc(sizeof(eapol_pdu_data_t));
    eapol_pdu_data->interface_ptr = interface_ptr;
    eapol_pdu_data->recv_cb = NULL;
    ns_list_init(&eapol_pdu_data->msdu_list);
    eapol_pdu_data->msdu_handle = 0;

    ns_list_add_to_end(&eapol_pdu_data_list, eapol_pdu_data);
}

int8_t ws_eapol_pdu_delete(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return -1;
    }

    eapol_pdu_data_t *eapol_pdu_data = ws_eapol_pdu_data_get(interface_ptr);

    if (!eapol_pdu_data) {
        return -1;
    }

    ns_list_foreach_safe(eapol_pdu_msdu_t, msdu_entry, &eapol_pdu_data->msdu_list) {
        ns_list_remove(&eapol_pdu_data->msdu_list, msdu_entry);
        free(msdu_entry);
    }

    ns_list_remove(&eapol_pdu_data_list, eapol_pdu_data);
    free(eapol_pdu_data);

    return 0;
}

int8_t ws_eapol_pdu_cb_register(struct net_if *interface_ptr, ws_eapol_pdu_receive *recv_cb)
{
    if (!interface_ptr || !recv_cb) {
        return -1;
    }

    eapol_pdu_data_t *eapol_pdu_data =  ws_eapol_pdu_data_get(interface_ptr);

    if (!eapol_pdu_data) {
        return -1;
    }

    eapol_pdu_data->recv_cb = recv_cb;

    return 0;
}

int8_t ws_eapol_pdu_send_to_mpx(struct net_if *interface_ptr, const uint8_t *eui_64, void *data, uint16_t size, void *buffer, ws_eapol_pdu_tx_status *tx_status, uint8_t tx_identifier)
{
    eapol_pdu_data_t *eapol_pdu_data = ws_eapol_pdu_data_get(interface_ptr);

    if (!eapol_pdu_data) {
        return -1;
    }

    mcps_data_req_t data_request;
    ws_eapol_pdu_data_request_primitiv_set(&data_request, eapol_pdu_data->interface_ptr);

    eapol_pdu_msdu_t *msdu_entry = malloc(sizeof(eapol_pdu_msdu_t));
    if (!msdu_entry) {
        return -1;
    }
    msdu_entry->data_ptr = data;
    msdu_entry->buffer = buffer;
    msdu_entry->handle = eapol_pdu_data->msdu_handle;
    msdu_entry->tx_status = tx_status;
    msdu_entry->tx_identifier = tx_identifier;
    ns_list_add_to_start(&eapol_pdu_data->msdu_list, msdu_entry);

    memcpy(data_request.DstAddr, eui_64, 8);
    data_request.msdu = data;
    data_request.msduLength = size;
    data_request.msduHandle = eapol_pdu_data->msdu_handle;

    eapol_pdu_data->msdu_handle++;

    eapol_pdu_data->mpx_api->mpx_data_request(eapol_pdu_data->mpx_api, &data_request, eapol_pdu_data->mpx_user_id);
    return 0;
}

static void ws_eapol_pdu_data_request_primitiv_set(mcps_data_req_t *dataReq, struct net_if *cur)
{
    memset(dataReq, 0, sizeof(mcps_data_req_t));
    dataReq->TxAckReq = true;
    dataReq->SrcAddrMode = ADDR_802_15_4_LONG;
    dataReq->DstAddrMode = ADDR_802_15_4_LONG;
    dataReq->DstPANId = cur->ws_info.pan_information.pan_id;
}

void ws_eapol_pdu_mpx_register(struct net_if *interface_ptr, struct mpx_api *mpx_api, uint16_t mpx_user_id)
{
    BUG_ON(!interface_ptr);

    eapol_pdu_data_t *eapol_pdu_data = ws_eapol_pdu_data_get(interface_ptr);
    BUG_ON(!eapol_pdu_data);

    if (!mpx_api && eapol_pdu_data->mpx_api) {
        //Disable Data Callbacks from MPX Class
        eapol_pdu_data->mpx_api->mpx_user_registration(eapol_pdu_data->mpx_api, NULL, NULL, eapol_pdu_data->mpx_user_id);
    }

    eapol_pdu_data->mpx_api = mpx_api;
    eapol_pdu_data->mpx_user_id = mpx_user_id;

    if (eapol_pdu_data->mpx_api) {
        eapol_pdu_data->mpx_api->mpx_user_registration(eapol_pdu_data->mpx_api, ws_eapol_pdu_mpx_data_confirm, ws_eapol_pdu_mpx_data_indication, eapol_pdu_data->mpx_user_id);
    }
}

static void ws_eapol_pdu_mpx_data_confirm(const mpx_api_t *api, const struct mcps_data_cnf *data)
{
    uint8_t mlme_status = mlme_status_from_hif(data->hif.status);
    eapol_pdu_data_t *eapol_pdu_data = NULL;

    ns_list_foreach(eapol_pdu_data_t, entry, &eapol_pdu_data_list) {
        if (entry->mpx_api == api) {
            eapol_pdu_data = entry;
            break;
        }
    }

    if (!eapol_pdu_data) {
        return;
    }

    ns_list_foreach(eapol_pdu_msdu_t, msdu, &eapol_pdu_data->msdu_list) {
        if (msdu->handle == data->hif.handle) {
            if (msdu->tx_status) {
                eapol_pdu_tx_status_e status = EAPOL_PDU_TX_ERR_UNSPEC;
                if (mlme_status == MLME_SUCCESS) {
                    status = EAPOL_PDU_TX_OK;
                } else if (mlme_status == MLME_TX_NO_ACK) {
                    status = EAPOL_PDU_TX_ERR_TX_NO_ACK;
                    tr_error("EAPOL TX err no ack");
                } else {
                    tr_error("EAPOL TX err");
                }
                msdu->tx_status(eapol_pdu_data->interface_ptr, status, msdu->tx_identifier);
            }
            free(msdu->buffer);
            ns_list_remove(&eapol_pdu_data->msdu_list, msdu);
            free(msdu);
            return;
        }
    }
}

static void ws_eapol_pdu_mpx_data_indication(const mpx_api_t *api, const struct mcps_data_ind *data)
{
    if (!data || !data->msduLength || !data->msdu_ptr) {
        return;
    }

    eapol_pdu_data_t *eapol_pdu_data = NULL;

    ns_list_foreach(eapol_pdu_data_t, entry, &eapol_pdu_data_list) {
        if (entry->mpx_api == api) {
            eapol_pdu_data = entry;
            break;
        }
    }

    if (!eapol_pdu_data) {
        return;
    }

    if (eapol_pdu_data->recv_cb)
        eapol_pdu_data->recv_cb(eapol_pdu_data->interface_ptr, data->SrcAddr, data->msdu_ptr, data->msduLength);
}

static eapol_pdu_data_t *ws_eapol_pdu_data_get(struct net_if *interface_ptr)
{
    eapol_pdu_data_t *eapol_pdu_data = NULL;

    ns_list_foreach(eapol_pdu_data_t, entry, &eapol_pdu_data_list) {
        if (entry->interface_ptr == interface_ptr) {
            eapol_pdu_data = entry;
            break;
        }
    }

    return eapol_pdu_data;
}
