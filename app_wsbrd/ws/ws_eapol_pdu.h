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

#ifndef WS_EAPOL_PDU_H_
#define WS_EAPOL_PDU_H_
#include <stdint.h>
#include <stdbool.h>

#include "net/protocol_abstract.h"
#include "6lowpan/mac/mpx_api.h"

/*
 * EAPOL PDU module transfers EAPOL PDUs to/from MPX. Several users
 * (e.g. supplicant PAE and EAPOL relay) can register to incoming
 * EAPOL PDUs. When registering, users need to define priority that
 * defines in which order incoming EAPOL PDUs are offered to them.
 *
 * Incoming EAPOL PDU user callbacks form a pair on EAPOL PDU module:
 * address check callback is called first, and if it returns match
 * then incoming EAPOL PDU callback is called.
 *
 */

void ws_eapol_pdu_init(struct net_if *interface_ptr);

void ws_eapol_pdu_mpx_register(struct net_if *interface_ptr, struct mpx_api *mpx_api, uint16_t mpx_user_id);

/**
 *  ws_eapol_pdu_receive receive EAPOL PDU
 *
 * \param interface_ptr interface
 * \param eui_64 source EUI-64
 * \param data EAPOL PDU
 * \param size PDU size
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
typedef int8_t ws_eapol_pdu_receive(struct net_if *interface_ptr, const uint8_t *eui_64, const void *data, uint16_t size);

/**
 *  ws_eapol_pdu_cb_register register an incoming EAPOL PDU callback
 *
 * \param interface_ptr interface
 * \param cb_data callback data
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_eapol_pdu_cb_register(struct net_if *interface_ptr, ws_eapol_pdu_receive *recv_cb);

typedef enum {
    EAPOL_PDU_TX_OK = 0,                 // Successful
    EAPOL_PDU_TX_ERR_TX_NO_ACK  = -1,    // No acknowledge was received
    EAPOL_PDU_TX_ERR_UNSPEC = -2,        // Other reason
} eapol_pdu_tx_status_e;

/**
 * ws_eapol_pdu_tx_status will be called when TX status is known
 *
 * \param interface_ptr interface
 * \param tx_status tx status
 * \param tx_identifier tx identifier
 *
 */
typedef int8_t ws_eapol_pdu_tx_status(struct net_if *interface_ptr, eapol_pdu_tx_status_e tx_status, uint8_t tx_identifier);

/**
 *  ws_eapol_pdu_send_to_mpx send EAPOL PDU to MPX
 *
 * \param interface_ptr interface
 * \param eui_64 destination EUI-64
 * \param data EAPOL PDU
 * \param size PDU size
 * \param buffer pointer to allocated buffer
 * \param tx_status tx status callback
 * \param tx_identifier tx identifier
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_eapol_pdu_send_to_mpx(struct net_if *interface_ptr, const uint8_t *eui_64, void *data, uint16_t size, void *buffer, ws_eapol_pdu_tx_status tx_status, uint8_t tx_identifier);

#endif
