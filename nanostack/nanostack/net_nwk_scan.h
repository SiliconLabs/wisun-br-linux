/*
 * Copyright (c) 2013-2017, Pelion and affiliates.
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
#ifndef _NS_NWK_SCAN_H
#define _NS_NWK_SCAN_H
#include <stdint.h>

typedef struct channel_list_s channel_list_s;
typedef struct mlme_pan_descriptor_s mlme_pan_descriptor_t;
typedef struct mlme_comm_status_s mlme_comm_status_t;

/*!
 * \struct nwk_pan_alternative_parent_t
 * \brief Network alternative parent structure.
 */
typedef struct nwk_pan_alternative_parent_t {
    uint8_t CoordAddrMode; /**< Parent address mode NET_PARET_SHORT_16_BIT or NET_PARET_LONG_64_BIT. */
    uint8_t CoordAddress[8]; /**< Parent address based on CoordAddrMode. */
    uint8_t LinkQuality; /**< LQI to parent. */
} nwk_pan_alternative_parent_t;

/*!
 * \struct nwk_pan_descriptor_t
 * \brief Linked network response list.
 */
typedef struct nwk_pan_descriptor_t {
    mlme_pan_descriptor_t *pan_descriptor;              /**< Pan Description */
    uint8_t *beacon_payload;                            /**< Beacon Payload pointer */
    uint8_t beacon_length;                              /**< Beacon Payload length */
    nwk_pan_alternative_parent_t alternative_parent;   /**< Alternative Parent information pointer */
    struct nwk_pan_descriptor_t *next;                   /**< Link to next network result */
} nwk_pan_descriptor_t;

#endif /*_NS_NWK_SCAN_H*/
