/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#ifndef NET_INTERFACE_H_
#define NET_INTERFACE_H_
#include <stdint.h>

struct mac_api;
struct rcp;

/**  6LoWPAN Extension modes. */
typedef enum {
    NET_6LOWPAN_ND_WITHOUT_MLE,         /**< **UNSUPPORTED** */
    NET_6LOWPAN_ND_WITH_MLE,            /**< 6LoWPAN ND with MLE. */
    NET_6LOWPAN_WS,                     /**< WS. */
    NET_6LOWPAN_ZIGBEE_IP               /**< **UNSUPPORTED** */
} net_6lowpan_mode_extension_e;

/** CCA threshold table */
typedef struct cca_threshold_table {
    uint8_t number_of_channels;         /**< Number of channels */
    const int8_t *cca_threshold_table;  /**< CCA threshold table */
} cca_threshold_table_s;

/** Network MAC address info. */
typedef struct link_layer_address {
    uint16_t PANId;            /**< Network PAN-ID. */
    uint8_t mac_long[8];       /**< MAC long address (EUI-48 for Ethernet; EUI-64 for IEEE 802.15.4). */
    uint8_t iid_eui64[8];      /**< IPv6 interface identifier based on EUI-64. */
} link_layer_address_s;

/** Certificate structure. */
typedef struct arm_certificate_entry {
    const uint8_t *cert;           /**< Certificate pointer. */
    const uint8_t *key;            /**< Key pointer. */
    uint16_t cert_len;             /**< Certificate length. */
    uint16_t key_len;              /**< Key length. */
} arm_certificate_entry_s;

#endif
