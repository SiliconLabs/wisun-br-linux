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

/** Ipv6 address type.*/
typedef enum net_address {
    ADDR_IPV6_GP,             /**< Node default global address. */
    ADDR_IPV6_GP_SEC,         /**< Node secondary global address. */
    ADDR_IPV6_LL              /**< Node default link local address. */
} net_address_e;

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

/** Certificate chain structure. */
typedef struct arm_certificate_chain_entry {
    uint8_t chain_length;           /**< Certificate chain length, indicates the chain length. */
    const uint8_t *cert_chain[4];   /**< Certificate chain pointer list. */
    uint16_t cert_len[4];           /**< Certificate length. */
    const uint8_t *key_chain[4];    /**< Certificate private key. */
} arm_certificate_chain_entry_s;

/** Certificate Revocation List structure. */
typedef struct arm_cert_revocation_list_entry {
    const uint8_t *crl;            /**< Certificate Revocation List pointer. */
    uint16_t crl_len;              /**< Certificate Revocation List length. */
} arm_cert_revocation_list_entry_s;

/** Event library type. */
typedef enum arm_library_event_type_e {
    ARM_LIB_TASKLET_INIT_EVENT = 0, /**< Tasklet init occurs always when generating a tasklet. */
} arm_library_event_type_e;


/** Socket type exceptions. */
/** Socket event mask. */
#define SOCKET_EVENT_MASK                   0xF0
/** Data received. */
#define SOCKET_DATA                         (0 << 4)
/** TCP connection ready. */
#define SOCKET_CONNECT_DONE                 (1 << 4)
/** TCP connection failure. */
#define SOCKET_CONNECT_FAIL                 (2 << 4)
/** TCP connection authentication failed. */
#define SOCKET_CONNECT_AUTH_FAIL            (3 << 4)
/** TCP incoming connection on listening socket */
#define SOCKET_INCOMING_CONNECTION          (4 << 4)
/** Socket data send failure. */
#define SOCKET_TX_FAIL                      (5 << 4)
/** TCP connection closed (received their FIN and ACK of our FIN). */
#define SOCKET_CONNECT_CLOSED               (6 << 4)
/** TCP connection reset */
#define SOCKET_CONNECTION_RESET             (7 << 4)
/** No route available to the destination. */
#define SOCKET_NO_ROUTE                     (8 << 4)
/** Socket TX done. */
#define SOCKET_TX_DONE                      (9 << 4)
/** Out of memory failure. */
#define SOCKET_NO_RAM                       (10 << 4)
/** TCP connection problem indication (RFC 1122 R1) */
#define SOCKET_CONNECTION_PROBLEM           (11 << 4)

#define SOCKET_BIND_DONE                    SOCKET_CONNECT_DONE      /**< Backward compatibility */
#define SOCKET_BIND_FAIL                    SOCKET_CONNECT_FAIL      /**< Backward compatibility */
#define SOCKET_BIND_AUTH_FAIL               SOCKET_CONNECT_AUTH_FAIL /**< Backward compatibility */


#endif
