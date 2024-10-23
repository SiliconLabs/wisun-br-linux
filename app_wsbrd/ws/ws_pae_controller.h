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

#ifndef WS_PAE_CONTROLLER_H_
#define WS_PAE_CONTROLLER_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "security/protocols/sec_prot.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/protocols/sec_prot_keys.h"

typedef struct arm_certificate_entry {
    const uint8_t *cert;           /**< Certificate pointer. */
    const uint8_t *key;            /**< Key pointer. */
    uint16_t cert_len;             /**< Certificate length. */
    uint16_t key_len;              /**< Key length. */
} arm_certificate_entry_s;

typedef enum auth_result {
    AUTH_RESULT_OK = 0,                    // Successful
    AUTH_RESULT_ERR_NO_MEM = -1,           // No memory
    AUTH_RESULT_ERR_TX_ERR = -2,           // TX error (e.g. no acknowledge was received)
    AUTH_RESULT_ERR_UNSPEC = -3            // Other reason
} auth_result_e;

struct net_if;
struct ws_info;
struct nvm_tlv_entry;
struct ws_sec_timer_cfg;
struct ws_sec_prot_cfg;
struct ws_timing_cfg;

/**
 * ws_pae_controller_authenticator_start start PAE authenticator
 *
 * \param interface_ptr interface
 * \param local_port local port
 * \param remote_addr remote address
 * \param remote_port remote port
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_authenticator_start(struct net_if *interface_ptr, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port);

void ws_pae_controller_init(struct net_if *interface_ptr);

/**
 * ws_pae_controller_config_set sets PAE controller configuration
 *
 * \param interface_ptr interface
 * \param sec_timer_cfg timer configuration or NULL if not set
 * \param sec_prot_cfg protocol configuration or NULL if not set
 * \param timing_cfg timing configuration or NULL if not set
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_configure(struct net_if *interface_ptr,
                                   const struct sec_timing *timing_ffn,
                                   const struct sec_timing *timing_lfn,
                                   const struct sec_prot_cfg *sec_prot_cfg);

/**
 * ws_pae_controller_init initializes PAE authenticator
 *
 * \param interface_ptr interface
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_auth_init(struct net_if *interface_ptr);

/**
 * ws_pae_controller_stop stop PAE controller (e.g. on interface down)
 *
 * \param interface_ptr interface
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_stop(struct net_if *interface_ptr);

/**
 * ws_pae_controller_delete delete PAE controller (e.g. failure to create interface)
 *
 * \param interface_ptr interface
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_delete(struct net_if *interface_ptr);

/**
 * ws_pae_controller_own_certificate_add add own certificate to certificate chain
 *
 * \param cert own certificate
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_own_certificate_add(const arm_certificate_entry_s *cert);

/**
 * ws_pae_controller_trusted_certificate_add add trusted certificate
 *
 * \param cert trusted certificate
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_trusted_certificate_add(const arm_certificate_entry_s *cert);

/**
 * ws_pae_controller_radius_address_set set radius address
 *
 * \param interface_id interface identifier
 * \param address address
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_radius_address_set(int8_t interface_id, const struct sockaddr_storage *address);

/**
 * ws_pae_controller_radius_shared_secret_set set radius shared secret
 *
 * \param interface_id interface identifier
 * \param shared_secret_len shared secret length
 * \param shared_secret shared secret
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_radius_shared_secret_set(int8_t interface_id, const uint16_t shared_secret_len, const uint8_t *shared_secret);

/**
 * ws_pae_controller_gtk_update update GTKs (test interface)
 *
 * \param interface_id interface identifier
 * \param gtk GTK array, if GTK is not set, pointer for the index shall be NULL.
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_gtk_update(int8_t interface_id, uint8_t *gtk[4]);
int8_t ws_pae_controller_lgtk_update(int8_t interface_id, uint8_t *lgtk[3]);

/**
 * ws_pae_controller_node_keys_remove remove node's keys
 *
 * \param interface_id interface identifier
 * \param eui-64 EUI-64
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_node_keys_remove(int8_t interface_id, uint8_t *eui_64);

/**
 * ws_pae_controller_node_access_revoke_start start node's access revoke
 *
 * \param interface_id interface identifier
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_node_access_revoke_start(int8_t interface_id, bool is_lgtk, uint8_t new_gtk[GTK_LEN]);

/**
 * ws_pae_controller_gtk_hash_ptr_get get pointer to GTK hash storage
 *
 * \param interface_ptr interface
 *
 * \return pointer to GTK has storage or NULL
 *
 */
gtkhash_t *ws_pae_controller_gtk_hash_ptr_get(struct net_if *interface_ptr);

/**
 * ws_pae_controller_lgtk_hash_ptr_get get pointer to LFN-GTK hash storage
 *
 * \param interface_ptr interface
 *
 * \return pointer to LFN-GTK has storage or NULL
 *
 */
gtkhash_t *ws_pae_controller_lgtk_hash_ptr_get(struct net_if *interface_ptr);

int8_t ws_pae_controller_lgtk_active_index_get(struct net_if *interface_ptr);

typedef void ws_pae_controller_nw_key_set(struct net_if *interface_ptr,
                                          uint8_t key_index,
                                          const uint8_t key[16],
                                          uint32_t frame_counter);

/**
 * ws_pae_controller_nw_send_key_index_set network send key index set callback
 *
 * \param interface_ptr interface
 * \param index index of the key to be used on sending
 *
 */
typedef void ws_pae_controller_nw_send_key_index_set(struct net_if *interface_ptr, uint8_t index);

/**
 * ws_pae_controller_pan_ver_increment PAN version increment callback
 */
typedef void ws_pae_controller_pan_ver_increment(struct ws_info *ws_info);

/**
 * ws_pae_controller_nw_info_updated network information is updated (read from memory)
 *
 * \param interface_ptr interface
 * \param pan_id PAN ID
 *
 */
typedef void ws_pae_controller_nw_info_updated(struct net_if *interface_ptr);

/**
 * ws_pae_controller_congestion_get get congestion information
 *
 * \param interface_ptr interface
 *
 * \return TRUE reject, FALSE accept
 *
 */
typedef bool ws_pae_controller_congestion_get(struct net_if *interface_ptr);

/**
 * ws_pae_controller_cb_register register controller callbacks
 *
 * \param interface_ptr interface
 * \param completed authentication completed callback
 * \param next_target authentication next target callback
 * \param nw_key_set network key set callback
 * \param nw_send_key_index_set network send key index set callback
 * \param pan_ver_increment PAN version increment callback
 * \param nw_info_updated network information updated callback
 * \param congestion_get congestion get callback
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_cb_register(struct net_if *interface_ptr,
                                     ws_pae_controller_nw_key_set *nw_key_set,
                                     ws_pae_controller_nw_send_key_index_set *nw_send_key_index_set,
                                     ws_pae_controller_pan_ver_increment *pan_ver_increment,
                                     ws_pae_controller_pan_ver_increment *lpan_ver_increment,
                                     ws_pae_controller_congestion_get *congestion_get);

/**
 * ws_pae_controller_ip_addr_get gets IP addressing information
 *
 * \param interface_ptr interface
 * \param address IP address
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
typedef int8_t ws_pae_controller_ip_addr_get(struct net_if *interface_ptr, uint8_t *address);

/**
 * ws_pae_controller_auth_cb_register register authenticator callbacks
 *
 * \param interface_ptr interface
 * \param ip_addr_get IP address get callback
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_controller_auth_cb_register(struct net_if *interface_ptr, ws_pae_controller_ip_addr_get *ip_addr_get);

/**
 * ws_pae_controller_fast_timer PAE controller fast timer call
 *
 * \param ticks elapsed ticks
 *
 */
void ws_pae_controller_fast_timer(int ticks);

/**
 * ws_pae_controller_slow_timer PAE controller slow timer call
 *
 * \param seconds elapsed seconds
 *
 */
void ws_pae_controller_slow_timer(int seconds);

sec_prot_gtk_keys_t *ws_pae_controller_get_transient_keys(int8_t interface_id, bool is_lfn);

void ws_pae_controller_nw_frame_counter_indication_cb(int8_t net_if_id, unsigned int gtk_index, uint32_t frame_counter);

int8_t ws_pae_controller_network_name_set(struct net_if *interface_ptr, char *network_name);

#endif
