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

#ifndef WS_PAE_AUTH_H_
#define WS_PAE_AUTH_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "security/protocols/sec_prot.h"
#include "security/protocols/sec_prot_keys.h"

struct net_if;
struct sec_prot_gtk_keys;
struct sec_prot_certs;
struct sec_prot_keys_nw_info;
struct frame_counters;

/*
 * Authenticator port access entity controls key security protocols using KMP API.
 *
 * Configures KMP service network access and provides timing and callback services
 * for it. Registers needed security protocols to KMP service.
 *
 * PAE Maintains security keys that are internal to port access entity for
 * each supplicant and maintains supplicant security registration state.
 *
 * Autenticator PAE controls network access keys and provides new network
 * access keys to supplicants when they are changed. When supplicant
 * network keys are updated, also other keys (master key, pairwise key)
 * are updated as needed.
 *
 */

/**
 * ws_pae_auth_init initializes PAE authenticator
 *
 * \param interface_ptr interface
 * \param local_port local port
 * \param remote_addr remote address
 * \param remote_port remote port
 * \param next_gtks next group keys to be used
 * \param cert_chain certificate chain
 * \param timer_settings timer settings
 * \param sec_cfg security configuration
 * \param sec_keys_nw_info security keys network information
 * \param frame_counters frame counters
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
void ws_pae_auth_init(struct net_if *interface_ptr,
                      struct sec_prot_gtk_keys *next_gtks,
                      struct sec_prot_gtk_keys *next_lgtks,
                      const struct sec_prot_certs *certs,
                      sec_cfg_t *sec_cfg,
                      struct sec_prot_keys_nw_info *sec_keys_nw_info,
                      struct frame_counters *gtk_frame_counters,
                      struct frame_counters *lgtk_frame_counters);

/**
 * ws_pae_auth_addresses_set set relay addresses
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
int8_t ws_pae_auth_addresses_set(struct net_if *interface_ptr, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port);

/**
 * ws_pae_auth_radius_address_set set radius address
 *
 * \param interface_ptr interface
 * \param remote_addr remote address
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_auth_radius_address_set(struct net_if *interface_ptr, const struct sockaddr_storage *remote_addr);

/**
 * ws_pae_auth_fast_timer PAE authenticator fast timer call
 *
 * \param ticks elapsed ticks
 *
 */
void ws_pae_auth_fast_timer(uint16_t ticks);

/**
 * ws_pae_auth_slow_timer PAE authenticator slow call
 *
 * \param seconds elapsed seconds
 *
 */
void ws_pae_auth_slow_timer(uint16_t seconds);

/**
 * ws_pae_auth_start start PAE authenticator
 *
 * \param interface_ptr interface
 *
 */
void ws_pae_auth_start(struct net_if *interface_ptr);

/**
 * ws_pae_auth_gtks_updated indicates that GTKs has been updated
 *
 * \param interface_ptr interface
 *
 */
void ws_pae_auth_gtks_updated(struct net_if *interface_ptr, bool is_lgtk);

/**
 * ws_pae_auth_gtks_updated indicates that key index has been updated
 *
 * \param interface_ptr interface
 * \param index key index
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_auth_nw_key_index_update(struct net_if *interface_ptr, uint8_t index, bool is_lgtk);

/**
 * ws_pae_auth_node_keys_remove removes nodes keys
 *
 * \param interface_ptr interface
 * \param eui64 node's EUI-64
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_auth_node_keys_remove(struct net_if *interface_ptr, uint8_t *eui64);

/**
 * ws_pae_auth_node_access_revoke_start start node's access revoke
 *
 * \param interface_ptr interface
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
int8_t ws_pae_auth_node_access_revoke_start(struct net_if *interface_ptr, bool is_lgtk, uint8_t new_gtk[GTK_LEN]);

/**
 * ws_pae_auth_gtk_hash_set GTK hash set callback
 *
 * \param interface_ptr interface
 * \param gtkhash GTK hash, 32 bytes
 *
 */
typedef void ws_pae_auth_gtk_hash_set(struct net_if *interface_ptr, gtkhash_t *gtkhash, bool is_lgtk);

/**
 * ws_pae_auth_nw_key_insert network key insert callback
 *
 * \param interface_ptr interface
 * \param gtks group keys
 *
 * \return < 0 failure
 * \return >= 0 success
 *
 */
typedef int8_t ws_pae_auth_nw_key_insert(struct net_if *interface_ptr, struct sec_prot_gtk_keys *gtks, bool is_lgtk);

/**
 * ws_pae_auth_nw_key_index_set network send key index set callback
 *
 * \param interface_ptr interface
 * \param index network send key index
 *
 */
typedef void ws_pae_auth_nw_key_index_set(struct net_if *interface_ptr, uint8_t index, bool is_lgtk);

/**
 * ws_pae_auth_nw_info_updated security keys network information updated
 *
 * \param interface_ptr interface
 *
 */
typedef void ws_pae_auth_nw_info_updated(struct net_if *interface_ptr);

/**
 * ws_pae_auth_ip_addr_get gets IP addressing information related to KMP
 *
 * \param interface_ptr interface
 * \param address IP address
 *
 */
typedef void ws_pae_auth_ip_addr_get(struct net_if *interface_ptr, uint8_t *address);

/**
 * ws_pae_auth_congestion_get get congestion information
 *
 * \param interface_ptr interface
 *
 * \return TRUE reject, FALSE accept
 *
 */
typedef bool ws_pae_auth_congestion_get(struct net_if *interface_ptr);

/**
 *  ws_pae_auth_cb_register register PAE authenticator callbacks
 *
 * \param interface_ptr interface
 * \param hash_set GTK hash set callback
 * \param nw_key_insert network key index callback
 * \param nw_key_index_set network send key index callback
 * \param nw_info_updated network keys updated callback
 * \param ip_addr_get IP addressing information callback
 * \param congestion_get congestion get callback
 * \param nw_frame_cnt_read network frame counter read callback
 *
 */
void ws_pae_auth_cb_register(struct net_if *interface_ptr,
                             ws_pae_auth_gtk_hash_set *hash_set,
                             ws_pae_auth_nw_key_insert *nw_key_insert,
                             ws_pae_auth_nw_key_index_set *nw_key_index_set,
                             ws_pae_auth_nw_info_updated *nw_info_updated,
                             ws_pae_auth_ip_addr_get *ip_addr_get,
                             ws_pae_auth_congestion_get *congestion_get);

int ws_pae_auth_supp_list(int8_t interface_id, uint8_t eui64[][8], int len);
void ws_pae_auth_gtk_install(int8_t interface_id, const uint8_t key[GTK_LEN], bool is_lgtk);

#endif
