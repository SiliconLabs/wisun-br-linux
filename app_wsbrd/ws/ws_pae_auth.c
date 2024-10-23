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
#include <inttypes.h>
#include "common/log_legacy.h"
#include "common/rand.h"
#include "common/memutils.h"
#include "common/ns_list.h"
#include "common/events_scheduler.h"
#include "common/time_extra.h"
#include "common/specs/ws.h"

#include "net/ns_address.h"
#include "net/timers.h"
#include "net/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/kmp/kmp_addr.h"
#include "security/kmp/kmp_api.h"
#include "security/kmp/kmp_socket_if.h"
#include "security/eapol/eapol_helper.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "security/protocols/key_sec_prot/key_sec_prot.h"
#include "security/protocols/eap_tls_sec_prot/auth_eap_tls_sec_prot.h"
#include "security/protocols/eap_tls_sec_prot/radius_eap_tls_sec_prot.h"
#include "security/protocols/tls_sec_prot/tls_sec_prot.h"
#include "security/protocols/fwh_sec_prot/auth_fwh_sec_prot.h"
#include "security/protocols/gkh_sec_prot/auth_gkh_sec_prot.h"
#include "security/protocols/radius_sec_prot/radius_client_sec_prot.h"
#include "security/protocols/msg_sec_prot/msg_sec_prot.h"
#include "ws/ws_config.h"
#include "ws/ws_common.h"
#include "ws/ws_pae_controller.h"
#include "ws/ws_pae_lib.h"
#include "ws/ws_pae_key_storage.h"

#include "ws/ws_pae_auth.h"

#define TRACE_GROUP "wspa"

/* Wait for supplicant to indicate activity (e.g. to send a message) when
   authentication is ongoing */
#define WAIT_FOR_AUTHENTICATION_TICKS          2 * 60 * 10  // 2 minutes
// Wait after authentication has completed before supplicant entry goes inactive
#define WAIT_AFTER_AUTHENTICATION_TICKS        15 * 10      // 15 seconds

// Default for maximum number of supplicants
#define SUPPLICANT_MAX_NUMBER                  5000

/* Default for number of supplicants to purge per garbage collect call from
   nanostack monitor */
#define SUPPLICANT_NUMBER_TO_PURGE             5

// Short GTK lifetime value, for GTK install check
#define SHORT_GTK_LIFETIME                     10 * 3600  // 10 hours
#define SHORT_LGTK_LIFETIME                    10 * 3600  // 10 hours

// Frame counter exhaust check timer
#define FRAME_CNT_TIMER                        3600

// Once reached, a new GTK must be propagated (90% of frame counter max)
#define FRAME_CNT_THRESHOLD                    3865470565U

#define SECONDS_IN_DAY                         (3600 * 24)

typedef struct pae_auth_gtk {
    sec_prot_gtk_keys_t *next_gtks;                          /**< Next GTKs */
    frame_counters_t *frame_counters;                        /**< Frame counters */
    uint16_t prev_frame_cnt_timer;                           /**< Previous frame counter timer */
    bool gtk_new_inst_req_exp : 1;                           /**< GTK new install required timer expired */
} pae_auth_gtk_t;

typedef struct pae_auth {
    ns_list_link_t link;                                     /**< Link */
    kmp_service_t *kmp_service;                              /**< KMP service */
    struct net_if *interface_ptr;                            /**< Interface pointer */
    ws_pae_auth_gtk_hash_set *hash_set;                      /**< GTK hash set callback */
    ws_pae_auth_nw_key_insert *nw_key_insert;                /**< Key insert callback */
    ws_pae_auth_nw_key_index_set *nw_key_index_set;          /**< Key index set callback */
    ws_pae_auth_nw_info_updated *nw_info_updated;            /**< Security keys network info updated callback */
    ws_pae_auth_ip_addr_get *ip_addr_get;                    /**< IP address get callback */
    ws_pae_auth_congestion_get *congestion_get;              /**< Congestion get callback */
    supp_list_t active_supp_list;                            /**< List of active supplicants */
    supp_list_t waiting_supp_list;                           /**< List of waiting supplicants */
    shared_comp_list_t shared_comp_list;                     /**< Shared component list */
    struct event_storage *timer;                             /**< Timer */
    pae_auth_gtk_t gtks;                                     /**< Material for GTKs */
    pae_auth_gtk_t lgtks;                                    /**< Material for LGTKs */
    const sec_prot_certs_t *certs;                           /**< Certificates */
    sec_prot_keys_nw_info_t *sec_keys_nw_info;               /**< Security keys network information */
    sec_cfg_t *sec_cfg;                                      /**< Security configuration */
    uint16_t supp_max_number;                                /**< Max number of stored supplicants */
    uint16_t waiting_supp_list_size;                         /**< Waiting supplicants list size */
    uint8_t relay_socked_msg_if_instance_id;                 /**< Relay socket message interface instance identifier */
    uint8_t radius_socked_msg_if_instance_id;                /**< Radius socket message interface instance identifier */
    bool timer_running : 1;                                  /**< Timer is running */
} pae_auth_t;

static int8_t ws_pae_auth_network_keys_from_gtks_set(pae_auth_t *pae_auth, bool is_lgtk);
static int8_t ws_pae_auth_active_gtk_set(sec_prot_gtk_keys_t *gtks, uint8_t index);
static int8_t ws_pae_auth_network_key_index_set(pae_auth_t *pae_auth, uint8_t index, bool is_lgtk);
static void ws_pae_auth_free(pae_auth_t *pae_auth);
static pae_auth_t *ws_pae_auth_get(struct net_if *interface_ptr);
static pae_auth_t *ws_pae_auth_by_kmp_service_get(kmp_service_t *service);
static int8_t ws_pae_auth_event_send(kmp_service_t *service, void *data);
static void ws_pae_auth_tasklet_handler(struct event_payload *event);
static uint32_t ws_pae_auth_lifetime_key_frame_cnt_check(pae_auth_t *pae_auth, sec_prot_gtk_keys_t *keys, pae_auth_gtk_t *pae_keys, uint8_t gtk_index, bool is_lgtk, int seconds);
static void ws_pae_auth_gtk_insert(sec_prot_gtk_keys_t *gtks, const uint8_t gtk[GTK_LEN], int lifetime, bool is_lgtk);
static void ws_pae_auth_gtk_key_insert(sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *next_gtks, uint32_t lifetime, bool is_lgtk);
static int8_t ws_pae_auth_new_gtk_activate(sec_prot_gtk_keys_t *gtks);
static int8_t ws_pae_auth_timer_if_start(kmp_service_t *service, kmp_api_t *kmp);
static int8_t ws_pae_auth_timer_if_stop(kmp_service_t *service, kmp_api_t *kmp);
static int8_t ws_pae_auth_timer_start(pae_auth_t *pae_auth);
static int8_t ws_pae_auth_timer_stop(pae_auth_t *pae_auth);
static int8_t ws_pae_auth_shared_comp_add(kmp_service_t *service, kmp_shared_comp_t *data);
static int8_t ws_pae_auth_shared_comp_remove(kmp_service_t *service, kmp_shared_comp_t *data);
static bool ws_pae_auth_timer_running(pae_auth_t *pae_auth);
static void ws_pae_auth_kmp_service_addr_get(kmp_service_t *service, kmp_api_t *kmp, kmp_addr_t *local_addr, kmp_addr_t *remote_addr);
static void ws_pae_auth_kmp_service_ip_addr_get(kmp_service_t *service, kmp_api_t *kmp, uint8_t *address);
static kmp_api_t *ws_pae_auth_kmp_service_api_get(kmp_service_t *service, kmp_api_t *kmp, kmp_type_e type);
static bool ws_pae_auth_active_limit_reached(pae_auth_t *pae_auth);
static kmp_api_t *ws_pae_auth_kmp_incoming_ind(kmp_service_t *service, uint8_t msg_if_instance_id, kmp_type_e type, const kmp_addr_t *addr, const void *pdu, uint16_t size);
static void ws_pae_auth_kmp_api_create_confirm(kmp_api_t *kmp, kmp_result_e result);
static void ws_pae_auth_kmp_api_create_indication(kmp_api_t *kmp, kmp_type_e type, kmp_addr_t *addr);
static bool ws_pae_auth_kmp_api_finished_indication(kmp_api_t *kmp, kmp_result_e result, kmp_sec_keys_t *sec_keys);
static bool ws_pae_auth_next_kmp_trigger(pae_auth_t *pae_auth, supp_entry_t *supp_entry);
static kmp_type_e ws_pae_auth_next_protocol_get(pae_auth_t *pae_auth, supp_entry_t *supp_entry);
static kmp_api_t *ws_pae_auth_kmp_create_and_start(kmp_service_t *service, kmp_type_e type, uint8_t socked_msg_if_instance_id, supp_entry_t *supp_entry, sec_cfg_t *sec_cfg);
static void ws_pae_auth_kmp_api_finished(kmp_api_t *kmp);
static void ws_pae_auth_active_supp_deleted(void *pae_auth);
static void ws_pae_auth_waiting_supp_deleted(void *pae_auth);

static int8_t tasklet_id = -1;
static NS_LIST_DEFINE(pae_auth_list, pae_auth_t, link);

int8_t ws_pae_auth_init(struct net_if *interface_ptr,
                        sec_prot_gtk_keys_t *next_gtks,
                        sec_prot_gtk_keys_t *next_lgtks,
                        const sec_prot_certs_t *certs,
                        sec_cfg_t *sec_cfg,
                        sec_prot_keys_nw_info_t *sec_keys_nw_info,
                        frame_counters_t *gtk_frame_counters,
                        frame_counters_t *lgtk_frame_counters)
{
    if (!interface_ptr || !next_gtks || !next_lgtks || !certs || !sec_cfg || !sec_keys_nw_info || !gtk_frame_counters || !lgtk_frame_counters) {
        return -1;
    }

    if (ws_pae_auth_get(interface_ptr) != NULL) {
        return 0;
    }

    pae_auth_t *pae_auth = malloc(sizeof(pae_auth_t));
    if (!pae_auth) {
        return -1;
    }

    pae_auth->interface_ptr = interface_ptr;
    ws_pae_lib_supp_list_init(&pae_auth->active_supp_list);
    ws_pae_lib_supp_list_init(&pae_auth->waiting_supp_list);
    ws_pae_lib_shared_comp_list_init(&pae_auth->shared_comp_list);
    pae_auth->timer = NULL;

    pae_auth->hash_set = NULL;
    pae_auth->nw_key_insert = NULL;
    pae_auth->nw_key_index_set = NULL;
    pae_auth->nw_info_updated = NULL;
    pae_auth->ip_addr_get = NULL;
    pae_auth->congestion_get = NULL;

    pae_auth->certs = certs;
    pae_auth->sec_keys_nw_info = sec_keys_nw_info;
    pae_auth->sec_cfg = sec_cfg;
    pae_auth->supp_max_number = SUPPLICANT_MAX_NUMBER;
    pae_auth->waiting_supp_list_size = 0;

    pae_auth->gtks.next_gtks = next_gtks;
    pae_auth->gtks.frame_counters = gtk_frame_counters;
    pae_auth->gtks.prev_frame_cnt_timer = FRAME_CNT_TIMER;
    pae_auth->gtks.gtk_new_inst_req_exp = false;

    pae_auth->lgtks.next_gtks = next_lgtks;
    pae_auth->lgtks.frame_counters = lgtk_frame_counters;
    pae_auth->lgtks.prev_frame_cnt_timer = FRAME_CNT_TIMER;
    pae_auth->lgtks.gtk_new_inst_req_exp = false;

    pae_auth->relay_socked_msg_if_instance_id = 0;
    pae_auth->radius_socked_msg_if_instance_id = 0;

    pae_auth->kmp_service = kmp_service_create();
    BUG_ON(!pae_auth->kmp_service);

    kmp_service_cb_register(pae_auth->kmp_service,
                            ws_pae_auth_kmp_incoming_ind,
                            ws_pae_auth_kmp_service_addr_get,
                            ws_pae_auth_kmp_service_ip_addr_get,
                            ws_pae_auth_kmp_service_api_get);
    kmp_service_event_if_register(pae_auth->kmp_service, ws_pae_auth_event_send);
    kmp_service_timer_if_register(pae_auth->kmp_service,
                                  ws_pae_auth_timer_if_start,
                                  ws_pae_auth_timer_if_stop);
    kmp_service_shared_comp_if_register(pae_auth->kmp_service,
                                        ws_pae_auth_shared_comp_add,
                                        ws_pae_auth_shared_comp_remove);

    auth_key_sec_prot_register(pae_auth->kmp_service);

    // Register radius EAP-TLS and radius client security protocols
    radius_eap_tls_sec_prot_register(pae_auth->kmp_service);
    radius_client_sec_prot_register(pae_auth->kmp_service);

    // Register EAP-TLS and TLS security protocols
    auth_eap_tls_sec_prot_register(pae_auth->kmp_service);
    server_tls_sec_prot_register(pae_auth->kmp_service);

    auth_fwh_sec_prot_register(pae_auth->kmp_service);

    auth_gkh_sec_prot_register(pae_auth->kmp_service);

    msg_sec_prot_register(pae_auth->kmp_service);

    if (tasklet_id < 0) {
        tasklet_id = event_handler_create(ws_pae_auth_tasklet_handler);
        BUG_ON(tasklet_id < 0);
    }

    if (ws_pae_auth_timer_stop(pae_auth) < 0) {
        goto error;
    }

    ns_list_add_to_end(&pae_auth_list, pae_auth);

    return 0;

error:
    ws_pae_auth_free(pae_auth);

    return -1;
}

int8_t ws_pae_auth_addresses_set(struct net_if *interface_ptr, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port)
{
    if (!interface_ptr || !remote_addr) {
        return -1;
    }

    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return -1;
    }
    if (!pae_auth->kmp_service) {
        return -1;
    }

    if (kmp_socket_if_register(pae_auth->kmp_service, &pae_auth->relay_socked_msg_if_instance_id, true, local_port, remote_addr, remote_port) < 0) {
        return -1;
    }

    return 0;
}

int8_t ws_pae_auth_radius_address_set(struct net_if *interface_ptr, const struct sockaddr_storage *remote_addr)
{
    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return -1;
    }
    if (!pae_auth->kmp_service) {
        return -1;
    }

    if (kmp_socket_if_register(pae_auth->kmp_service, &pae_auth->radius_socked_msg_if_instance_id, false, 0, remote_addr, 1812) < 0) {
        return -1;
    }

    return 0;
}

void ws_pae_auth_cb_register(struct net_if *interface_ptr,
                             ws_pae_auth_gtk_hash_set *hash_set,
                             ws_pae_auth_nw_key_insert *nw_key_insert,
                             ws_pae_auth_nw_key_index_set *nw_key_index_set,
                             ws_pae_auth_nw_info_updated *nw_info_updated,
                             ws_pae_auth_ip_addr_get *ip_addr_get,
                             ws_pae_auth_congestion_get *congestion_get)
{
    if (!interface_ptr) {
        return;
    }

    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return;
    }

    pae_auth->hash_set = hash_set;
    pae_auth->nw_key_insert = nw_key_insert;
    pae_auth->nw_key_index_set = nw_key_index_set;
    pae_auth->nw_info_updated = nw_info_updated;
    pae_auth->ip_addr_get = ip_addr_get;
    pae_auth->congestion_get = congestion_get;
}

void ws_pae_auth_start(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return;
    }

    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return;
    }

    // Checks if there is predefined active key
    int gtk_index = sec_prot_keys_gtk_status_active_get(pae_auth->sec_keys_nw_info->gtks);
    if (gtk_index < 0) {
        // If there is no key, inserts a new one
        ws_pae_auth_gtk_key_insert(pae_auth->sec_keys_nw_info->gtks, pae_auth->gtks.next_gtks, pae_auth->sec_cfg->timing_ffn.expire_offset, false);
        gtk_index = sec_prot_keys_gtk_install_order_first_index_get(pae_auth->sec_keys_nw_info->gtks);
        ws_pae_auth_active_gtk_set(pae_auth->sec_keys_nw_info->gtks, gtk_index);
    } else {
        ws_pae_auth_active_gtk_set(pae_auth->sec_keys_nw_info->gtks, gtk_index);
    }

    // Checks if there is predefined active key
    int lgtk_index = sec_prot_keys_gtk_status_active_get(pae_auth->sec_keys_nw_info->lgtks);
    if (lgtk_index < 0) {
        // If there is no key, inserts a new one
        ws_pae_auth_gtk_key_insert(pae_auth->sec_keys_nw_info->lgtks, pae_auth->lgtks.next_gtks, pae_auth->sec_cfg->timing_lfn.expire_offset, true);
        lgtk_index = sec_prot_keys_gtk_install_order_first_index_get(pae_auth->sec_keys_nw_info->lgtks);
        ws_pae_auth_active_gtk_set(pae_auth->sec_keys_nw_info->lgtks, lgtk_index);
    } else {
        ws_pae_auth_active_gtk_set(pae_auth->sec_keys_nw_info->lgtks, lgtk_index);
    }

    // Update keys to NVM as needed
    pae_auth->nw_info_updated(pae_auth->interface_ptr);

    // Inserts keys and updates GTK hash on stack
    ws_pae_auth_network_keys_from_gtks_set(pae_auth, false);
    ws_pae_auth_network_keys_from_gtks_set(pae_auth, true);

    // Sets active key index
    ws_pae_auth_network_key_index_set(pae_auth, gtk_index, false);
    ws_pae_auth_network_key_index_set(pae_auth, lgtk_index, true);
}

void ws_pae_auth_gtks_updated(struct net_if *interface_ptr, bool is_lgtk)
{
    if (!interface_ptr) {
        return;
    }

    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return;
    }

    ws_pae_auth_network_keys_from_gtks_set(pae_auth, is_lgtk);
}

int8_t ws_pae_auth_nw_key_index_update(struct net_if *interface_ptr, uint8_t index, bool is_lgtk)
{
    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    sec_prot_gtk_keys_t *gtks;

    if (!pae_auth)
        return -1;
    if (is_lgtk)
        gtks = pae_auth->sec_keys_nw_info->lgtks;
    else
        gtks = pae_auth->sec_keys_nw_info->gtks;

    ws_pae_auth_active_gtk_set(gtks, index);
    ws_pae_auth_network_key_index_set(pae_auth, index, is_lgtk);
    return 0;
}

int8_t ws_pae_auth_node_keys_remove(struct net_if *interface_ptr, uint8_t *eui_64)
{
    int8_t ret_value = -1;

    if (!interface_ptr) {
        return ret_value;
    }

    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return ret_value;
    }

    // Checks if supplicant is active or waiting
    supp_entry_t *supp = ws_pae_lib_supp_list_entry_eui_64_get(&pae_auth->active_supp_list, eui_64);
    if (!supp) {
        supp = ws_pae_lib_supp_list_entry_eui_64_get(&pae_auth->waiting_supp_list, eui_64);
    }

    if (supp) {
        // Deletes keys and marks as revoked
        sec_prot_keys_pmk_delete(&supp->sec_keys);
        sec_prot_keys_ptk_delete(&supp->sec_keys);
        supp->access_revoked = true;
        tr_info("Access revoked; keys removed, eui-64: %s", tr_eui64(eui_64));
        ret_value = 0;
    }

    if (ws_pae_key_storage_supp_delete(pae_auth, eui_64)) {
        tr_info("Access revoked; key store deleted, eui-64: %s", tr_eui64(eui_64));
        ret_value = 0;
    }

    return ret_value;
}

int8_t ws_pae_auth_node_access_revoke_start(struct net_if *interface_ptr, bool is_lgtk, uint8_t new_gtk[GTK_LEN])
{
    struct sec_timing *timer_cfg;
    sec_prot_gtk_keys_t *key_nw_info, *key_nw_info_next;

    if (!interface_ptr) {
        return -1;
    }

    pae_auth_t *pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth) {
        return -1;
    }

    if (is_lgtk) {
        timer_cfg = &pae_auth->sec_cfg->timing_lfn;
        key_nw_info= pae_auth->sec_keys_nw_info->lgtks;
        key_nw_info_next = pae_auth->lgtks.next_gtks;
    } else {
        timer_cfg = &pae_auth->sec_cfg->timing_ffn;
        key_nw_info= pae_auth->sec_keys_nw_info->gtks;
        key_nw_info_next = pae_auth->gtks.next_gtks;
    }

    // Gets active GTK
    int8_t active_index = sec_prot_keys_gtk_status_active_get(key_nw_info);

    if (active_index >= 0) {
        // As default removes other keys than active
        int8_t not_removed_index = active_index;
        uint32_t revocation_lifetime = timer_cfg->expire_offset / timer_cfg->revocat_lifetime_reduct;
        uint32_t active_lifetime = sec_prot_keys_gtk_lifetime_get(key_nw_info, active_index);
        uint64_t current_time = time_now_s(CLOCK_REALTIME);

        // If active GTK lifetime is larger than revocation lifetime decrements active GTK lifetime
        if (active_lifetime > revocation_lifetime) {
            sec_prot_keys_gtk_lifetime_decrement(key_nw_info, active_index, current_time, active_lifetime - revocation_lifetime, true);
            tr_info("Access revocation start, %s active index: %i, revoked lifetime: %"PRIu32"", is_lgtk ? "LGTK" : "GTK", active_index, revocation_lifetime);
        } else {
            // Otherwise decrements lifetime of the GTK to be installed after the active one
            int8_t second_index = sec_prot_keys_gtk_install_order_second_index_get(key_nw_info);
            if (second_index >= 0) {
                // Second GTK revocation lifetime is the active GTK lifetime added with revocation time
                uint32_t second_revocation_lifetime = active_lifetime + revocation_lifetime;

                uint32_t second_lifetime = sec_prot_keys_gtk_lifetime_get(key_nw_info, second_index);
                if (second_lifetime > second_revocation_lifetime) {
                    sec_prot_keys_gtk_lifetime_decrement(key_nw_info, second_index, current_time, second_lifetime - second_revocation_lifetime, true);
                    tr_info("Access revocation start, %s second active index: %i, revoked lifetime: %"PRIu32"", is_lgtk ? "LGTK" : "GTK", second_index, second_revocation_lifetime);
                }
                // Removes other keys than active and GTK to be installed next
                not_removed_index = second_index;
            }
        }

        // Deletes other GTKs
        int8_t last_index = sec_prot_keys_gtk_install_order_last_index_get(key_nw_info);
        while (last_index >= 0 && last_index != not_removed_index) {
            tr_info("Access revocation %s clear index: %i", is_lgtk ? "LGTK" : "GTK", last_index);
            sec_prot_keys_gtk_clear(key_nw_info, last_index);
            last_index = sec_prot_keys_gtk_install_order_last_index_get(key_nw_info);
        }
    }

    // Adds new GTK
    if (new_gtk)
        ws_pae_auth_gtk_insert(key_nw_info, new_gtk, timer_cfg->expire_offset, is_lgtk);
    else
        ws_pae_auth_gtk_key_insert(key_nw_info, key_nw_info_next, timer_cfg->expire_offset, is_lgtk);
    ws_pae_auth_network_keys_from_gtks_set(pae_auth, is_lgtk);

    // Update keys to NVM as needed
    pae_auth->nw_info_updated(pae_auth->interface_ptr);

    return 0;
}

static int8_t ws_pae_auth_network_keys_from_gtks_set(pae_auth_t *pae_auth, bool is_lgtk)
{
    sec_prot_gtk_keys_t *gtks;

    if (is_lgtk)
        gtks = pae_auth->sec_keys_nw_info->lgtks;
    else
        gtks = pae_auth->sec_keys_nw_info->gtks;

    // Authenticator keys are always fresh
    sec_prot_keys_gtk_status_all_fresh_set(gtks);

    if (pae_auth->hash_set) {
        gtkhash_t gtk_hash[4];
        sec_prot_keys_gtks_hash_generate(gtks, gtk_hash);
        pae_auth->hash_set(pae_auth->interface_ptr, gtk_hash, is_lgtk);
    }

    if (pae_auth->nw_key_insert) {
        pae_auth->nw_key_insert(pae_auth->interface_ptr, gtks, is_lgtk);
    }

    return 0;
}

static int8_t ws_pae_auth_active_gtk_set(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    return sec_prot_keys_gtk_status_active_set(gtks, index);
}

static int8_t ws_pae_auth_gtk_clear(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    return sec_prot_keys_gtk_clear(gtks, index);
}

static int8_t ws_pae_auth_network_key_index_set(pae_auth_t *pae_auth, uint8_t index, bool is_lgtk)
{
    if (pae_auth->nw_key_index_set) {
        pae_auth->nw_key_index_set(pae_auth->interface_ptr, index, is_lgtk);
    }

    return 0;
}

static void ws_pae_auth_free(pae_auth_t *pae_auth)
{
    if (!pae_auth) {
        return;
    }

    ws_pae_lib_shared_comp_list_free(&pae_auth->shared_comp_list);

    ws_pae_lib_supp_list_delete(&pae_auth->active_supp_list);
    ws_pae_lib_supp_list_delete(&pae_auth->waiting_supp_list);

    kmp_socket_if_unregister(pae_auth->kmp_service);

    kmp_service_delete(pae_auth->kmp_service);

    ns_list_remove(&pae_auth_list, pae_auth);
    free(pae_auth);
}

static pae_auth_t *ws_pae_auth_get(struct net_if *interface_ptr)
{
    ns_list_foreach(pae_auth_t, entry, &pae_auth_list) {
        if (entry->interface_ptr == interface_ptr) {
            return entry;
        }
    }

    return NULL;
}

static pae_auth_t *ws_pae_auth_by_kmp_service_get(kmp_service_t *service)
{
    ns_list_foreach(pae_auth_t, entry, &pae_auth_list) {
        if (entry->kmp_service == service) {
            return entry;
        }
    }

    return NULL;
}

static int8_t ws_pae_auth_event_send(kmp_service_t *service, void *data)
{
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        return -1;
    }

    struct event_payload event = {
        .receiver = tasklet_id,
        .event_id = pae_auth->interface_ptr->id,
        .data_ptr = data,
    };

    if (event_send(&event) != 0) {
        return -1;
    }

    return 0;
}

static void ws_pae_auth_tasklet_handler(struct event_payload *event)
{
    pae_auth_t *pae_auth = NULL;

    ns_list_foreach(pae_auth_t, entry, &pae_auth_list) {
        if (entry->interface_ptr->id == event->event_id) {
            pae_auth = entry;
            break;
        }
    }

    if (pae_auth) {
        kmp_service_event_if_event(pae_auth->kmp_service, event->data_ptr);
    }
}

void ws_pae_auth_fast_timer(uint16_t ticks)
{
    ns_list_foreach(pae_auth_t, pae_auth, &pae_auth_list) {
        if (!ws_pae_auth_timer_running(pae_auth)) {
            continue;
        }

        // Updates KMP timers
        bool active_running = ws_pae_lib_supp_list_timer_update(pae_auth, &pae_auth->active_supp_list, ticks, kmp_service_timer_if_timeout, ws_pae_auth_active_supp_deleted);
        bool wait_running = ws_pae_lib_supp_list_timer_update(pae_auth, &pae_auth->waiting_supp_list, ticks, kmp_service_timer_if_timeout, ws_pae_auth_waiting_supp_deleted);
        if (!active_running && !wait_running) {
            ws_pae_auth_timer_stop(pae_auth);
        }
    }
}

void ws_pae_auth_slow_timer_key(pae_auth_t *pae_auth, int i, uint16_t seconds, bool is_lgtk)
{
    struct sec_timing *timer_gtk_cfg;
    pae_auth_gtk_t *pae_auth_gtk;
    sec_prot_gtk_keys_t *keys;
    uint64_t current_time = time_now_s(CLOCK_REALTIME);
    int8_t active_index;

    if (is_lgtk) {
        keys = pae_auth->sec_keys_nw_info->lgtks;
        pae_auth_gtk = &pae_auth->lgtks;
        active_index = sec_prot_keys_gtk_status_active_get(pae_auth->sec_keys_nw_info->lgtks);
        timer_gtk_cfg = &pae_auth->sec_cfg->timing_lfn;
    } else {
        keys = pae_auth->sec_keys_nw_info->gtks;
        pae_auth_gtk = &pae_auth->gtks;
        active_index = sec_prot_keys_gtk_status_active_get(pae_auth->sec_keys_nw_info->gtks);
        timer_gtk_cfg = &pae_auth->sec_cfg->timing_ffn;
    }

    if (!sec_prot_keys_gtk_is_set(keys, i)) {
        return;
    }
    uint32_t gtk_lifetime_dec_extra_seconds = 0;
    if (active_index == i)
        gtk_lifetime_dec_extra_seconds = ws_pae_auth_lifetime_key_frame_cnt_check(pae_auth, keys, pae_auth_gtk, i, is_lgtk, seconds);
    uint32_t timer_seconds = sec_prot_keys_gtk_lifetime_decrement(keys, i, current_time, seconds + gtk_lifetime_dec_extra_seconds, true);
    if (active_index == i) {
        if (!pae_auth_gtk->gtk_new_inst_req_exp &&
            timer_gtk_cfg->new_install_req > 0 &&
            timer_gtk_cfg->expire_offset - timer_gtk_cfg->new_install_req * timer_gtk_cfg->expire_offset / 100 > timer_seconds) {
            pae_auth_gtk->gtk_new_inst_req_exp = true;
            int8_t second_index = sec_prot_keys_gtk_install_order_second_index_get(keys);
            if (second_index < 0) {
                tr_info("%s new install required active index: %i, time: %"PRIu32", system time: %"PRIu32"",
                        is_lgtk ? "LGTK" : "GTK", active_index, timer_seconds, g_monotonic_time_100ms / 10);
                ws_pae_auth_gtk_key_insert(keys, pae_auth_gtk->next_gtks, timer_gtk_cfg->expire_offset, is_lgtk);
                ws_pae_auth_network_keys_from_gtks_set(pae_auth, is_lgtk);
                // Update keys to NVM as needed
                pae_auth->nw_info_updated(pae_auth->interface_ptr);
            } else {
                tr_info("%s new install already done; second index: %i, time: %"PRIu32", system time: %"PRIu32"",
                        is_lgtk ? "LGTK" : "GTK", second_index, timer_seconds, g_monotonic_time_100ms / 10);
            }
        }

        if (timer_gtk_cfg->expire_offset / timer_gtk_cfg->new_act_time > timer_seconds) {
            int8_t new_active_index = ws_pae_auth_new_gtk_activate(keys);
            tr_info("%s new activation time active index: %i, time: %"PRIu32", new index: %i, system time: %"PRIu32"",
                    is_lgtk ? "LGTK" : "GTK", active_index, timer_seconds, new_active_index, g_monotonic_time_100ms / 10);
            if (new_active_index >= 0) {
                ws_pae_auth_network_key_index_set(pae_auth, new_active_index, is_lgtk);
            }
            pae_auth_gtk->gtk_new_inst_req_exp = false;
            // Update keys to NVM as needed
            pae_auth->nw_info_updated(pae_auth->interface_ptr);
        }
        if (gtk_lifetime_dec_extra_seconds != 0) {
            // Update keys to NVM as needed
            pae_auth->nw_info_updated(pae_auth->interface_ptr);
        }
    }

    if (timer_seconds == 0) {
        tr_info("%s expired index: %i, system time: %"PRIu32"",
                is_lgtk ? "LGTK" : "GTK", i, g_monotonic_time_100ms / 10);
        ws_pae_auth_gtk_clear(keys, i);
        ws_pae_auth_network_keys_from_gtks_set(pae_auth, is_lgtk);
        // Update keys to NVM as needed
        pae_auth->nw_info_updated(pae_auth->interface_ptr);
    }
}

void ws_pae_auth_slow_timer(uint16_t seconds)
{
    ns_list_foreach(pae_auth_t, pae_auth, &pae_auth_list) {
        // Gets index of currently active GTK
        for (uint8_t i = 0; i < GTK_NUM; i++) {
            ws_pae_auth_slow_timer_key(pae_auth, i, seconds, false);
        }
        for (uint8_t i = 0; i < LGTK_NUM; i++) {
            ws_pae_auth_slow_timer_key(pae_auth, i, seconds, true);
        }

        ws_pae_lib_supp_list_slow_timer_update(&pae_auth->active_supp_list, seconds);

        ws_pae_lib_shared_comp_list_timeout(&pae_auth->shared_comp_list, seconds);
    }
}

static uint32_t ws_pae_auth_lifetime_key_frame_cnt_check(pae_auth_t *pae_auth, sec_prot_gtk_keys_t *keys,
                                                         pae_auth_gtk_t *pae_auth_gtk, uint8_t gtk_index,
                                                         bool is_lgtk, int seconds)
{
    uint32_t key_lifetime_left = sec_prot_keys_gtk_lifetime_get(keys, gtk_index);
    const struct sec_timing *timing;
    uint32_t decrement_seconds = 0;
    uint32_t key_new_install_threshold;

    if (pae_auth_gtk->prev_frame_cnt_timer > seconds) {
        pae_auth_gtk->prev_frame_cnt_timer -= seconds;
        return 0;
    }
    pae_auth_gtk->prev_frame_cnt_timer = FRAME_CNT_TIMER;

    timing = is_lgtk ? &pae_auth->sec_cfg->timing_lfn : &pae_auth->sec_cfg->timing_ffn;
    key_new_install_threshold = timing->expire_offset - timing->new_install_req * timing->expire_offset / 100;

    if (pae_auth_gtk->frame_counters->counter[gtk_index].frame_counter >= FRAME_CNT_THRESHOLD) {
        if (key_lifetime_left > key_new_install_threshold) {
            decrement_seconds = key_lifetime_left - key_new_install_threshold;
            tr_info("Decrement %s lifetime update, seconds %"PRIu32, is_lgtk ? "LGTK" : "GTK", decrement_seconds);
        }
    }

    return decrement_seconds;
}

static void ws_pae_auth_gtk_insert(sec_prot_gtk_keys_t *gtks, const uint8_t gtk[GTK_LEN], int lifetime, bool is_lgtk)
{
    int i_install, i_last;

    // Gets latest installed key lifetime and adds GTK expire offset to it
    i_last = sec_prot_keys_gtk_install_order_last_index_get(gtks);
    if (i_last >= 0)
        lifetime += sec_prot_keys_gtk_lifetime_get(gtks, i_last);

    // Installs the new key
    i_install = sec_prot_keys_gtk_install_index_get(gtks, is_lgtk);
    sec_prot_keys_gtk_clear(gtks, i_install);
    sec_prot_keys_gtk_set(gtks, i_install, gtk, lifetime);

    // Authenticator keys are always fresh
    sec_prot_keys_gtk_status_all_fresh_set(gtks);

    tr_info("%s install new index: %i, lifetime: %"PRIu32" system time: %"PRIu32"",
            is_lgtk ? "LGTK" : "GTK", i_install, lifetime, g_monotonic_time_100ms / 10);
}

static void ws_pae_auth_gtk_key_insert(sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *next_gtks, uint32_t lifetime, bool is_lgtk)
{
    // Key to install
    uint8_t gtk_value[GTK_LEN];

    // Checks if next GTK values are set and gets first GTK to install
    int8_t next_gtk_index = sec_prot_keys_gtk_install_order_first_index_get(next_gtks);
    if (next_gtk_index >= 0) {
        // Gets GTK value
        uint8_t *gtk = sec_prot_keys_gtk_get(next_gtks, next_gtk_index);
        memcpy(gtk_value, gtk, GTK_LEN);
        // Sets same key back to next GTKs but as the last key to be installed
        sec_prot_keys_gtk_clear(next_gtks, next_gtk_index);
        sec_prot_keys_gtk_set(next_gtks, next_gtk_index, gtk_value, 0);
    } else {
        do {
            rand_get_n_bytes_random(gtk_value, GTK_LEN);
        } while (sec_prot_keys_gtk_valid_check(gtk_value) < 0);
    }

    ws_pae_auth_gtk_insert(gtks, gtk_value, lifetime, is_lgtk);
}

static int8_t ws_pae_auth_new_gtk_activate(sec_prot_gtk_keys_t *gtks)
{
    int8_t new_active_index = sec_prot_keys_gtk_install_order_second_index_get(gtks);
    if (new_active_index >= 0) {
        ws_pae_auth_active_gtk_set(gtks, new_active_index);
    }

    return new_active_index;
}

static int8_t ws_pae_auth_timer_if_start(kmp_service_t *service, kmp_api_t *kmp)
{
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        return -1;
    }

    if (ws_pae_auth_timer_start(pae_auth) < 0) {
        return -1;
    }

    supp_entry_t *supp_entry = kmp_api_data_get(kmp);
    if (!supp_entry) {
        return -1;
    }

    kmp_entry_t *entry = ws_pae_lib_kmp_list_entry_get(&supp_entry->kmp_list, kmp);
    if (!entry) {
        return -1;
    }

    ws_pae_lib_kmp_timer_start(&supp_entry->kmp_list, entry);
    return 0;
}

static int8_t ws_pae_auth_timer_if_stop(kmp_service_t *service, kmp_api_t *kmp)
{
    (void) service;

    supp_entry_t *supp_entry = kmp_api_data_get(kmp);

    kmp_entry_t *entry = ws_pae_lib_kmp_list_entry_get(&supp_entry->kmp_list, kmp);
    if (!entry) {
        return -1;
    }

    ws_pae_lib_kmp_timer_stop(&supp_entry->kmp_list, entry);
    return 0;
}

static int8_t ws_pae_auth_shared_comp_add(kmp_service_t *service, kmp_shared_comp_t *data)
{
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        return -1;
    }

    return ws_pae_lib_shared_comp_list_add(&pae_auth->shared_comp_list, data);
}

static int8_t ws_pae_auth_shared_comp_remove(kmp_service_t *service, kmp_shared_comp_t *data)
{
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        return -1;
    }

    return ws_pae_lib_shared_comp_list_remove(&pae_auth->shared_comp_list, data);
}

static int8_t ws_pae_auth_timer_start(pae_auth_t *pae_auth)
{
    pae_auth->timer_running = true;
    return 0;
}

static int8_t ws_pae_auth_timer_stop(pae_auth_t *pae_auth)
{
    pae_auth->timer_running = false;
    return 0;
}

static bool ws_pae_auth_timer_running(pae_auth_t *pae_auth)
{
    return pae_auth->timer_running;
}

static void ws_pae_auth_kmp_service_addr_get(kmp_service_t *service, kmp_api_t *kmp, kmp_addr_t *local_addr, kmp_addr_t *remote_addr)
{
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    struct net_if *cur;

    if (!pae_auth) {
        return;
    }

    cur = protocol_stack_interface_info_get_by_id(pae_auth->interface_ptr->id);
    if (cur)
        kmp_address_eui_64_set(local_addr, cur->mac);

    // Get supplicant address
    supp_entry_t *entry = kmp_api_data_get(kmp);
    if (entry) {
        kmp_address_copy(remote_addr, &entry->addr);
    }
}

static void ws_pae_auth_kmp_service_ip_addr_get(kmp_service_t *service, kmp_api_t *kmp, uint8_t *address)
{
    (void) kmp;

    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        return;
    }

    pae_auth->ip_addr_get(pae_auth->interface_ptr, address);
}

static kmp_api_t *ws_pae_auth_kmp_service_api_get(kmp_service_t *service, kmp_api_t *kmp, kmp_type_e type)
{
    (void) service;

    supp_entry_t *supp_entry = kmp_api_data_get(kmp);
    if (!supp_entry) {
        return NULL;
    }

    return ws_pae_lib_kmp_list_type_get(&supp_entry->kmp_list, type);
}

static bool ws_pae_auth_active_limit_reached(pae_auth_t *pae_auth)
{
    return pae_auth->congestion_get(pae_auth->interface_ptr);
}

static supp_entry_t *ws_pae_auth_waiting_supp_list_add(pae_auth_t *pae_auth, supp_entry_t *supp_entry, const kmp_addr_t *addr)
{
    // Entry is already allocated
    if (supp_entry) {
        ns_list_add_to_start(&pae_auth->waiting_supp_list, supp_entry);
        pae_auth->waiting_supp_list_size++;
    } else {
        supp_entry = ws_pae_lib_supp_list_add(&pae_auth->waiting_supp_list, addr);
        if (!supp_entry) {
            tr_info("PAE: waiting list no memory, eui-64: %s", tr_eui64(addr->eui_64));
            return NULL;
        }
        pae_auth->waiting_supp_list_size++;
        sec_prot_keys_init(&supp_entry->sec_keys, pae_auth->sec_keys_nw_info->gtks, pae_auth->sec_keys_nw_info->lgtks, pae_auth->certs);
    }

    // 90 percent of the EAPOL temporary entry lifetime (10 ticks per second)
    supp_entry->waiting_ticks = WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME * 900 / 100;

    tr_info("PAE: to waiting, list size %i, retry %i, eui-64: %s", pae_auth->waiting_supp_list_size, supp_entry->waiting_ticks, tr_eui64(supp_entry->addr.eui_64));

    return supp_entry;
}

static kmp_api_t *ws_pae_auth_kmp_incoming_ind(kmp_service_t *service, uint8_t msg_if_instance_id, kmp_type_e type, const kmp_addr_t *addr, const void *pdu, uint16_t size)
{
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        return NULL;
    }

    // For radius messages
    if (msg_if_instance_id == pae_auth->radius_socked_msg_if_instance_id) {
        // Find KMP from list of active supplicants based on radius message
        kmp_api_t *kmp_api = ws_pae_lib_supp_list_kmp_receive_check(&pae_auth->active_supp_list, pdu, size);
        return kmp_api;
    }

    // For relay messages find supplicant from list of active supplicants based on EUI-64
    supp_entry_t *supp_entry = ws_pae_lib_supp_list_entry_eui_64_get(&pae_auth->active_supp_list, kmp_address_eui_64_get(addr));

    if (!supp_entry) {
        // Check if supplicant is already on the the waiting supplicant list
        supp_entry = ws_pae_lib_supp_list_entry_eui_64_get(&pae_auth->waiting_supp_list, kmp_address_eui_64_get(addr));
        if (supp_entry) {
            /* Remove from waiting list (supplicant is later added to active list, or if no room back to the start of the
             * waiting list with updated timer)
             */
            ns_list_remove(&pae_auth->waiting_supp_list, supp_entry);
            pae_auth->waiting_supp_list_size--;
            supp_entry->waiting_ticks = 0;
        } else {
            // Find supplicant from key storage
            supp_entry = ws_pae_key_storage_supp_read(pae_auth, kmp_address_eui_64_get(addr), pae_auth->sec_keys_nw_info->gtks, pae_auth->sec_keys_nw_info->lgtks, pae_auth->certs);
        }

        // Checks if active supplicant list has space for new supplicants
        if (ws_pae_auth_active_limit_reached(pae_auth)) {
            WARN("%s: congestion detected, moving supplicant to waiting list", __func__);
            // If there is no space, add supplicant entry to the start of the waiting supplicant list
            supp_entry = ws_pae_auth_waiting_supp_list_add(pae_auth, supp_entry, addr);
            if (!supp_entry) {
                return 0;
            }
        } else {
            if (supp_entry) {
                /*
                 * If there is space and there is already an allocated supplicant, add it to active list and
                 * start/continue authentication
                 */
                tr_debug("PAE: to active, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
                ns_list_add_to_start(&pae_auth->active_supp_list, supp_entry);
            }
        }
    }

    // If supplicant does not exists create a new supplicant entry to the active list
    if (!supp_entry) {
        supp_entry = ws_pae_lib_supp_list_add(&pae_auth->active_supp_list, addr);
        if (!supp_entry) {
            return 0;
        }
        sec_prot_keys_init(&supp_entry->sec_keys, pae_auth->sec_keys_nw_info->gtks, pae_auth->sec_keys_nw_info->lgtks, pae_auth->certs);
    } else {
        // Updates relay address
        kmp_address_copy(&supp_entry->addr, addr);
    }

    // Increases waiting time for supplicant authentication
    ws_pae_lib_supp_timer_ticks_set(supp_entry, WAIT_FOR_AUTHENTICATION_TICKS);

    kmp_type_e kmp_type_to_search = type;

    // If radius is enabled, route EAP-TLS to radius EAP-TLS
    if (pae_auth->sec_cfg->radius_cfg != NULL && pae_auth->sec_cfg->radius_cfg->radius_addr_set && type == IEEE_802_1X_MKA) {
        kmp_type_to_search = RADIUS_IEEE_802_1X_MKA;
    }

    // Search for existing KMP for supplicant
    kmp_api_t *kmp = ws_pae_lib_kmp_list_type_get(&supp_entry->kmp_list, kmp_type_to_search);
    if (kmp) {
        struct eapol_pdu recv_eapol_pdu;
        kmp_api_t *kmp_tls;

        if (kmp_type_to_search != IEEE_802_1X_MKA)
            // Found KMP for 4WH or GKH
            return kmp;
        if (eapol_parse_pdu_header(pdu, size, &recv_eapol_pdu)) {
            if (recv_eapol_pdu.packet_type == EAPOL_EAP_TYPE) {
                // Received EAP packet, found corresponding KMP
                return kmp;
            } else if (recv_eapol_pdu.packet_type == EAPOL_KEY_TYPE) {
                // Received KEY packet for MKA: allow EAP exchange restart by wiping corresponding KMPs
                tr_info("MKA already ongoing; delete previous, eui-64: %s", trace_array(supp_entry->addr.eui_64, 8));
                ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, kmp);
                kmp_tls = ws_pae_lib_kmp_list_type_get(&supp_entry->kmp_list, TLS_PROT);
                if (kmp_tls)
                    ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, kmp_tls);
            }
        }
    }

    // Create a new KMP for initial eapol-key
    kmp = kmp_api_create(service, type + IEEE_802_1X_INITIAL_KEY, pae_auth->relay_socked_msg_if_instance_id, pae_auth->sec_cfg);

    if (!kmp) {
        return 0;
    }

    kmp_api_data_set(kmp, supp_entry);
    // Sets address to KMP
    kmp_api_addr_set(kmp, &supp_entry->addr);

    // Sets security keys to KMP
    kmp_api_sec_keys_set(kmp, &supp_entry->sec_keys);

    if (ws_pae_lib_kmp_list_add(&supp_entry->kmp_list, kmp) == NULL) {
        kmp_api_delete(kmp);
        return 0;
    }

    kmp_api_cb_register(kmp,
                        ws_pae_auth_kmp_api_create_confirm,
                        ws_pae_auth_kmp_api_create_indication,
                        ws_pae_auth_kmp_api_finished_indication,
                        ws_pae_auth_kmp_api_finished);

    if (kmp_api_start(kmp) < 0) {
        ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, kmp);
        return 0;
    }

    return kmp;
}

static void ws_pae_auth_kmp_api_create_confirm(kmp_api_t *kmp, kmp_result_e result)
{
    (void) kmp;
    (void) result;
    // If KMP-CREATE.request has failed, authentication error, just stop for now
}

static void ws_pae_auth_kmp_api_create_indication(kmp_api_t *kmp, kmp_type_e type, kmp_addr_t *addr)
{
    (void) type;
    (void) addr;
    // For now, accept every KMP-CREATE.indication
    kmp_api_create_response(kmp, KMP_RESULT_OK);
}

static bool ws_pae_auth_kmp_api_finished_indication(kmp_api_t *kmp, kmp_result_e result, kmp_sec_keys_t *sec_keys)
{
    (void) sec_keys;

    // For now, just ignore if not ok
    if (result != KMP_RESULT_OK) {
        return false;
    }

    supp_entry_t *supp_entry = kmp_api_data_get(kmp);
    if (!supp_entry) {
        // Should not be possible
        return false;
    }
    kmp_service_t *service = kmp_api_service_get(kmp);
    pae_auth_t *pae_auth = ws_pae_auth_by_kmp_service_get(service);
    if (!pae_auth) {
        // Should not be possible
        return false;
    }

    // Ensures that supplicant is in active supplicant list before initiating next KMP
    if (!ws_pae_lib_supp_list_entry_is_in_list(&pae_auth->active_supp_list, supp_entry)) {
        return false;
    }

    return ws_pae_auth_next_kmp_trigger(pae_auth, supp_entry);
}

static bool ws_pae_auth_next_kmp_trigger(pae_auth_t *pae_auth, supp_entry_t *supp_entry)
{
    // Get next protocol based on what keys supplicant has
    kmp_type_e next_type = ws_pae_auth_next_protocol_get(pae_auth, supp_entry);

    if (next_type == KMP_TYPE_NONE) {
        // Supplicant goes inactive after 15 seconds
        ws_pae_lib_supp_timer_ticks_set(supp_entry, WAIT_AFTER_AUTHENTICATION_TICKS);
        // All done
        return true;
    } else {
        kmp_api_t *api = ws_pae_lib_kmp_list_type_get(&supp_entry->kmp_list, next_type);
        if (api != NULL) {
            /* For other types than GTK, only one ongoing negotiation at the same time,
               for GTK there can be previous terminating and the new one for next key index */
            if (next_type != IEEE_802_11_GKH) {
                tr_info("KMP already ongoing; delete previous, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
                ws_pae_auth_kmp_api_finished(api);
            }
        }
    }

    // Increases waiting time for supplicant authentication
    ws_pae_lib_supp_timer_ticks_set(supp_entry, WAIT_FOR_AUTHENTICATION_TICKS);

    // Create new instance
    kmp_api_t *new_kmp = ws_pae_auth_kmp_create_and_start(pae_auth->kmp_service, next_type, pae_auth->relay_socked_msg_if_instance_id, supp_entry, pae_auth->sec_cfg);
    if (!new_kmp) {
        return false;
    }

    // For radius EAP-TLS create also radius client in addition to EAP-TLS
    if (next_type == RADIUS_IEEE_802_1X_MKA) {
        if (ws_pae_lib_kmp_list_type_get(&supp_entry->kmp_list, RADIUS_CLIENT_PROT) != NULL) {
            // Radius client already exists, wait for it to be deleted
            ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, new_kmp);
            return false;
        }
        // Create radius client instance */
        if (ws_pae_auth_kmp_create_and_start(pae_auth->kmp_service, RADIUS_CLIENT_PROT, pae_auth->radius_socked_msg_if_instance_id, supp_entry, pae_auth->sec_cfg) == NULL) {
            ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, new_kmp);
            return false;
        }
    }
    // For EAP-TLS create also TLS client in addition to EAP-TLS
    if (next_type == IEEE_802_1X_MKA) {
        if (ws_pae_lib_kmp_list_type_get(&supp_entry->kmp_list, TLS_PROT) != NULL) {
            // TLS already exists, wait for it to be deleted
            ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, new_kmp);
            return false;
        }
        // Create TLS instance */
        if (ws_pae_auth_kmp_create_and_start(pae_auth->kmp_service, TLS_PROT, pae_auth->relay_socked_msg_if_instance_id, supp_entry, pae_auth->sec_cfg) == NULL) {
            ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, new_kmp);
            return false;
        }
    }

    kmp_api_create_request(new_kmp, next_type, &supp_entry->addr, &supp_entry->sec_keys);
    return false;
}

static kmp_type_e ws_pae_auth_next_protocol_get(pae_auth_t *pae_auth, supp_entry_t *supp_entry)
{
    kmp_type_e next_type = KMP_TYPE_NONE;
    sec_prot_keys_t *sec_keys = &supp_entry->sec_keys;

    if (sec_keys->node_role == WS_NR_ROLE_UNKNOWN &&
        !pae_auth->interface_ptr->ws_info.enable_ffn10) {
        TRACE(TR_DROP, "drop %-9s: FAN 1.0 authentication disabled", "eap");
        return KMP_TYPE_NONE;
    }
    if (sec_keys->node_role == WS_NR_ROLE_LFN &&
        !pae_auth->interface_ptr->ws_info.enable_lfn) {
        TRACE(TR_DROP, "drop %-9s: LFN authentication disabled", "eap");
        return KMP_TYPE_NONE;
    }
    // Supplicant has indicated that PMK is not valid
    if (sec_keys->pmk_mismatch) {
        sec_keys->ptk_mismatch = true;
        // start EAP-TLS towards supplicant
        if (pae_auth->sec_cfg->radius_cfg != NULL && pae_auth->sec_cfg->radius_cfg->radius_addr_set) {
            next_type = RADIUS_IEEE_802_1X_MKA;
        } else {
            next_type = IEEE_802_1X_MKA;
        }
        tr_info("PAE: start EAP-TLS, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
        return next_type;
    }
    if (sec_keys->ptk_mismatch) {
        // start 4WH towards supplicant
        next_type = IEEE_802_11_4WH;
        tr_info("PAE: start 4WH, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
    }

    int8_t gtk_index = -1;
    // FIXME: When an LFN connects to a border router that does not support it,
    // the behavior is always as if the border router was FAN 1.0. However it
    // may be better to differentiate 2 cases:
    // - 1.0: the border router does not know about the node role KDE, it sends
    //   GTKs as if the supplicant were a FAN 1.0 FFN
    // - 1.1-compat: the border router is aware that it does not support LFNs,
    //   so it should drop the key request frame and log using TR_DROP
    if (sec_keys->node_role == WS_NR_ROLE_LFN &&
        pae_auth->interface_ptr->ws_info.enable_lfn) {
        gtk_index = sec_prot_keys_gtk_insert_index_from_gtkl_get(&sec_keys->lgtks);

        // For 4WH insert always a key, in case no other then active
        if (next_type == IEEE_802_11_4WH && gtk_index < 0) {
            gtk_index = sec_prot_keys_gtk_status_active_get(sec_keys->lgtks.keys);
        }
        if (next_type == KMP_TYPE_NONE && gtk_index >= 0) {
            /* Check if the PTK has been already used to install GTK to specific index and if it
             * has been, trigger 4WH to update also the PTK. This prevents writing multiple
             * GTK keys to same index using same PTK.
             */
            if (pae_auth->sec_cfg->timing_lfn.expire_offset > SHORT_LGTK_LIFETIME &&
                sec_prot_keys_ptk_installed_gtk_hash_mismatch_check(&sec_keys->lgtks, gtk_index)) {
                // start 4WH towards supplicant
                next_type = IEEE_802_11_4WH;
                sec_keys->ptk_mismatch = true;
                tr_info("PAE: start 4WH due to LGTK index re-use, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
            } else {
                // Update just LGTK
                next_type = IEEE_802_11_GKH;
                tr_info("PAE: start GKH for LGTK index %i, eui-64: %s", gtk_index, tr_eui64(supp_entry->addr.eui_64));
            }
        }
    } else {
        gtk_index = sec_prot_keys_gtk_insert_index_from_gtkl_get(&sec_keys->gtks);

        // For 4WH insert always a key, in case no other then active
        if (next_type == IEEE_802_11_4WH && gtk_index < 0) {
            gtk_index = sec_prot_keys_gtk_status_active_get(sec_keys->gtks.keys);
        }
        if (next_type == KMP_TYPE_NONE && gtk_index >= 0) {
            /* Check if the PTK has been already used to install GTK to specific index and if it
             * has been, trigger 4WH to update also the PTK. This prevents writing multiple
             * GTK keys to same index using same PTK.
             */
            if (pae_auth->sec_cfg->timing_ffn.expire_offset > SHORT_GTK_LIFETIME &&
                    sec_prot_keys_ptk_installed_gtk_hash_mismatch_check(&sec_keys->gtks, gtk_index)) {
                // start 4WH towards supplicant
                next_type = IEEE_802_11_4WH;
                sec_keys->ptk_mismatch = true;
                tr_info("PAE: start 4WH due to GTK index re-use, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
            } else {
                // Update just GTK
                next_type = IEEE_802_11_GKH;
                tr_info("PAE: start GKH for GTK index %i, eui-64: %s", gtk_index, tr_eui64(supp_entry->addr.eui_64));
            }
        }
        if (next_type == KMP_TYPE_NONE && sec_keys->node_role == WS_NR_ROLE_ROUTER &&
            pae_auth->interface_ptr->ws_info.enable_lfn) {
            gtk_index = sec_prot_keys_gtk_insert_index_from_gtkl_get(&sec_keys->lgtks);
            if (gtk_index >= 0) {
                // Update just LGTK (do not when target is a FAN1.0 router)
                next_type = IEEE_802_11_GKH;
                tr_info("PAE: start GKH for LGTK index %i, eui-64: %s", gtk_index, tr_eui64(supp_entry->addr.eui_64));
            }
        }
    }
    if (gtk_index >= 0)
        tr_info("PAE: update (L)GTK index: %i, eui-64: %s", gtk_index, tr_eui64(supp_entry->addr.eui_64));

    if (next_type == KMP_TYPE_NONE) {
        tr_info("PAE: authenticated, eui-64: %s", tr_eui64(supp_entry->addr.eui_64));
    }

    return next_type;
}

static kmp_api_t *ws_pae_auth_kmp_create_and_start(kmp_service_t *service, kmp_type_e type, uint8_t socked_msg_if_instance_id, supp_entry_t *supp_entry, sec_cfg_t *sec_cfg)
{
    // Create KMP instance for new authentication
    kmp_api_t *kmp = kmp_api_create(service, type, socked_msg_if_instance_id, sec_cfg);

    if (!kmp) {
        return NULL;
    }

    kmp_api_data_set(kmp, supp_entry);
    // Sets address to KMP
    kmp_api_addr_set(kmp, &supp_entry->addr);

    // Sets security keys to KMP
    kmp_api_sec_keys_set(kmp, &supp_entry->sec_keys);

    if (ws_pae_lib_kmp_list_add(&supp_entry->kmp_list, kmp) == NULL) {
        kmp_api_delete(kmp);
        return NULL;
    }

    kmp_api_cb_register(kmp,
                        ws_pae_auth_kmp_api_create_confirm,
                        ws_pae_auth_kmp_api_create_indication,
                        ws_pae_auth_kmp_api_finished_indication,
                        ws_pae_auth_kmp_api_finished);

    kmp_api_data_set(kmp, supp_entry);

    if (kmp_api_start(kmp) < 0) {
        ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, kmp);
        return NULL;
    }

    return kmp;
}

static void ws_pae_auth_kmp_api_finished(kmp_api_t *kmp)
{
    supp_entry_t *supp_entry = kmp_api_data_get(kmp);
    if (!supp_entry) {
        // Should not be possible
        return;
    }

    // Delete KMP
    ws_pae_lib_kmp_list_delete(&supp_entry->kmp_list, kmp);
}

static void ws_pae_auth_active_supp_deleted(void *pae_auth_ptr)
{
    pae_auth_t *pae_auth = pae_auth_ptr;

    tr_info("Supplicant deleted");

    if (ws_pae_auth_active_limit_reached(pae_auth)) {
        WARN("%s: congestion detected, leaving supplicant waiting list as is", __func__);
        return;
    }

    supp_entry_t *retry_supp = ns_list_get_first(&pae_auth->waiting_supp_list);
    if (retry_supp != NULL) {
        ns_list_remove(&pae_auth->waiting_supp_list, retry_supp);
        pae_auth->waiting_supp_list_size--;
        ns_list_add_to_start(&pae_auth->active_supp_list, retry_supp);
        tr_info("PAE: waiting supplicant to active, eui-64: %s", tr_eui64(retry_supp->addr.eui_64));
        retry_supp->waiting_ticks = 0;
        ws_pae_auth_next_kmp_trigger(pae_auth, retry_supp);
    }
}

static void ws_pae_auth_waiting_supp_deleted(void *pae_auth_ptr)
{
    pae_auth_t *pae_auth = pae_auth_ptr;
    pae_auth->waiting_supp_list_size--;
}

int ws_pae_auth_supp_list(int8_t interface_id, uint8_t eui64[][8], int len)
{
    struct net_if *interface_ptr;
    supp_list_t *supp_lists[2];
    pae_auth_t *pae_auth;
    int len_ret, j;

    interface_ptr = protocol_stack_interface_info_get_by_id(interface_id);
    if (!interface_ptr)
        return 0;

    pae_auth = ws_pae_auth_get(interface_ptr);
    if (!pae_auth)
        return 0;
    supp_lists[0] = &pae_auth->active_supp_list;
    supp_lists[1] = &pae_auth->waiting_supp_list;

    len_ret = ws_pae_key_storage_list(eui64, len);
    if (len_ret == len)
        return len_ret;

    for (int i = 0; i < ARRAY_SIZE(supp_lists); i++) {
        ns_list_foreach(supp_entry_t, cur, supp_lists[i]) {
            for (j = 0; j < len_ret; j++)
                if (!memcmp(cur->addr.eui_64, eui64[j], 8))
                    break;
            if (j != len_ret)
                continue;
            memcpy(eui64[len_ret++], cur->addr.eui_64, 8);
            if (len_ret == len)
                return len_ret;
        }
    }
    return len_ret;
}

void ws_pae_auth_gtk_install(int8_t interface_id, const uint8_t key[GTK_LEN], bool is_lgtk)
{
    struct net_if *interface_ptr;
    sec_prot_gtk_keys_t *keys;
    pae_auth_t *pae_auth;
    int lifetime;
    interface_ptr = protocol_stack_interface_info_get_by_id(interface_id);
    BUG_ON(!interface_ptr);
    pae_auth = ws_pae_auth_get(interface_ptr);
    BUG_ON(!pae_auth);
    if (is_lgtk) {
        keys     = pae_auth->sec_keys_nw_info->lgtks;
        lifetime = pae_auth->sec_cfg->timing_lfn.expire_offset;
    } else {
        keys     = pae_auth->sec_keys_nw_info->gtks;
        lifetime = pae_auth->sec_cfg->timing_ffn.expire_offset;
    }
    ws_pae_auth_gtk_insert(keys, key, lifetime, is_lgtk);
    ws_pae_auth_network_keys_from_gtks_set(pae_auth, is_lgtk);
}
