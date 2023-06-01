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
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <fnmatch.h>
#include <arpa/inet.h>
#include <mbedtls/sha256.h>
#if MBEDTLS_VERSION_MAJOR > 2
#include <mbedtls/compat-2.x.h>
#endif
#include "common/log.h"
#include "common/named_values.h"
#include "common/key_value_storage.h"
#include "common/parsers.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "stack/mac/fhss_config.h"
#include "stack/ns_address.h"
#include "stack/ws_management_api.h"
#include "stack/ws_bbr_api.h"
#include "stack/timers.h"

#include "nwk_interface/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_mngt.h"
#include "6lowpan/ws/ws_pae_timers.h"
#include "6lowpan/ws/ws_pae_supp.h"
#include "6lowpan/ws/ws_pae_auth.h"
#include "6lowpan/ws/ws_pae_time.h"
#include "6lowpan/ws/ws_pae_key_storage.h"

#include "6lowpan/ws/ws_pae_controller.h"

#define TRACE_GROUP "wspc"

typedef int8_t ws_pae_delete(struct net_if *interface_ptr);
typedef void ws_pae_timer(uint16_t ticks);
typedef int8_t ws_pae_br_addr_write(struct net_if *interface_ptr, const uint8_t *eui_64);
typedef int8_t ws_pae_br_addr_read(struct net_if *interface_ptr, uint8_t *eui_64);
typedef void ws_pae_gtks_updated(struct net_if *interface_ptr, bool is_lgtk);
typedef int8_t ws_pae_gtk_hash_update(struct net_if *interface_ptr, gtkhash_t *gtkhash, bool del_gtk_on_mismatch);
typedef int8_t ws_pae_nw_key_index_update(struct net_if *interface_ptr, uint8_t index, bool is_lgtk);
typedef int8_t ws_pae_nw_info_set(struct net_if *interface_ptr, uint16_t pan_id, char *network_name, bool updated);

typedef struct nw_key {
    uint8_t gtk[GTK_LEN];                                            /**< GTK key */
    bool set : 1;                                                    /**< Key has been set */
    bool installed : 1;                                              /**< Key has been installed on MAC */
} nw_key_t;

typedef struct pae_controller_gtk {
    sec_prot_gtk_keys_t gtks;                                        /**< GTKs */
    sec_prot_gtk_keys_t next_gtks;                                   /**< Next GTKs */
    int8_t gtk_index;                                                /**< GTK index */
    gtkhash_t gtkhash[4];                                            /**< GTK hashes */
    nw_key_t nw_key[GTK_NUM];                                        /**< Currently active network keys (on MAC) */
    frame_counters_t frame_counters;                                 /**< Frame counters */
    bool gtks_set : 1;                                               /**< GTKs are set */
    bool gtkhash_set : 1;                                            /**< GTK hashes are set */
    bool key_index_set : 1;                                          /**< NW key index is set */
} pae_controller_gtk_t;

typedef struct pae_controller {
    ns_list_link_t link;                                             /**< Link */
    uint8_t target_eui_64[8];                                        /**< EAPOL target */
    uint16_t target_pan_id;                                          /**< EAPOL target PAN ID */
    uint8_t br_eui_64[8];                                            /**< Border router EUI-64 */
    pae_controller_gtk_t gtks;                                       /**< Material for GTKs */
    pae_controller_gtk_t lgtks;                                       /**< Material for GTKs */
    sec_prot_keys_nw_info_t sec_keys_nw_info;                        /**< Security keys network information */
    sec_prot_certs_t certs;                                          /**< Certificates */
    uint16_t frame_cnt_store_timer;                                  /**< Timer to check if storing of frame counter value is needed */
    uint32_t frame_cnt_store_force_timer;                            /**< Timer to force storing of frame counter, if no other updates */
    sec_cfg_t sec_cfg;                                               /**< Security configuration (configuration set values) */
    struct net_if *interface_ptr;                  /**< List link entry */
    ws_pae_controller_auth_completed *auth_completed;                /**< Authentication completed callback, continue bootstrap */
    ws_pae_controller_nw_key_set *nw_key_set;                        /**< Key set callback */
    ws_pae_controller_nw_key_clear *nw_key_clear;                    /**< Key clear callback */
    ws_pae_controller_nw_send_key_index_set *nw_send_key_index_set;  /**< Send key index set callback */
    ws_pae_controller_nw_frame_counter_set *nw_frame_counter_set;    /**< Frame counter set callback */
    ws_pae_controller_nw_frame_counter_read *nw_frame_counter_read;  /**< Frame counter read callback */
    ws_pae_controller_pan_ver_increment *pan_ver_increment;          /**< PAN version increment callback */
    ws_pae_controller_pan_ver_increment *lpan_ver_increment;         /**< LFN-PAN version increment callback */
    ws_pae_controller_nw_info_updated *nw_info_updated;              /**< Network information updated callback */
    ws_pae_controller_auth_next_target *auth_next_target;            /**< Authentication next target callback */
    ws_pae_controller_congestion_get *congestion_get;                /**< Congestion get callback */
    ws_pae_controller_ip_addr_get *ip_addr_get;                      /**< IP address get callback */
    ws_pae_delete *pae_delete;                                       /**< PAE delete callback */
    ws_pae_timer *pae_fast_timer;                                    /**< PAE fast timer callback */
    ws_pae_timer *pae_slow_timer;                                    /**< PAE slow timer callback */
    ws_pae_br_addr_write *pae_br_addr_write;                         /**< PAE Border router EUI-64 write callback */
    ws_pae_br_addr_read *pae_br_addr_read;                           /**< PAE Border router EUI-64 read callback */
    ws_pae_gtks_updated *pae_gtks_updated;                           /**< PAE GTKs updated */
    ws_pae_gtk_hash_update *pae_gtk_hash_update;                     /**< PAE GTK HASH update */
    ws_pae_nw_key_index_update *pae_nw_key_index_update;             /**< PAE NW key index update */
    ws_pae_nw_info_set *pae_nw_info_set;                             /**< PAE security key network info set */
    bool frame_counter_read : 1;                                     /**< Frame counters has been read */
    bool auth_started : 1;                                           /**< Authenticator has been started */
} pae_controller_t;

typedef struct pae_controller_config {
    sec_radius_cfg_t *radius_cfg;                                    /**< Radius configuration settings */
    uint16_t node_limit;                                             /**< Max number of stored supplicants */
    bool node_limit_set : 1;                                         /**< Node limit set */
    bool ext_cert_valid_enabled : 1;                                 /**< Extended certificate validation enabled */
} pae_controller_config_t;

static void ws_pae_controller_keys_nw_info_init(sec_prot_keys_nw_info_t *sec_keys_nw_info, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks);
static void ws_pae_controller_nw_info_updated_check(struct net_if *interface_ptr);
#ifdef HAVE_PAE_AUTH
static void ws_pae_controller_auth_ip_addr_get(struct net_if *interface_ptr, uint8_t *address);
static bool ws_pae_controller_auth_congestion_get(struct net_if *interface_ptr, uint16_t active_supp);
static int8_t  ws_pae_controller_auth_nw_frame_counter_read(struct net_if *interface_ptr, uint32_t *counter, uint8_t gtk_index);
#endif
static pae_controller_t *ws_pae_controller_get(struct net_if *interface_ptr);
static void ws_pae_controller_frame_counter_timer(uint16_t seconds, pae_controller_t *entry);
static void ws_pae_controller_frame_counter_store(pae_controller_t *entry, bool use_threshold, bool is_lgtk);
static int8_t ws_pae_controller_nvm_frame_counter_read(uint64_t *stored_time,
                                                       uint16_t *pan_version, uint16_t *lpan_version,
                                                       frame_counters_t *gtk_counters,
                                                       frame_counters_t *lgtk_counters);
static pae_controller_t *ws_pae_controller_get_or_create(int8_t interface_id);
static int8_t ws_pae_controller_nw_key_check_and_insert(struct net_if *interface_ptr, sec_prot_gtk_keys_t *gtks, bool force_install, bool is_lgtk);
static void ws_pae_controller_frame_counter_store_and_nw_keys_remove(struct net_if *interface_ptr, pae_controller_t *controller, bool use_threshold, bool is_lgtk);
#ifdef HAVE_PAE_AUTH
static void ws_pae_controller_gtk_hash_set(struct net_if *interface_ptr, gtkhash_t *gtkhash, bool is_lgtk);
static void ws_pae_controller_nw_key_index_check_and_set(struct net_if *interface_ptr, uint8_t index, bool is_lgtk);
#endif
static void ws_pae_controller_data_init(pae_controller_t *controller);
static int8_t ws_pae_controller_frame_counter_read(pae_controller_t *controller);
static void ws_pae_controller_frame_counter_reset(frame_counters_t *frame_counters);
static void ws_pae_controller_frame_counter_index_reset(frame_counters_t *frame_counters, uint8_t index);
static int8_t ws_pae_controller_nw_info_read(pae_controller_t *controller,
                                             sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks);
static int8_t ws_pae_controller_nvm_nw_info_write(struct net_if *interface_ptr,
                                                  uint16_t pan_id, char *network_name, uint8_t *gtk_eui64,
                                                  sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks);
static int8_t ws_pae_controller_nvm_nw_info_read(struct net_if *interface_ptr,
                                                 uint16_t *pan_id, char *network_name, uint8_t *gtk_eui64,
                                                 sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks,
                                                 uint64_t current_time);


static NS_LIST_DEFINE(pae_controller_list, pae_controller_t, link);

pae_controller_config_t pae_controller_config = {
    .radius_cfg = NULL,
    .node_limit = 0,
    .node_limit_set = false,
    .ext_cert_valid_enabled = false
};

#ifdef HAVE_PAE_SUPP
int8_t ws_pae_controller_authenticate(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }
    // In case LGTKs are set uses those
    if (controller->lgtks.gtks_set) {
        if (sec_prot_keys_gtks_are_updated(&controller->lgtks.gtks)) {
            ws_pae_controller_nw_key_check_and_insert(controller->interface_ptr, &controller->lgtks.gtks, false, true);
            sec_prot_keys_gtks_updated_reset(&controller->lgtks.gtks);
            ws_pae_supp_gtks_set(controller->interface_ptr, &controller->lgtks.gtks, true);
        }
    }

    // In case test keys are set uses those and does not initiate authentication
    if (controller->gtks.gtks_set) {
        if (sec_prot_keys_gtks_are_updated(&controller->gtks.gtks)) {
            ws_pae_controller_nw_key_check_and_insert(controller->interface_ptr, &controller->gtks.gtks, false, false);
            sec_prot_keys_gtks_updated_reset(&controller->gtks.gtks);
            ws_pae_supp_gtks_set(controller->interface_ptr, &controller->gtks.gtks, false);
        }
        controller->auth_completed(interface_ptr, AUTH_RESULT_OK, NULL);
        return 0;
    }

    if (ws_pae_supp_authenticate(controller->interface_ptr, controller->target_pan_id, controller->target_eui_64, controller->sec_keys_nw_info.network_name) < 0) {
        controller->auth_completed(interface_ptr, AUTH_RESULT_ERR_UNSPEC, controller->target_eui_64);
    }

    return 0;
}

int8_t ws_pae_controller_bootstrap_done(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    // RPL parent is known, remove EAPOL target that what was set using the authenticate call */
    ws_pae_supp_eapol_target_remove(interface_ptr);

    /* Trigger GTK hash update to supplicant, so it can check whether keys have been updated
       during bootstrap. Does nothing if GTKs are up to date. */
    ws_pae_supp_gtk_hash_update(interface_ptr, controller->gtks.gtkhash, false);

    return 0;
}
#endif

#ifdef HAVE_PAE_AUTH
int8_t ws_pae_controller_authenticator_start(struct net_if *interface_ptr, uint16_t local_port, const uint8_t *remote_addr, uint16_t remote_port)
{
    (void) local_port;
    (void) remote_port;

    if (!interface_ptr || !remote_addr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (ws_pae_auth_addresses_set(interface_ptr, local_port, remote_addr, remote_port) < 0) {
        return -1;
    }

    // If either radius address or password is set, both must be set
    if (controller->sec_cfg.radius_cfg != NULL) {
        if (controller->sec_cfg.radius_cfg->radius_addr_set || controller->sec_cfg.radius_cfg->radius_shared_secret_len > 0) {
            if (!controller->sec_cfg.radius_cfg->radius_addr_set) {
                return -1;
            }
            if (controller->sec_cfg.radius_cfg->radius_shared_secret_len == 0) {
                return -1;
            }
            if (ws_pae_auth_radius_address_set(interface_ptr, &controller->sec_cfg.radius_cfg->radius_addr) < 0) {
                return -1;
            }
        }
    }

    if (pae_controller_config.node_limit_set) {
        ws_pae_auth_node_limit_set(controller->interface_ptr, pae_controller_config.node_limit);
    }

    ws_pae_auth_cb_register(interface_ptr,
                            ws_pae_controller_gtk_hash_set,
                            ws_pae_controller_nw_key_check_and_insert,
                            ws_pae_controller_nw_key_index_check_and_set,
                            ws_pae_controller_nw_info_updated_check,
                            ws_pae_controller_auth_ip_addr_get,
                            ws_pae_controller_auth_congestion_get,
                            ws_pae_controller_auth_nw_frame_counter_read);

    controller->auth_started = true;

    ws_pae_auth_start(interface_ptr);

    return 0;
}
#endif

int8_t ws_pae_controller_cb_register(struct net_if *interface_ptr,
                                     ws_pae_controller_auth_completed *completed,
                                     ws_pae_controller_auth_next_target *auth_next_target,
                                     ws_pae_controller_nw_key_set *nw_key_set,
                                     ws_pae_controller_nw_key_clear *nw_key_clear,
                                     ws_pae_controller_nw_send_key_index_set *nw_send_key_index_set,
                                     ws_pae_controller_nw_frame_counter_set *nw_frame_counter_set,
                                     ws_pae_controller_nw_frame_counter_read *nw_frame_counter_read,
                                     ws_pae_controller_pan_ver_increment *pan_ver_increment,
                                     ws_pae_controller_pan_ver_increment *lpan_ver_increment,
                                     ws_pae_controller_nw_info_updated *nw_info_updated,
                                     ws_pae_controller_congestion_get *congestion_get)
{
    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    controller->auth_completed = completed;
    controller->nw_key_set = nw_key_set;
    controller->nw_key_clear = nw_key_clear;
    controller->nw_send_key_index_set = nw_send_key_index_set;
    controller->nw_frame_counter_set = nw_frame_counter_set;
    controller->nw_frame_counter_read = nw_frame_counter_read;
    controller->pan_ver_increment = pan_ver_increment;
    controller->lpan_ver_increment = lpan_ver_increment;
    controller->nw_info_updated = nw_info_updated;
    controller->auth_next_target = auth_next_target;
    controller->congestion_get = congestion_get;
    return 0;
}

int8_t ws_pae_controller_auth_cb_register(struct net_if *interface_ptr, ws_pae_controller_ip_addr_get *ip_addr_get)
{
    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    controller->ip_addr_get = ip_addr_get;
    return 0;
}

int8_t ws_pae_controller_set_target(struct net_if *interface_ptr, uint16_t target_pan_id, uint8_t *target_eui_64)
{
    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    controller->target_pan_id = target_pan_id;
    memcpy(controller->target_eui_64, target_eui_64, 8);

    return 0;
}

static void ws_pae_controller_keys_nw_info_init(sec_prot_keys_nw_info_t *sec_keys_nw_info, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks)
{
    if (!sec_keys_nw_info) {
        return;
    }

    memset(sec_keys_nw_info, 0, sizeof(sec_prot_keys_nw_info_t));

    sec_keys_nw_info->gtks = gtks;
    sec_keys_nw_info->lgtks = lgtks;
    sec_keys_nw_info->new_pan_id = 0xFFFF;
    sec_keys_nw_info->key_pan_id = 0xFFFF;
    sec_keys_nw_info->updated = false;
}

int8_t ws_pae_controller_nw_info_set(struct net_if *interface_ptr, uint16_t pan_id, uint16_t pan_version, uint16_t lpan_version, char *network_name)
{
    (void) pan_id;
    (void) network_name;

    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    bool updated = false;

    // Network name has been modified
    if (network_name && strcmp(controller->sec_keys_nw_info.network_name, network_name) != 0) {
        strncpy(controller->sec_keys_nw_info.network_name, network_name, 32);
        controller->sec_keys_nw_info.updated = true;
        updated = true;
    }

    // PAN ID has been modified
    if (pan_id != 0xffff && pan_id != controller->sec_keys_nw_info.new_pan_id) {
        controller->sec_keys_nw_info.new_pan_id = pan_id;
        controller->sec_keys_nw_info.updated = true;
        updated = true;
    }

    // Store pan version
    controller->sec_keys_nw_info.pan_version = pan_version;
    controller->sec_keys_nw_info.lpan_version = lpan_version;

    if (controller->pae_nw_info_set) {
        controller->pae_nw_info_set(interface_ptr, pan_id, network_name, updated);
    }

    return 0;
}

static void ws_pae_controller_nw_info_updated_check(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return;
    }

    if (controller->sec_keys_nw_info.updated || sec_prot_keys_gtks_are_updated(controller->sec_keys_nw_info.gtks)) {
        // Get own EUI-64
        uint8_t gtk_eui64[8] = {0};
        link_layer_address_s mac_params;
        if (arm_nwk_mac_address_read(interface_ptr->id, &mac_params) >= 0) {
            memcpy(gtk_eui64, mac_params.mac_long, 8);
        }
        ws_pae_controller_nvm_nw_info_write(interface_ptr,
                                            controller->sec_keys_nw_info.key_pan_id,
                                            controller->sec_keys_nw_info.network_name,
                                            gtk_eui64,
                                            controller->sec_keys_nw_info.gtks,
                                            controller->sec_keys_nw_info.lgtks);
        controller->sec_keys_nw_info.updated = false;
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.gtks);
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.lgtks);
    }
}

#ifdef HAVE_PAE_AUTH
static void ws_pae_controller_auth_ip_addr_get(struct net_if *interface_ptr, uint8_t *address)
{
    if (!interface_ptr) {
        return;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return;
    }

    controller->ip_addr_get(interface_ptr, address);
}

static bool ws_pae_controller_auth_congestion_get(struct net_if *interface_ptr, uint16_t active_supp)
{
    if (!interface_ptr) {
        return 0;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return 0;
    }

    return controller->congestion_get(interface_ptr, active_supp);
}

static int8_t ws_pae_controller_auth_nw_frame_counter_read(struct net_if *interface_ptr, uint32_t *counter, uint8_t gtk_index)
{
    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    controller->nw_frame_counter_read(interface_ptr, counter, gtk_index);
    return 0;
}
#endif

int8_t ws_pae_controller_nw_key_valid(struct net_if *interface_ptr, uint8_t *br_iid)
{
#ifdef HAVE_PAE_SUPP
    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    return ws_pae_supp_nw_key_valid(interface_ptr, br_iid);
#else
    return -1;
#endif
}

static int8_t ws_pae_controller_nw_key_check_and_insert(struct net_if *interface_ptr, sec_prot_gtk_keys_t *gtks, bool force_install, bool is_lgtk)
{
    // Adds, removes and updates network keys to MAC based on new GTKs
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    nw_key_t *nw_key;
    frame_counters_t *frame_counters;
    int8_t ret = -1;
    int key_offset;

    if (!controller) {
        return -1;
    }

    if (is_lgtk) {
            nw_key = controller->lgtks.nw_key;
            frame_counters = &controller->lgtks.frame_counters;
            key_offset = GTK_NUM;
    } else {
            nw_key = controller->gtks.nw_key;
            frame_counters = &controller->gtks.frame_counters;
            key_offset = 0;
    }
    for (uint8_t i = 0; i < (is_lgtk ? LGTK_NUM : GTK_NUM); i++) {
        // Gets GTK for the index (new, modified or none)
        uint8_t *gtk = sec_prot_keys_gtk_get(gtks, i);

        // If network key is set and GTK key is not set or not the same, removes network key
        if (nw_key[i].set && (!gtk || memcmp(nw_key[i].gtk, gtk, GTK_LEN) != 0)) {
            // Removes key from MAC if installed
            if (nw_key[i].installed)
                controller->nw_key_clear(interface_ptr, i + key_offset);
            nw_key[i].installed = false;
            nw_key[i].set = false;
            tr_info("NW key remove: %i", i + key_offset);
        }

        if (force_install) {
            // Install always
            nw_key[i].installed = false;
            // Frame counters are fresh
            ws_pae_controller_frame_counter_index_reset(frame_counters, i);
        }

        // If GTK key is not set, continues to next GTK
        if (!gtk) {
            continue;
        }

        // Network key is set and installed, all done
        if (nw_key[i].set && nw_key[i].installed) {
            continue;
        }

        // If network key is not set, stores the new GTK key to network key
        if (!nw_key[i].set) {
            nw_key[i].set = true;
            nw_key[i].installed = false;
            memcpy(nw_key[i].gtk, gtk, GTK_LEN);
        }

        // If network key has not been installed, installs it and updates frame counter as needed
        if (!nw_key[i].installed) {
            gtkhash_t gtkhash;
            sec_prot_keys_gtk_hash_generate(gtk, gtkhash);
            tr_info("NW key set: %i, hash: %s", i + key_offset, trace_array(gtkhash, 8));
            uint8_t gak[GTK_LEN];
            if (ws_pae_controller_gak_from_gtk(gak, gtk, controller->sec_keys_nw_info.network_name) >= 0) {
                // Install the new network key derived from GTK and network name (GAK) to MAC
                controller->nw_key_set(interface_ptr, i + key_offset, i + key_offset, gak);
                nw_key[i].installed = true;
                ret = 0;
#ifdef EXTRA_DEBUG_INFO
                tr_info("NW name: %s", controller->sec_keys_nw_info.network_name);
                size_t nw_name_len = strlen(controller->sec_keys_nw_info.network_name);
                tr_info("NW name: %s", trace_array((uint8_t *)controller->sec_keys_nw_info.network_name, nw_name_len));
                tr_info("%s: %s", is_lgtk ? "LGTK" : "GTK", trace_array(gtk, 16));
                tr_info("%s: %s", is_lgtk ? "LGAK" : "GAK", trace_array(gak, 16));
#endif
            } else {
                tr_error("GAK generation failed network name: %s", controller->sec_keys_nw_info.network_name);
                continue;
            }

            // If frame counter value has been stored for the network key, updates the frame counter if needed
            if (frame_counters->counter[i].set &&
                    memcmp(gtk, frame_counters->counter[i].gtk, GTK_LEN) == 0) {
                // Read current counter from MAC
                uint32_t curr_frame_counter;
                controller->nw_frame_counter_read(controller->interface_ptr, &curr_frame_counter, i + key_offset);

                // If stored frame counter is greater than MAC counter
                if (frame_counters->counter[i].frame_counter > curr_frame_counter) {
                    tr_debug("Frame counter set: %i, stored %"PRIu32" current: %"PRIu32"", i + key_offset,
                             frame_counters->counter[i].frame_counter, curr_frame_counter);
                    curr_frame_counter = frame_counters->counter[i].frame_counter;
                    // Updates MAC frame counter
                    controller->nw_frame_counter_set(controller->interface_ptr, curr_frame_counter, i + key_offset);
                }
            }
        }
    }

    return ret;
}

int8_t ws_pae_controller_gak_from_gtk(uint8_t *gak, uint8_t *gtk, char *network_name)
{
    uint8_t network_name_len = strlen(network_name);
    if (network_name_len == 0) {
        return -1;
    }

    uint8_t input[network_name_len + GTK_LEN];
    memcpy(input, network_name, network_name_len);
    memcpy(input + network_name_len, gtk, GTK_LEN);

    int8_t ret_val = 0;

    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    if (mbedtls_sha256_starts_ret(&ctx, 0) != 0) {
        ret_val = -1;
        goto error;
    }

    if (mbedtls_sha256_update_ret(&ctx, input, network_name_len + GTK_LEN) != 0) {
        ret_val = -1;
        goto error;
    }

    uint8_t output[32];

    if (mbedtls_sha256_finish_ret(&ctx, output) != 0) {
        ret_val = -1;
        goto error;
    }

    memcpy(gak, &output[0], 16);

error:
    mbedtls_sha256_free(&ctx);

    return ret_val;
}

int8_t ws_pae_controller_nw_key_index_update(struct net_if *interface_ptr, uint8_t index)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (controller->pae_nw_key_index_update) {
        if (index > GTK_NUM)
            controller->pae_nw_key_index_update(interface_ptr, index - GTK_NUM, true);
        else
            controller->pae_nw_key_index_update(interface_ptr, index, false);
    }

    return 0;
}

void ws_pae_controller_nw_keys_remove(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return;
    }

    /* Stores frame counters if incremented by threshold and removes network keys from PAE
       controller and MAC */
    ws_pae_controller_frame_counter_store_and_nw_keys_remove(interface_ptr, controller, true, false);
    ws_pae_controller_frame_counter_store_and_nw_keys_remove(interface_ptr, controller, true, true);
}

static void ws_pae_controller_frame_counter_store_and_nw_keys_remove(struct net_if *interface_ptr, pae_controller_t *controller, bool use_threshold, bool is_lgtk)
{
    pae_controller_gtk_t *gtks;
    int key_offset;

    if (is_lgtk) {
        key_offset = GTK_NUM;
        gtks = &controller->lgtks;
    } else {
        key_offset = 0;
        gtks = &controller->gtks;
    }

    /* Checks if frame counters needs to be stored when keys are removed */
    ws_pae_controller_frame_counter_store(controller, use_threshold, is_lgtk);

    tr_info("NW keys remove");

    gtks->gtk_index = -1;

    nw_key_t *nw_key = gtks->nw_key;
    for (uint8_t i = 0; i < (is_lgtk ? LGTK_NUM : GTK_NUM); i++) {
        // Deletes the key if it is set
        if (nw_key[i].set) {
            tr_info("NW key remove: %i", i + key_offset);
            if (nw_key[i].installed)
                controller->nw_key_clear(interface_ptr, i + key_offset);
            nw_key[i].set = false;
            nw_key[i].installed = false;
        }
    }
}

#ifdef HAVE_PAE_AUTH
static void ws_pae_controller_nw_key_index_check_and_set(struct net_if *interface_ptr, uint8_t index, bool is_lgtk)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    pae_controller_gtk_t *gtks;
    int key_offset;
    if (!controller) {
        return;
    }
    if (is_lgtk) {
        gtks = &controller->lgtks;
        key_offset = GTK_NUM;
    } else {
        gtks = &controller->gtks;
        key_offset = 0;
    }

    if (controller->nw_send_key_index_set) {
        gtks->gtk_index = index;
        /* Checks if frame counters needs to be stored for the new GTK that is taken into
           use; this is the last check that stored counters are in sync before activating key */
        ws_pae_controller_frame_counter_store(controller, true, is_lgtk);
        tr_info("NW send key index set: %i", index + key_offset);
        controller->nw_send_key_index_set(interface_ptr, index + key_offset);
    }

    // Do not update PAN version for initial key index set
    if (gtks->key_index_set) {
        if (!is_lgtk && controller->pan_ver_increment)
            controller->pan_ver_increment(interface_ptr);
        if (is_lgtk && controller->lpan_ver_increment)
            controller->lpan_ver_increment(interface_ptr);
    } else {
        gtks->key_index_set = true;
    }
}
#endif

#ifdef HAVE_PAE_SUPP
static void ws_pae_controller_active_nw_key_set(struct net_if *cur, uint8_t index, bool is_lgtk)
{
    pae_controller_t *controller = ws_pae_controller_get(cur);
    int key_offset;
    if (!controller) {
        return;
    }

    if (controller->nw_send_key_index_set) {
        if (is_lgtk) {
            controller->lgtks.gtk_index = index;
            key_offset = GTK_NUM;
        } else {
            controller->gtks.gtk_index = index;
            key_offset = 0;
        }
        /* Checks if frame counters needs to be stored for the new GTK that is taken into
           use; this is the last check that stored counters are in sync before activating key */
        ws_pae_controller_frame_counter_store(controller, true, is_lgtk);
        // Activates key on MAC
        controller->nw_send_key_index_set(controller->interface_ptr, index + key_offset);
        tr_info("NW send key index set: %i", index + key_offset);
    }
}
#endif

int8_t ws_pae_controller_init(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return -1;
    }

    if (ws_pae_controller_get(interface_ptr) != NULL) {
        return 0;
    }

    pae_controller_t *controller = malloc(sizeof(pae_controller_t));

    if (!controller) {
        free(controller);
        return -1;
    }

    controller->interface_ptr = interface_ptr;
    controller->auth_completed = NULL;
    controller->nw_key_set = NULL;
    controller->nw_key_clear = NULL;
    controller->nw_send_key_index_set = NULL;
    controller->nw_frame_counter_set = NULL;
    controller->pan_ver_increment = NULL;
    controller->nw_info_updated = NULL;
    controller->auth_next_target = NULL;
    controller->congestion_get = NULL;

    memset(&controller->sec_cfg, 0, sizeof(sec_cfg_t));

    ws_pae_controller_data_init(controller);

    ns_list_add_to_end(&pae_controller_list, controller);

    return 0;
}

int8_t ws_pae_controller_configure(struct net_if *interface_ptr, struct ws_sec_timer_cfg *sec_timer_cfg, struct ws_sec_prot_cfg *sec_prot_cfg, struct ws_timing_cfg *timing_cfg)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (controller == NULL) {
        return 0;
    }

    if (sec_prot_cfg) {
        controller->sec_cfg.prot_cfg.sec_prot_trickle_params.Imin = sec_prot_cfg->sec_prot_trickle_imin * 10;
        controller->sec_cfg.prot_cfg.sec_prot_trickle_params.Imax = sec_prot_cfg->sec_prot_trickle_imax * 10;
        controller->sec_cfg.prot_cfg.sec_prot_trickle_params.k = 0;
        controller->sec_cfg.prot_cfg.sec_prot_trickle_params.TimerExpirations = sec_prot_cfg->sec_prot_trickle_timer_exp;
        controller->sec_cfg.prot_cfg.sec_prot_retry_timeout = sec_prot_cfg->sec_prot_retry_timeout * 10;
        controller->sec_cfg.prot_cfg.initial_key_retry_min = sec_prot_cfg->initial_key_retry_min;
        controller->sec_cfg.prot_cfg.initial_key_retry_max = sec_prot_cfg->initial_key_retry_max;
        controller->sec_cfg.prot_cfg.initial_key_retry_max_limit = sec_prot_cfg->initial_key_retry_max_limit;
        controller->sec_cfg.prot_cfg.initial_key_retry_cnt = sec_prot_cfg->initial_key_retry_cnt;
    }

    if (sec_timer_cfg) {
        ws_pae_timers_settings_init(&controller->sec_cfg.timer_cfg, sec_timer_cfg);
    }

    controller->sec_cfg.radius_cfg = pae_controller_config.radius_cfg;

    if (timing_cfg) {
        controller->sec_cfg.timing_cfg.temp_eapol_min_timeout = timing_cfg->temp_eapol_min_timeout;
    }

    return 0;
}

static void ws_pae_controller_data_init(pae_controller_t *controller)
{
    memset(controller->target_eui_64, 0, sizeof(controller->target_eui_64));
    memset(controller->br_eui_64, 0, sizeof(controller->br_eui_64));
    memset(controller->gtks.gtkhash, 0, sizeof(controller->gtks.gtkhash));
    memset(controller->lgtks.gtkhash, 0, sizeof(controller->lgtks.gtkhash));
    memset(controller->gtks.nw_key, 0, sizeof(controller->gtks.nw_key));
    memset(controller->lgtks.nw_key, 0, sizeof(controller->lgtks.nw_key));

    controller->target_pan_id = 0xffff;
    controller->pae_delete = NULL;
    controller->pae_fast_timer = NULL;
    controller->pae_slow_timer = NULL;
    controller->pae_br_addr_write = NULL;
    controller->pae_br_addr_read = NULL;
    controller->pae_gtks_updated = NULL;
    controller->pae_gtk_hash_update = NULL;
    controller->pae_nw_key_index_update = NULL;
    controller->pae_nw_info_set = NULL;
    controller->gtks.gtks_set = false;
    controller->gtks.gtkhash_set = false;
    controller->gtks.key_index_set = false;
    controller->lgtks.gtks_set = false;
    controller->lgtks.gtkhash_set = false;
    controller->lgtks.key_index_set = false;
    controller->frame_counter_read = false;
    controller->gtks.gtk_index = -1;
    controller->lgtks.gtk_index = -1;
    controller->frame_cnt_store_timer = FRAME_COUNTER_STORE_INTERVAL;
    controller->frame_cnt_store_force_timer = FRAME_COUNTER_STORE_FORCE_INTERVAL;
    controller->auth_started = false;
    ws_pae_controller_frame_counter_reset(&controller->gtks.frame_counters);
    ws_pae_controller_frame_counter_reset(&controller->lgtks.frame_counters);
    sec_prot_keys_gtks_init(&controller->gtks.gtks);
    sec_prot_keys_gtks_init(&controller->lgtks.gtks);
    sec_prot_keys_gtks_init(&controller->gtks.next_gtks);
    sec_prot_keys_gtks_init(&controller->lgtks.next_gtks);
    sec_prot_certs_init(&controller->certs);
    sec_prot_certs_ext_certificate_validation_set(&controller->certs, pae_controller_config.ext_cert_valid_enabled);
    ws_pae_controller_keys_nw_info_init(&controller->sec_keys_nw_info, &controller->gtks.gtks, &controller->lgtks.gtks);
}

static int8_t ws_pae_controller_frame_counter_read(pae_controller_t *controller)
{
    if (controller->frame_counter_read) {
        return 0;
    }
    controller->frame_counter_read = true;

    uint64_t stored_time = 0;

    // Read frame counters
    if (ws_pae_controller_nvm_frame_counter_read(&stored_time, &controller->sec_keys_nw_info.pan_version, &controller->sec_keys_nw_info.lpan_version, &controller->gtks.frame_counters, &controller->lgtks.frame_counters) >= 0) {
        // Increments PAN version to ensure that it is fresh
        controller->sec_keys_nw_info.pan_version += PAN_VERSION_STORAGE_READ_INCREMENT;

        // Checks frame counters
        for (uint8_t index = 0; index < GTK_NUM; index++) {
            if (controller->gtks.frame_counters.counter[index].set) {
                // If there is room on frame counter space
                if (controller->gtks.frame_counters.counter[index].frame_counter < (UINT32_MAX - FRAME_COUNTER_INCREMENT * 2)) {
                    // Increments frame counters
                    controller->gtks.frame_counters.counter[index].frame_counter += FRAME_COUNTER_INCREMENT;
                } else {
                    tr_error("Frame counter space exhausted");
                    controller->gtks.frame_counters.counter[index].frame_counter = UINT32_MAX;
                }
                controller->gtks.frame_counters.counter[index].stored_frame_counter =
                    controller->gtks.frame_counters.counter[index].frame_counter;

                tr_info("Read frame counter: index %i value %"PRIu32"", index, controller->gtks.frame_counters.counter[index].frame_counter);
            }
        }
    }

    return 0;
}

static void ws_pae_controller_frame_counter_reset(frame_counters_t *frame_counters)
{
    for (uint8_t index = 0; index < GTK_NUM; index++) {
        ws_pae_controller_frame_counter_index_reset(frame_counters, index);
    }
    frame_counters->active_gtk_index = -1;
}

static void ws_pae_controller_frame_counter_index_reset(frame_counters_t *frame_counters, uint8_t index)
{
    memset(&frame_counters->counter[index], 0, sizeof(frame_counters->counter[index]));
}

static int8_t ws_pae_controller_nw_info_read(pae_controller_t *controller,
                                             sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks)
{
    uint8_t nvm_gtk_eui64[8];
    uint64_t system_time = ws_pae_current_time_get();

    if (ws_pae_controller_nvm_nw_info_read(controller->interface_ptr,
                                           &controller->sec_keys_nw_info.key_pan_id,
                                           controller->sec_keys_nw_info.network_name,
                                           nvm_gtk_eui64, gtks, lgtks, system_time) < 0) {
        // If no stored GTKs and network info (pan_id and network name) exits
        return -1;
    }

    /* Get own EUI-64 and compare to the one read from the NVM. In case of mismatch delete GTKs and make
       full authentication to update keys with new EUI-64 and in case of authenticator to update new
       authenticator EUI-64 to the network. */
    uint8_t gtk_eui64[8] = {0};
    link_layer_address_s mac_params;
    if (arm_nwk_mac_address_read(controller->interface_ptr->id, &mac_params) >= 0) {
        memcpy(gtk_eui64, mac_params.mac_long, 8);
    }
    if (memcmp(nvm_gtk_eui64, gtk_eui64, 8) != 0) {
        tr_warn("NVM EUI-64 mismatch, current: %s stored: %s", tr_eui64(gtk_eui64), tr_eui64(nvm_gtk_eui64));
        sec_prot_keys_gtks_clear(gtks);
        sec_prot_keys_gtks_clear(lgtks);
    }

    // Sets also new pan_id used for pan_id set by bootstrap
    controller->sec_keys_nw_info.new_pan_id = controller->sec_keys_nw_info.key_pan_id;

    return 0;
}

const struct name_value valid_gtk_status[] = {
    { "new",    GTK_STATUS_NEW    },
    { "fresh",  GTK_STATUS_FRESH  },
    { "active", GTK_STATUS_ACTIVE },
    { "old",    GTK_STATUS_OLD    },
    { NULL },
};

static int8_t ws_pae_controller_nvm_nw_info_write(struct net_if *interface_ptr,
                                                  uint16_t pan_id, char *network_name, uint8_t *gtk_eui64,
                                                  sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks)
{
    unsigned long long current_time = ws_pae_current_time_get();
    struct storage_parse_info *info = storage_open_prefix("network-keys", "w");
    uint8_t gtk_hash[GTK_HASH_LEN];
    uint8_t gak[GTK_LEN];
    char str_buf[256];
    int i;

    if (!info)
        return -1;
    fprintf(info->file, "pan_id = %#04x\n", pan_id);
    str_bytes(network_name, strlen(network_name), NULL, str_buf, sizeof(str_buf), FMT_ASCII_ALNUM);
    fprintf(info->file, "network_name = %s\n", str_buf);
    str_key(gtk_eui64, 8, str_buf, sizeof(str_buf));
    fprintf(info->file, "eui64 = %s\n", str_buf);
    for (i = 0; i < GTK_NUM; i++) {
        if (gtks && gtks->gtk[i].set) {
            fprintf(info->file, "\n");
            sec_prot_keys_gtk_hash_generate(gtks->gtk[i].key, gtk_hash);
            ws_pae_controller_gak_from_gtk(gak, gtks->gtk[i].key, network_name);
            str_key(gtks->gtk[i].key, GTK_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "gtk[%d] = %s\n", i, str_buf);
            fprintf(info->file, "gtk[%d].lifetime = %llu\n", i, gtks->gtk[i].lifetime + current_time);
            fprintf(info->file, "gtk[%d].status = %s\n", i, val_to_str(gtks->gtk[i].status, valid_gtk_status, NULL));
            fprintf(info->file, "gtk[%d].install_order = %u\n", i, gtks->gtk[i].install_order);
            fprintf(info->file, "# For information:\n");
            str_key(gak, GTK_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "#gtk[%d].gak = %s\n", i, str_buf);
            str_key(gtk_hash, GTK_HASH_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "#gtk[%d].hash = %s\n", i, str_buf);
            str_key(gtk_hash, INS_GTK_HASH_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "#gtk[%d].installed_hash = %s\n", i, str_buf);
        }
    }
    for (i = 0; i < LGTK_NUM; i++) {
        if (lgtks && lgtks->gtk[i].set) {
            fprintf(info->file, "\n");
            sec_prot_keys_gtk_hash_generate(lgtks->gtk[i].key, gtk_hash);
            ws_pae_controller_gak_from_gtk(gak, lgtks->gtk[i].key, network_name);
            str_key(lgtks->gtk[i].key, GTK_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "lgtk[%d] = %s\n", i, str_buf);
            fprintf(info->file, "lgtk[%d].lifetime = %llu\n", i, lgtks->gtk[i].lifetime + current_time);
            fprintf(info->file, "lgtk[%d].status = %s\n", i, val_to_str(lgtks->gtk[i].status, valid_gtk_status, NULL));
            fprintf(info->file, "lgtk[%d].install_order = %u\n", i, lgtks->gtk[i].install_order);
            fprintf(info->file, "# For information:\n");
            str_key(gak, GTK_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "#lgtk[%d].gak = %s\n", i, str_buf);
            str_key(gtk_hash, GTK_HASH_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "#lgtk[%d].hash = %s\n", i, str_buf);
            str_key(gtk_hash, INS_GTK_HASH_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "#lgtk[%d].installed_hash = %s\n", i, str_buf);
        }
    }
    storage_close(info);
    return 0;
}

static int8_t ws_pae_controller_nvm_nw_info_read(struct net_if *interface_ptr,
                                                 uint16_t *pan_id, char *network_name, uint8_t *gtk_eui64,
                                                 sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks,
                                                 uint64_t current_time)
{
    struct storage_parse_info *info = storage_open_prefix("network-keys", "r");
    gtk_key_t new_gtks[GTK_NUM] = { };
    gtk_key_t new_lgtks[LGTK_NUM] = { };
    int ret, i;

    if (!info)
        return -1;
    for (;;) {
        // This function does not support case where only some keys attributes
        // are set (eg install_order with gtk value, etc...)
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("pan_id", info->key, 0)) {
            *pan_id = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("network_name", info->key, 0)) {
            if (parse_escape_sequences(network_name, info->value, 33))
                WARN("%s:%d: parsing error (escape sequence or too long)", info->filename, info->linenr);
        } else if (!fnmatch("eui64", info->key, 0)) {
            if (parse_byte_array(gtk_eui64, 8, info->value))
                WARN("%s:%d: invalid EUI64: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("gtk\\[*]", info->key, 0) && info->key_array_index < 4) {
            if (!parse_byte_array(new_gtks[info->key_array_index].key, GTK_LEN, info->value))
                new_gtks[info->key_array_index].set = true;
            else
                WARN("%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("lgtk\\[*]", info->key, 0) && info->key_array_index < 3) {
            if (!parse_byte_array(new_lgtks[info->key_array_index].key, GTK_LEN, info->value))
                new_lgtks[info->key_array_index].set = true;
            else
                WARN("%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("gtk\\[*].install_order", info->key, 0) && info->key_array_index < 4) {
            new_gtks[info->key_array_index].install_order = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("lgtk\\[*].install_order", info->key, 0) && info->key_array_index < 3) {
            new_lgtks[info->key_array_index].install_order = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("gtk\\[*].status", info->key, 0) && info->key_array_index < 4) {
            new_gtks[info->key_array_index].status = str_to_val(info->value, valid_gtk_status);
        } else if (!fnmatch("lgtk\\[*].status", info->key, 0) && info->key_array_index < 3) {
            new_lgtks[info->key_array_index].status = str_to_val(info->value, valid_gtk_status);
        } else if (!fnmatch("gtk\\[*].lifetime", info->key, 0) && info->key_array_index < 4) {
            if (strtoull(info->value, NULL, 0) > current_time)
                new_gtks[info->key_array_index].lifetime = strtoull(info->value, NULL, 0) - current_time;
            else
                WARN("%s:%d: expired lifetime: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("lgtk\\[*].lifetime", info->key, 0) && info->key_array_index < 3) {
            if (strtoull(info->value, NULL, 0) > current_time)
                new_lgtks[info->key_array_index].lifetime = strtoull(info->value, NULL, 0) - current_time;
            else
                WARN("%s:%d: expired lifetime: %s", info->filename, info->linenr, info->value);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);

    for (i = 0; i < GTK_NUM; i++)
        if (!gtks->gtk[i].set && new_gtks[i].set && new_gtks[i].lifetime)
            memcpy(&gtks->gtk[i], &new_gtks[i], sizeof(new_gtks[i]));
    for (i = 0; i < LGTK_NUM; i++)
        if (!lgtks->gtk[i].set && new_lgtks[i].set && new_lgtks[i].lifetime)
            memcpy(&lgtks->gtk[i], &new_lgtks[i], sizeof(new_lgtks[i]));
    return 0;
}

#ifdef HAVE_PAE_SUPP
int8_t ws_pae_controller_supp_init(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (ws_pae_supp_init(controller->interface_ptr, &controller->certs, &controller->sec_cfg, &controller->sec_keys_nw_info) < 0) {
        return -1;
    }

    controller->pae_delete = ws_pae_supp_delete;
    controller->pae_fast_timer = ws_pae_supp_fast_timer;
    controller->pae_slow_timer = ws_pae_supp_slow_timer;
    controller->pae_br_addr_write = ws_pae_supp_border_router_addr_write;
    controller->pae_br_addr_read = ws_pae_supp_border_router_addr_read;
    controller->pae_gtk_hash_update = ws_pae_supp_gtk_hash_update;
    controller->pae_nw_key_index_update = ws_pae_supp_nw_key_index_update;
    controller->pae_nw_info_set = ws_pae_supp_nw_info_set;

    ws_pae_supp_cb_register(controller->interface_ptr,
                            controller->auth_completed,
                            controller->auth_next_target,
                            ws_pae_controller_nw_key_check_and_insert,
                            ws_pae_controller_active_nw_key_set,
                            ws_pae_controller_gtk_hash_ptr_get,
                            ws_pae_controller_nw_info_updated_check);

    ws_pae_controller_frame_counter_read(controller);
    ws_pae_controller_nw_info_read(controller, controller->sec_keys_nw_info.gtks, controller->sec_keys_nw_info.lgtks);
    // Set active key back to fresh so that it can be used again after re-start
    sec_prot_keys_gtk_status_active_to_fresh_set(&controller->gtks.gtks);
    sec_prot_keys_gtk_status_active_to_fresh_set(&controller->lgtks.gtks);
    sec_prot_keys_gtks_updated_reset(&controller->gtks.gtks);
    sec_prot_keys_gtks_updated_reset(&controller->lgtks.gtks);

    return 0;
}
#endif

#ifdef HAVE_PAE_AUTH
int8_t ws_pae_controller_auth_init(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (ws_pae_auth_init(controller->interface_ptr,
                         &controller->gtks.next_gtks,
                         &controller->lgtks.next_gtks,
                         &controller->certs,
                         &controller->sec_cfg,
                         &controller->sec_keys_nw_info,
                         &controller->gtks.frame_counters,
                         &controller->lgtks.frame_counters) < 0) {
        return -1;
    }

    controller->pae_delete = ws_pae_auth_delete;
    controller->pae_fast_timer = ws_pae_auth_fast_timer;
    controller->pae_slow_timer = ws_pae_auth_slow_timer;
    controller->pae_gtks_updated = ws_pae_auth_gtks_updated;
    controller->pae_nw_key_index_update = ws_pae_auth_nw_key_index_update;
    controller->pae_nw_info_set = ws_pae_auth_nw_info_set;

    sec_prot_gtk_keys_t *read_gtks_to = controller->sec_keys_nw_info.gtks;
    sec_prot_gtk_keys_t *read_lgtks_to = controller->sec_keys_nw_info.lgtks;
    ws_pae_controller_frame_counter_read(controller);

    if (sec_prot_keys_gtks_are_updated(controller->sec_keys_nw_info.gtks)) {
        // If application has set GTK keys prepare those for use
        ws_pae_auth_gtks_updated(interface_ptr, false);
        if (controller->gtks.gtk_index >= 0) {
            controller->pae_nw_key_index_update(interface_ptr, controller->gtks.gtk_index, false);
        }
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.gtks);
    }
    if (sec_prot_keys_gtks_are_updated(controller->sec_keys_nw_info.lgtks)) {
        // If application has set LGTK keys prepare those for use
        ws_pae_auth_gtks_updated(interface_ptr, true);
        if (controller->lgtks.gtk_index >= 0) {
            controller->pae_nw_key_index_update(interface_ptr, controller->lgtks.gtk_index, true);
        }
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.lgtks);
    }

    if (ws_pae_controller_nw_info_read(controller, read_gtks_to, read_lgtks_to) >= 0) {
        /* If network information i.e pan_id and network name exists updates bootstrap with it,
           (in case already configured by application then no changes are made) */
        if (controller->nw_info_updated) {
            controller->nw_info_updated(interface_ptr,
                                        controller->sec_keys_nw_info.key_pan_id,
                                        controller->sec_keys_nw_info.pan_version,
                                        controller->sec_keys_nw_info.lpan_version,
                                        controller->sec_keys_nw_info.network_name);
        }
        if (sec_prot_keys_gtk_count(read_gtks_to) == 0 ||
            sec_prot_keys_gtk_count(read_lgtks_to) == 0) {
            // Key material invalid or (L)GTKs are expired, delete (L)GTKs from NVM
            uint8_t gtk_eui64[8] = {0}; // Set GTK EUI-64 to zero
            ws_pae_controller_nvm_nw_info_write(controller->interface_ptr,
                                                controller->sec_keys_nw_info.key_pan_id,
                                                controller->sec_keys_nw_info.network_name,
                                                gtk_eui64, read_gtks_to, read_lgtks_to);
        }
    }

    return 0;
}
#endif

int8_t ws_pae_controller_stop(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    // Stores frame counters and removes network keys from PAE controller and MAC
    ws_pae_controller_frame_counter_store_and_nw_keys_remove(interface_ptr, controller, false, false);
    ws_pae_controller_frame_counter_store_and_nw_keys_remove(interface_ptr, controller, false, true);

    // Store security key network info if it has been modified
    ws_pae_controller_nw_info_updated_check(interface_ptr);

    // If PAE has been initialized, deletes it
    if (controller->pae_delete) {
        controller->pae_delete(interface_ptr);
    }

    // Free data
    sec_prot_certs_delete(&controller->certs);

    // Init controller data
    ws_pae_controller_data_init(controller);

    return 0;
}

int8_t ws_pae_controller_delete(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return -1;
    }

    ws_pae_controller_stop(interface_ptr);

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    ns_list_remove(&pae_controller_list, controller);
    free(controller);

    return 0;
}

int8_t ws_pae_controller_certificate_chain_set(const arm_certificate_chain_entry_s *new_chain)
{
    if (!new_chain) {
        return -1;
    }

    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        // Delete previous information
        sec_prot_certs_delete(&entry->certs);

        // Adds a trusted certificate from index 0
        if (new_chain->cert_chain[0]) {
            cert_chain_entry_t *root_ca_chain = sec_prot_certs_chain_entry_create();
            sec_prot_certs_cert_set(root_ca_chain, 0, (uint8_t *) new_chain->cert_chain[0], new_chain->cert_len[0]);
            sec_prot_certs_chain_list_add(&entry->certs.trusted_cert_chain_list, root_ca_chain);
        }

        // Adds own certificate chain from indexes 1 to 3
        for (uint8_t i = 1; i < SEC_PROT_CERT_CHAIN_DEPTH; i++) {
            if (new_chain->cert_chain[i]) {
                sec_prot_certs_cert_set(&entry->certs.own_cert_chain, i - 1, (uint8_t *) new_chain->cert_chain[i], new_chain->cert_len[i]);
                if (new_chain->key_chain[i]) {
                    // Will be the key from top certificate in chain after all certificates are added
                    uint8_t key_len = strlen((char *) new_chain->key_chain[i]) + 1;
                    sec_prot_certs_priv_key_set(&entry->certs.own_cert_chain, (uint8_t *) new_chain->key_chain[i], key_len);
                }
            }
        }

        // Updates the length of own certificates
        entry->certs.own_cert_chain_len = sec_prot_certs_cert_chain_entry_len_get(&entry->certs.own_cert_chain);
    }

    return 0;
}

int8_t ws_pae_controller_own_certificate_add(const arm_certificate_entry_s *cert)
{
    if (!cert) {
        return -1;
    }

    int8_t ret = -1;

    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        for (uint8_t i = 0; i < SEC_PROT_CERT_CHAIN_DEPTH; i++) {
            if (entry->certs.own_cert_chain.cert[i] == NULL) {
                sec_prot_certs_cert_set(&entry->certs.own_cert_chain, i, (uint8_t *) cert->cert, cert->cert_len);
                // Set private key if set for the certificate that is added
                if (cert->key && cert->key_len > 0) {
                    sec_prot_certs_priv_key_set(&entry->certs.own_cert_chain, (uint8_t *) cert->key, cert->key_len);
                }
                ret = 0;
                break;
            }
        }
        // Updates the length of own certificates
        entry->certs.own_cert_chain_len = sec_prot_certs_cert_chain_entry_len_get(&entry->certs.own_cert_chain);
    }

    return ret;
}

int8_t ws_pae_controller_own_certificates_remove(void)
{
    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        sec_prot_certs_chain_entry_init(&entry->certs.own_cert_chain);
        entry->certs.own_cert_chain_len = 0;
    }

    return 0;
}

int8_t ws_pae_controller_trusted_certificate_add(const arm_certificate_entry_s *cert)
{
    if (!cert) {
        return -1;
    }

    int8_t ret = -1;

    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        cert_chain_entry_t *trusted_cert = sec_prot_certs_chain_entry_create();
        sec_prot_certs_cert_set(trusted_cert, 0, (uint8_t *) cert->cert, cert->cert_len);

        if (sec_prot_certs_chain_list_entry_find(&entry->certs.trusted_cert_chain_list, trusted_cert)) {
            sec_prot_certs_chain_entry_delete(trusted_cert);
            continue;
        }
        sec_prot_certs_chain_list_add(&entry->certs.trusted_cert_chain_list, trusted_cert);
        ret = 0;
    }

    return ret;
}

int8_t ws_pae_controller_trusted_certificate_remove(const arm_certificate_entry_s *cert)
{
    if (!cert) {
        return -1;
    }

    int8_t ret = -1;

    cert_chain_entry_t *trusted_cert = sec_prot_certs_chain_entry_create();
    sec_prot_certs_cert_set(trusted_cert, 0, (uint8_t *) cert->cert, cert->cert_len);

    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        cert_chain_entry_t *removed_cert = sec_prot_certs_chain_list_entry_find(&entry->certs.trusted_cert_chain_list, trusted_cert);
        if (removed_cert) {
            sec_prot_certs_chain_list_entry_delete(&entry->certs.trusted_cert_chain_list, removed_cert);
            ret = 0;
        }
    }

    sec_prot_certs_chain_entry_delete(trusted_cert);

    return ret;
}

int8_t ws_pae_controller_trusted_certificates_remove(void)
{
    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        sec_prot_certs_chain_list_delete(&entry->certs.trusted_cert_chain_list);
    }

    return 0;
}

int8_t ws_pae_controller_certificate_revocation_list_add(const arm_cert_revocation_list_entry_s *crl)
{
    if (!crl) {
        return -1;
    }

    int8_t ret = -1;

    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        cert_revocat_list_entry_t *cert_revoc_list = sec_prot_certs_revocat_list_entry_create();
        sec_prot_certs_revocat_list_set(cert_revoc_list, crl->crl, crl->crl_len);

        if (sec_prot_certs_revocat_lists_entry_find(&entry->certs.cert_revocat_lists, cert_revoc_list)) {
            sec_prot_certs_revocat_list_entry_delete(cert_revoc_list);
            continue;
        }

        sec_prot_certs_revocat_lists_add(&entry->certs.cert_revocat_lists, cert_revoc_list);
        ret = 0;
    }

    return ret;
}

int8_t ws_pae_controller_certificate_revocation_list_remove(const arm_cert_revocation_list_entry_s *crl)
{
    if (!crl) {
        return -1;
    }

    int8_t ret = -1;

    cert_revocat_list_entry_t *cert_revoc_list = sec_prot_certs_revocat_list_entry_create();
    sec_prot_certs_revocat_list_set(cert_revoc_list, crl->crl, crl->crl_len);

    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        cert_revocat_list_entry_t *removed_cert_revoc_list = sec_prot_certs_revocat_lists_entry_find(&entry->certs.cert_revocat_lists, cert_revoc_list);
        if (removed_cert_revoc_list) {
            sec_prot_certs_revocat_lists_entry_delete(&entry->certs.cert_revocat_lists, removed_cert_revoc_list);
            ret = 0;
        }
    }

    sec_prot_certs_revocat_list_entry_delete(cert_revoc_list);

    return ret;
}

sec_radius_cfg_t *ws_pae_controller_radius_config_get(void)
{
    if (pae_controller_config.radius_cfg != NULL) {
        return pae_controller_config.radius_cfg;
    }

    pae_controller_config.radius_cfg = malloc(sizeof(sec_radius_cfg_t));
    if (pae_controller_config.radius_cfg == NULL) {
        return NULL;
    }

    pae_controller_config.radius_cfg->radius_retry_trickle_params.Imin = RADIUS_CLIENT_RETRY_IMIN;
    pae_controller_config.radius_cfg->radius_retry_trickle_params.Imax = RADIUS_CLIENT_RETRY_IMAX;
    pae_controller_config.radius_cfg->radius_retry_trickle_params.k = 0;
    pae_controller_config.radius_cfg->radius_retry_trickle_params.TimerExpirations = RADIUS_CLIENT_TIMER_EXPIRATIONS;

    pae_controller_config.radius_cfg->radius_addr_set = false;
    pae_controller_config.radius_cfg->radius_shared_secret_len = 0;
    pae_controller_config.radius_cfg->radius_shared_secret = NULL;

    return pae_controller_config.radius_cfg;
}

int8_t ws_pae_controller_radius_address_set(int8_t interface_id, const struct sockaddr_storage *address)
{
    sec_radius_cfg_t *radius_cfg = ws_pae_controller_radius_config_get();
    if (radius_cfg == NULL) {
        return -1;
    }

    if (address != NULL) {
        memcpy(&radius_cfg->radius_addr, address, sizeof(struct sockaddr_storage));
        radius_cfg->radius_addr_set = true;
    } else {
        radius_cfg->radius_addr_set = false;
    }

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return 0;
    }

    if (ws_pae_controller_configure(controller->interface_ptr, NULL, NULL, NULL) < 0) {
        return -1;
    }

    if (!radius_cfg->radius_addr_set) {
        return 0;
    }

    if (ws_pae_auth_radius_address_set(controller->interface_ptr, address) < 0) {
        // If not set here since authenticator not created, then set on authenticator initialization
        return 0;
    }

    return 0;
}

int8_t ws_pae_controller_radius_address_get(int8_t interface_id, struct sockaddr_storage *address)
{
    (void) interface_id;

    if (address == NULL) {
        return -1;
    }

    sec_radius_cfg_t *radius_cfg = ws_pae_controller_radius_config_get();
    if (radius_cfg == NULL) {
        return -1;
    }

    if (!radius_cfg->radius_addr_set) {
        return -1;
    }

    memcpy(address, &radius_cfg->radius_addr, sizeof(struct sockaddr_storage));

    return 0;
}

int8_t ws_pae_controller_radius_shared_secret_set(int8_t interface_id, const uint16_t shared_secret_len, const uint8_t *shared_secret)
{
    sec_radius_cfg_t *radius_cfg = ws_pae_controller_radius_config_get();
    if (radius_cfg == NULL) {
        return -1;
    }

    radius_cfg->radius_shared_secret = shared_secret;
    radius_cfg->radius_shared_secret_len = shared_secret_len;

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (controller) {
        ws_pae_controller_configure(controller->interface_ptr, NULL, NULL, NULL);
    }

    return 0;
}

int8_t ws_pae_controller_radius_shared_secret_get(int8_t interface_id, uint16_t *shared_secret_len, uint8_t *shared_secret)
{
    (void) interface_id;

    if (shared_secret_len == NULL) {
        return -1;
    }

    sec_radius_cfg_t *radius_cfg = ws_pae_controller_radius_config_get();
    if (radius_cfg == NULL) {
        return -1;
    }

    uint16_t length = radius_cfg->radius_shared_secret_len;
    if (shared_secret != NULL) {
        if (length > *shared_secret_len) {
            length = *shared_secret_len;
        }
        if (length > 0 && radius_cfg->radius_shared_secret != NULL) {
            memcpy(shared_secret, radius_cfg->radius_shared_secret, length);
        }
    }

    *shared_secret_len = length;

    return 0;
}

int8_t ws_pae_controller_radius_timing_set(int8_t interface_id, bbr_radius_timing_t *timing)
{
    (void) interface_id;

    if (timing == NULL) {
        return -1;
    }

    sec_radius_cfg_t *radius_cfg = ws_pae_controller_radius_config_get();
    if (radius_cfg == NULL) {
        return -1;
    }

    radius_cfg->radius_retry_trickle_params.Imin = timing->radius_retry_imin;
    radius_cfg->radius_retry_trickle_params.Imax = timing->radius_retry_imax;
    radius_cfg->radius_retry_trickle_params.TimerExpirations = timing->radius_retry_count;

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (controller) {
        ws_pae_controller_configure(controller->interface_ptr, NULL, NULL, NULL);
    }

    return 0;
}

int8_t ws_pae_controller_radius_timing_get(int8_t interface_id, bbr_radius_timing_t *timing)
{
    (void) interface_id;

    if (timing == NULL) {
        return -1;
    }

    if (pae_controller_config.radius_cfg == NULL) {
        timing->radius_retry_imin = RADIUS_CLIENT_RETRY_IMIN;
        timing->radius_retry_imax = RADIUS_CLIENT_RETRY_IMAX;
        timing->radius_retry_count = RADIUS_CLIENT_TIMER_EXPIRATIONS;
        return 0;
    }

    sec_radius_cfg_t *radius_cfg = ws_pae_controller_radius_config_get();
    if (radius_cfg == NULL) {
        return -1;
    }

    timing->radius_retry_imin = radius_cfg->radius_retry_trickle_params.Imin;
    timing->radius_retry_imax = radius_cfg->radius_retry_trickle_params.Imax;
    timing->radius_retry_count = radius_cfg->radius_retry_trickle_params.TimerExpirations;

    return 0;
}

int8_t ws_pae_controller_radius_timing_validate(int8_t interface_id, bbr_radius_timing_t *timing)
{
    (void) interface_id;

    if (timing == NULL) {
        return -1;
    }

    if (timing->radius_retry_imin == 0 || timing->radius_retry_imax == 0 ||
            timing->radius_retry_imin > timing->radius_retry_imax) {
        return -1;
    }

    return 0;
}

int8_t ws_pae_controller_border_router_addr_write(struct net_if *interface_ptr, const uint8_t *eui_64)
{
    if (!eui_64) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (controller->pae_br_addr_write) {
        return controller->pae_br_addr_write(interface_ptr, eui_64);
    } else {
        memcpy(controller->br_eui_64, eui_64, 8);
    }

    return 0;
}

int8_t ws_pae_controller_border_router_addr_read(struct net_if *interface_ptr, uint8_t *eui_64)
{
    if (!eui_64) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (controller->pae_br_addr_read) {
        return controller->pae_br_addr_read(interface_ptr, eui_64);
    } else {
        memcpy(eui_64, controller->br_eui_64, 8);
    }

    return 0;
}

int8_t ws_pae_controller_gtk_update(int8_t interface_id, uint8_t *gtk[GTK_NUM])
{
    if (!gtk) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    // Removes keys set as not used
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (!gtk[i]) {
            sec_prot_keys_gtk_clear(&controller->gtks.gtks, i);
        }
    }

    // Inserts new keys
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (gtk[i]) {
            uint32_t lifetime = sec_prot_keys_gtk_install_order_last_lifetime_get(&controller->gtks.gtks);
            lifetime += controller->sec_cfg.timer_cfg.gtk.expire_offset;
            if (sec_prot_keys_gtk_set(&controller->gtks.gtks, i, gtk[i], lifetime) >= 0) {
                controller->gtks.gtks_set = true;
                tr_info("GTK set index: %i, lifetime %"PRIu32", system time: %"PRIu32"", i, lifetime, g_monotonic_time_100ms / 10);
            }
        }
    }

    // Sets active key
    int8_t index = sec_prot_keys_gtk_install_order_first_index_get(&controller->gtks.gtks);
    sec_prot_keys_gtk_status_all_fresh_set(&controller->gtks.gtks);
    sec_prot_keys_gtk_status_active_set(&controller->gtks.gtks, index);

    // Notifies PAE authenticator that GTKs have been updated */
    if (controller->pae_gtks_updated) {
        controller->pae_gtks_updated(controller->interface_ptr, false);
    }

    return 0;
}

int8_t ws_pae_controller_lgtk_update(int8_t interface_id, uint8_t *lgtk[LGTK_NUM])
{
    if (!lgtk) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    // Removes keys set as not used
    for (uint8_t i = 0; i < LGTK_NUM; i++) {
        if (!lgtk[i]) {
            sec_prot_keys_gtk_clear(&controller->lgtks.gtks, i);
        }
    }

    // Inserts new keys
    for (uint8_t i = 0; i < LGTK_NUM; i++) {
        if (lgtk[i]) {
            uint32_t lifetime = sec_prot_keys_gtk_install_order_last_lifetime_get(&controller->lgtks.gtks);
            lifetime += controller->sec_cfg.timer_cfg.lgtk.expire_offset;
            if (sec_prot_keys_gtk_set(&controller->lgtks.gtks, i, lgtk[i], lifetime) >= 0) {
                controller->lgtks.gtks_set = true;
                tr_info("LGTK set index: %i, lifetime %"PRIu32", system time: %"PRIu32"", i, lifetime, g_monotonic_time_100ms / 10);
            }
        }
    }

    // Sets active key
    int8_t index = sec_prot_keys_gtk_install_order_first_index_get(&controller->lgtks.gtks);
    sec_prot_keys_gtk_status_all_fresh_set(&controller->lgtks.gtks);
    sec_prot_keys_gtk_status_active_set(&controller->lgtks.gtks, index);

    // Notifies PAE authenticator that GTKs have been updated */
    if (controller->pae_gtks_updated) {
        controller->pae_gtks_updated(controller->interface_ptr, true);
    }

    return 0;
}

int8_t ws_pae_controller_next_gtk_update(int8_t interface_id, uint8_t *gtk[GTK_NUM])
{
    if (!gtk) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    // Inserts new keys and removed keys set as not used
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (gtk[i]) {
            sec_prot_keys_gtk_set(&controller->gtks.next_gtks, i, gtk[i], 0);
        } else {
            sec_prot_keys_gtk_clear(&controller->gtks.next_gtks, i);
        }
    }

    return 0;
}

int8_t ws_pae_controller_next_lgtk_update(int8_t interface_id, uint8_t *gtk[LGTK_NUM])
{
    if (!gtk) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    // Inserts new keys and removed keys set as not used
    for (uint8_t i = 0; i < LGTK_NUM; i++) {
        if (gtk[i]) {
            sec_prot_keys_gtk_set(&controller->lgtks.next_gtks, i, gtk[i], 0);
        } else {
            sec_prot_keys_gtk_clear(&controller->lgtks.next_gtks, i);
        }
    }

    return 0;
}

int8_t ws_pae_controller_active_key_update(int8_t interface_id, uint8_t index)
{
    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    BUG_ON(index >= GTK_NUM);
    controller->gtks.gtk_index = index;

    if (controller->pae_nw_key_index_update) {
        controller->pae_nw_key_index_update(controller->interface_ptr, index, false);
    }

    return 0;
}

int8_t ws_pae_controller_node_keys_remove(int8_t interface_id, uint8_t *eui_64)
{
#ifndef HAVE_PAE_AUTH
    (void) eui_64;
#endif

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    return ws_pae_auth_node_keys_remove(controller->interface_ptr, eui_64);
}

int8_t ws_pae_controller_node_access_revoke_start(int8_t interface_id, bool is_lgtk, uint8_t new_gtk[GTK_LEN])
{
    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    return ws_pae_auth_node_access_revoke_start(controller->interface_ptr, is_lgtk, new_gtk);
}

int8_t ws_pae_controller_node_limit_set(int8_t interface_id, uint16_t limit)
{
#ifdef HAVE_PAE_AUTH
    pae_controller_config.node_limit = limit;
    pae_controller_config.node_limit_set = true;

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    ws_pae_auth_node_limit_set(controller->interface_ptr, limit);

    return 0;
#else
    (void) interface_id;
    (void) limit;
    return -1;
#endif
}

int8_t ws_pae_controller_ext_certificate_validation_set(int8_t interface_id, bool enabled)
{
#ifdef HAVE_PAE_AUTH
    pae_controller_config.ext_cert_valid_enabled = enabled;

    pae_controller_t *controller = ws_pae_controller_get_or_create(interface_id);
    if (!controller) {
        return -1;
    }

    sec_prot_certs_ext_certificate_validation_set(&controller->certs, enabled);

    return 0;
#else
    (void) interface_id;
    (void) enabled;
    return -1;
#endif
}

#ifdef HAVE_PAE_AUTH
static void ws_pae_controller_gtk_hash_set(struct net_if *interface_ptr, gtkhash_t *gtkhash, bool is_lgtk)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return;
    }
    pae_controller_gtk_t *gtk_struct = is_lgtk ? &controller->lgtks : &controller->gtks;

    if (!memcmp(gtk_struct->gtkhash, gtkhash, sizeof(gtk_struct->gtkhash)))
        return;
    memcpy(gtk_struct->gtkhash, gtkhash, sizeof(gtk_struct->gtkhash));

    tr_info("%s hash set %s %s %s %s",
            is_lgtk ? "LGTK" : "GTK",
            trace_array(gtkhash[0], 8),
            trace_array(gtkhash[1], 8),
            trace_array(gtkhash[2], 8),
            trace_array(gtkhash[3], 8));

    // Do not update PAN version for initial hash set
    if (gtk_struct->gtkhash_set) {
        if (!is_lgtk && controller->pan_ver_increment) {
            controller->pan_ver_increment(interface_ptr);
        }
        if (is_lgtk && controller->lpan_ver_increment) {
            controller->lpan_ver_increment(interface_ptr);
        }
    } else {
        gtk_struct->gtkhash_set = true;
    }
    if (is_lgtk)
        ws_mngt_lpc_pae_cb(interface_ptr);
}
#endif

gtkhash_t *ws_pae_controller_gtk_hash_ptr_get(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return NULL;
    }

    return controller->gtks.gtkhash;
}

gtkhash_t *ws_pae_controller_lgtk_hash_ptr_get(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return NULL;
    }

    return controller->lgtks.gtkhash;
}

int8_t ws_pae_controller_lgtk_active_index_get(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return 0;
    }

    return controller->lgtks.gtk_index;
}

int8_t ws_pae_controller_gtk_hash_update(struct net_if *interface_ptr, gtkhash_t *gtkhash)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    memcpy(controller->gtks.gtkhash, gtkhash, sizeof(controller->gtks.gtkhash));

    if (controller->pae_gtk_hash_update) {
        return controller->pae_gtk_hash_update(interface_ptr, controller->gtks.gtkhash, true);
    }

    return 0;
}

int8_t ws_pae_controller_lgtk_hash_update(struct net_if *interface_ptr, gtkhash_t *gtkhash)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    memcpy(controller->lgtks.gtkhash, gtkhash, sizeof(controller->lgtks.gtkhash));

    return 0;
}

void ws_pae_controller_fast_timer(int ticks)
{
    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        if (entry->pae_fast_timer) {
            entry->pae_fast_timer(ticks);
        }
    }
}

void ws_pae_controller_slow_timer(int seconds)
{
    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        if (entry->pae_slow_timer) {
            entry->pae_slow_timer(seconds);
        }
        ws_pae_controller_frame_counter_timer(seconds, entry);
    }
}

static void ws_pae_controller_frame_counter_timer(uint16_t seconds, pae_controller_t *entry)
{
    if (entry->frame_cnt_store_timer > seconds) {
        entry->frame_cnt_store_timer -= seconds;
    } else {
        entry->frame_cnt_store_timer = FRAME_COUNTER_STORE_INTERVAL;
        ws_pae_controller_frame_counter_store(entry, true, false);
        ws_pae_controller_frame_counter_store(entry, true, true);
    }

    if (entry->frame_cnt_store_force_timer > seconds) {
        entry->frame_cnt_store_force_timer -= seconds;
    } else {
        entry->frame_cnt_store_force_timer = 0;
        ws_pae_controller_frame_counter_store(entry, true, false);
        ws_pae_controller_frame_counter_store(entry, true, true);
    }
}

static void ws_pae_controller_frame_counter_store(pae_controller_t *entry, bool use_threshold, bool is_lgtk)
{
    bool update_needed = false;
    pae_controller_gtk_t *gtks;
    int key_offset;

    if (is_lgtk) {
        gtks = &entry->lgtks;
        key_offset = GTK_NUM;
    } else {
        gtks = &entry->gtks;
        key_offset = 0;
    }

    for (int i = 0; i < GTK_NUM; i++) {
        /* If network key is set, checks if frame counter needs to be updated to NVM
         * Note! The frame counters for non-installed keys (previous frame counters) are not changed.
         *       This is because GTKs are removed e.g. if PAN configuration is not heard/cannot be
         *       de-crypted during a bootstrap. If BR later installs previous keys using 4WH/GKH, the
         *       frame counters will be still valid.
         */
        if (gtks->nw_key[i].installed) {
            // Reads MAC frame counter for the key
            uint32_t curr_frame_counter;
            entry->nw_frame_counter_read(entry->interface_ptr, &curr_frame_counter, i + key_offset);

            // If frame counter for the network key has already been stored
            if (gtks->frame_counters.counter[i].set &&
                    memcmp(gtks->nw_key[i].gtk, gtks->frame_counters.counter[i].gtk, GTK_LEN) == 0) {

                if (curr_frame_counter > gtks->frame_counters.counter[i].frame_counter) {
                    gtks->frame_counters.counter[i].frame_counter = curr_frame_counter;
                }
                uint32_t frame_counter = gtks->frame_counters.counter[i].frame_counter;

                /* If threshold check is disabled or frame counter has advanced for the threshold value, stores the new value.
                   If frame counter is at maximum at storage, do not initiate storing */
                if (!use_threshold || (
                            (frame_counter > gtks->frame_counters.counter[i].stored_frame_counter + FRAME_COUNTER_STORE_THRESHOLD) &&
                            !(gtks->frame_counters.counter[i].stored_frame_counter == UINT32_MAX &&
                              frame_counter >= UINT32_MAX - FRAME_COUNTER_STORE_THRESHOLD))) {
                    gtks->frame_counters.counter[i].stored_frame_counter = frame_counter;
                    update_needed = true;
                    tr_debug("Stored updated frame counter: index %i value %"PRIu32"", i, frame_counter);
                }
            } else {
                // New or modified network key
                gtks->frame_counters.counter[i].set = true;
                memcpy(gtks->frame_counters.counter[i].gtk, gtks->nw_key[i].gtk, GTK_LEN);
                gtks->frame_counters.counter[i].frame_counter = curr_frame_counter;
                gtks->frame_counters.counter[i].stored_frame_counter = curr_frame_counter;
                tr_debug("Pending to store new frame counter: index %i value %"PRIu32"", i, curr_frame_counter);
            }

            /* If currently active key is changed or active key is set for the first time,
               stores the frame counter value */
            if (gtks->gtk_index == i && gtks->frame_counters.active_gtk_index != i) {
                gtks->frame_counters.active_gtk_index = gtks->gtk_index;
                update_needed = true;
                // Updates MAC frame counter for the key
                entry->nw_frame_counter_set(entry->interface_ptr, gtks->frame_counters.counter[i].frame_counter, i + key_offset);
                tr_debug("Stored frame counters, active key set: index %i value %"PRIu32"", i, gtks->frame_counters.counter[i].frame_counter);
            }
        }
    }

    if (update_needed || entry->frame_cnt_store_force_timer == 0) {
        struct storage_parse_info *info = storage_open_prefix("counters", "w");
        char str_buf[256];
        int i;

        if (!info)
            return;
        fprintf(info->file, "# stored time: %" PRIu64 "\n", ws_pae_current_time_get());
        // FIXME: It seems harmless, but entry->sec_keys_nw_info.pan_version and
        //        entry->sec_keys_nw_info.lpan_version are not set on wsnode.
        //        They could be replaced by ws_info.pan_information.pan_version
        //        and ws_info.pan_information.lpan_version
        fprintf(info->file, "pan_version = %d\n", entry->sec_keys_nw_info.pan_version);
        fprintf(info->file, "lpan_version = %d\n", entry->sec_keys_nw_info.lpan_version);
        for (i = 0; i < GTK_NUM; i++) {
            if (entry->gtks.frame_counters.counter[i].set) {
                str_key(entry->gtks.frame_counters.counter[i].gtk, GTK_LEN, str_buf, sizeof(str_buf));
                fprintf(info->file, "gtk[%d] = %s\n", i, str_buf);
                fprintf(info->file, "gtk[%d].frame_counter = %d\n", i,
                        entry->gtks.frame_counters.counter[i].frame_counter);
                fprintf(info->file, "gtk[%d].max_frame_counter = %d\n", i,
                        entry->gtks.frame_counters.counter[i].max_frame_counter_chg);
            }
        }
        for (i = 0; i < LGTK_NUM; i++) {
            if (entry->lgtks.frame_counters.counter[i].set) {
                str_key(entry->lgtks.frame_counters.counter[i].gtk, GTK_LEN, str_buf, sizeof(str_buf));
                fprintf(info->file, "lgtk[%d] = %s\n", i, str_buf);
                fprintf(info->file, "lgtk[%d].frame_counter = %d\n", i,
                        entry->lgtks.frame_counters.counter[i].frame_counter);
                fprintf(info->file, "lgtk[%d].max_frame_counter = %d\n", i,
                        entry->lgtks.frame_counters.counter[i].max_frame_counter_chg);
            }
        }
        storage_close(info);
    }
}

static int8_t ws_pae_controller_nvm_frame_counter_read(uint64_t *stored_time,
                                                       uint16_t *pan_version, uint16_t *lpan_version,
                                                       frame_counters_t *gtk_counters,
                                                       frame_counters_t *lgtk_counters)
{
    struct storage_parse_info *info = storage_open_prefix("counters", "r");
    int ret;

    if (!info)
        return -1;

    // Wednesday, January 1, 2020 0:00:00 GMT
    *stored_time = 1577836800;
    for (;;) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("pan_version", info->key, 0)) {
            *pan_version = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("lpan_version", info->key, 0)) {
            *lpan_version = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("gtk\\[*]", info->key, 0) && info->key_array_index < 4) {
            if (parse_byte_array(gtk_counters->counter[info->key_array_index].gtk, GTK_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                gtk_counters->counter[info->key_array_index].set = true;
        } else if (!fnmatch("lgtk\\[*]", info->key, 0) && info->key_array_index < 3) {
            if (parse_byte_array(lgtk_counters->counter[info->key_array_index].gtk, GTK_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                lgtk_counters->counter[info->key_array_index].set = true;
        } else if (!fnmatch("gtk\\[*].frame_counter", info->key, 0) && info->key_array_index < 4) {
            gtk_counters->counter[info->key_array_index].frame_counter = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("lgtk\\[*].frame_counter", info->key, 0) && info->key_array_index < 3) {
            lgtk_counters->counter[info->key_array_index].frame_counter = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("gtk\\[*].max_frame_counter", info->key, 0) && info->key_array_index < 4) {
            gtk_counters->counter[info->key_array_index].max_frame_counter_chg = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("lgtk\\[*].max_frame_counter", info->key, 0) && info->key_array_index < 3) {
            lgtk_counters->counter[info->key_array_index].max_frame_counter_chg = strtoul(info->value, NULL, 0);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);
    return 0;
}

static pae_controller_t *ws_pae_controller_get(struct net_if *interface_ptr)
{
    ns_list_foreach(pae_controller_t, entry, &pae_controller_list) {
        if (entry->interface_ptr == interface_ptr) {
            return entry;
        }
    }

    return NULL;
}

static pae_controller_t *ws_pae_controller_get_or_create(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        return NULL;
    }

    pae_controller_t *controller = ws_pae_controller_get(cur);

    if (!controller) {
        if (ws_pae_controller_init(cur) < 0) {
            return NULL;
        }
        controller = ws_pae_controller_get(cur);
    }

    return controller;
}

sec_prot_gtk_keys_t *ws_pae_controller_get_transient_keys(int8_t interface_id, bool is_lfn)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    pae_controller_t *controller = ws_pae_controller_get(cur);

    if (!cur)
        return NULL;
    if (!controller)
        return NULL;
    return is_lfn ? &controller->lgtks.gtks : &controller->gtks.gtks;
}
