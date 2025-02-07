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
#include "common/crypto/ws_keys.h"
#include "common/log.h"
#include "common/named_values.h"
#include "common/key_value_storage.h"
#include "common/parsers.h"
#include "common/log_legacy.h"
#include "common/memutils.h"
#include "common/ns_list.h"
#include "common/time_extra.h"

#include "net/ns_address.h"
#include "net/timers.h"
#include "net/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "ws/ws_config.h"
#include "ws/ws_common.h"
#include "ws/ws_mngt.h"
#include "ws/ws_pae_auth.h"
#include "ws/ws_pae_key_storage.h"

#include "ws/ws_pae_controller.h"

#define TRACE_GROUP "wspc"

typedef void ws_pae_timer(uint16_t ticks);
typedef void ws_pae_gtks_updated(struct net_if *interface_ptr, bool is_lgtk);
typedef int8_t ws_pae_gtk_hash_update(struct net_if *interface_ptr, gtkhash_t *gtkhash, bool del_gtk_on_mismatch);

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
    pae_controller_gtk_t gtks;                                       /**< Material for GTKs */
    pae_controller_gtk_t lgtks;                                       /**< Material for GTKs */
    sec_prot_keys_nw_info_t sec_keys_nw_info;                        /**< Security keys network information */
    sec_prot_certs_t certs;                                          /**< Certificates */
    uint16_t frame_cnt_store_timer;                                  /**< Timer to check if storing of frame counter value is needed */
    sec_cfg_t sec_cfg;                                               /**< Security configuration (configuration set values) */
    struct net_if *interface_ptr;                  /**< List link entry */
    ws_pae_controller_nw_key_set *nw_key_set;                        /**< Key set callback */
    ws_pae_controller_nw_send_key_index_set *nw_send_key_index_set;  /**< Send key index set callback */
    ws_pae_controller_pan_ver_increment *pan_ver_increment;          /**< PAN version increment callback */
    ws_pae_controller_pan_ver_increment *lpan_ver_increment;         /**< LFN-PAN version increment callback */
    ws_pae_controller_congestion_get *congestion_get;                /**< Congestion get callback */
    ws_pae_controller_ip_addr_get *ip_addr_get;                      /**< IP address get callback */
    ws_pae_timer *pae_fast_timer;                                    /**< PAE fast timer callback */
    ws_pae_timer *pae_slow_timer;                                    /**< PAE slow timer callback */
    ws_pae_gtks_updated *pae_gtks_updated;                           /**< PAE GTKs updated */
    ws_pae_gtk_hash_update *pae_gtk_hash_update;                     /**< PAE GTK HASH update */
    bool auth_started : 1;                                           /**< Authenticator has been started */
} pae_controller_t;

typedef struct pae_controller_config {
    sec_radius_cfg_t *radius_cfg;                                    /**< Radius configuration settings */
    uint16_t node_limit;                                             /**< Max number of stored supplicants */
    bool ext_cert_valid_enabled : 1;                                 /**< Extended certificate validation enabled */
} pae_controller_config_t;

static void ws_pae_controller_keys_nw_info_init(sec_prot_keys_nw_info_t *sec_keys_nw_info, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks);
static void ws_pae_controller_nw_info_updated_check(struct net_if *interface_ptr);
static void ws_pae_controller_auth_ip_addr_get(struct net_if *interface_ptr, uint8_t *address);
static bool ws_pae_controller_auth_congestion_get(struct net_if *interface_ptr);
static pae_controller_t *ws_pae_controller_get(const struct net_if *interface_ptr);
static pae_controller_t *ws_pae_controller_get_or_create(int8_t interface_id);
static int8_t ws_pae_controller_nw_key_check_and_insert(struct net_if *interface_ptr, sec_prot_gtk_keys_t *gtks, bool is_lgtk);
static void ws_pae_controller_gtk_hash_set(struct net_if *interface_ptr, gtkhash_t *gtkhash, bool is_lgtk);
static void ws_pae_controller_nw_key_index_check_and_set(struct net_if *interface_ptr, uint8_t index, bool is_lgtk);
static void ws_pae_controller_data_init(pae_controller_t *controller);
static void ws_pae_controller_frame_counter_reset(frame_counters_t *frame_counters);
static int8_t ws_pae_controller_nw_info_read(pae_controller_t *controller);
static int8_t ws_pae_controller_nvm_nw_info_write(const struct net_if *interface_ptr, const sec_prot_keys_nw_info_t *sec_keys_nw_info,
                                                  const frame_counters_t *gtk_frame_counters, const frame_counters_t *lgtk_frame_counters,
                                                  const uint8_t *gtk_eui64);
static int8_t ws_pae_controller_nvm_nw_info_read(struct net_if *interface_ptr, sec_prot_keys_nw_info_t *sec_keys_nw_info,
                                                 frame_counters_t *gtk_frame_counters, frame_counters_t *lgtk_frame_counters, uint8_t *gtk_eui64,
                                                 uint64_t current_time);

static NS_LIST_DEFINE(pae_controller_list, pae_controller_t, link);

pae_controller_config_t pae_controller_config = {
    .radius_cfg = NULL,
    .node_limit = 0,
    .ext_cert_valid_enabled = false
};

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

    ws_pae_auth_cb_register(interface_ptr,
                            ws_pae_controller_gtk_hash_set,
                            ws_pae_controller_nw_key_check_and_insert,
                            ws_pae_controller_nw_key_index_check_and_set,
                            ws_pae_controller_nw_info_updated_check,
                            ws_pae_controller_auth_ip_addr_get,
                            ws_pae_controller_auth_congestion_get);

    controller->auth_started = true;

    ws_pae_auth_start(interface_ptr);

    return 0;
}

void ws_pae_controller_cb_register(struct net_if *interface_ptr,
                                     ws_pae_controller_nw_key_set *nw_key_set,
                                     ws_pae_controller_nw_send_key_index_set *nw_send_key_index_set,
                                     ws_pae_controller_pan_ver_increment *pan_ver_increment,
                                     ws_pae_controller_pan_ver_increment *lpan_ver_increment,
                                     ws_pae_controller_congestion_get *congestion_get)
{
    BUG_ON(!interface_ptr);

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    BUG_ON(!controller);

    controller->nw_key_set = nw_key_set;
    controller->nw_send_key_index_set = nw_send_key_index_set;
    controller->pan_ver_increment = pan_ver_increment;
    controller->lpan_ver_increment = lpan_ver_increment;
    controller->congestion_get = congestion_get;
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

static void ws_pae_controller_keys_nw_info_init(sec_prot_keys_nw_info_t *sec_keys_nw_info, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks)
{
    if (!sec_keys_nw_info) {
        return;
    }

    memset(sec_keys_nw_info, 0, sizeof(sec_prot_keys_nw_info_t));

    sec_keys_nw_info->gtks = gtks;
    sec_keys_nw_info->lgtks = lgtks;
    sec_keys_nw_info->updated = false;
}

int8_t ws_pae_controller_network_name_set(struct net_if *interface_ptr, char *network_name)
{
    if (!interface_ptr) {
        return -1;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    if (network_name && strcmp(controller->sec_keys_nw_info.network_name, network_name) != 0) {
        strncpy(controller->sec_keys_nw_info.network_name, network_name, 32);
        controller->sec_keys_nw_info.updated = true;
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

    if (controller->sec_keys_nw_info.updated ||
        sec_prot_keys_gtks_are_updated(controller->sec_keys_nw_info.gtks)) {
        ws_pae_controller_nvm_nw_info_write(controller->interface_ptr, &controller->sec_keys_nw_info,
                                            &controller->gtks.frame_counters, &controller->lgtks.frame_counters,
                                            controller->interface_ptr->mac);
        controller->sec_keys_nw_info.updated = false;
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.gtks);
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.lgtks);
    }
}

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

static bool ws_pae_controller_auth_congestion_get(struct net_if *interface_ptr)
{
    if (!interface_ptr) {
        return 0;
    }

    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return 0;
    }

    return controller->congestion_get(interface_ptr);
}

void ws_pae_controller_nw_frame_counter_indication_cb(int8_t net_if_id, unsigned int gtk_index, uint32_t frame_counter)
{
    struct net_if *interface_ptr = protocol_stack_interface_info_get_by_id(net_if_id);
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);

    if (gtk_index >= GTK_NUM)
        controller->lgtks.frame_counters.counter[gtk_index - GTK_NUM].frame_counter = frame_counter;
    else
        controller->gtks.frame_counters.counter[gtk_index].frame_counter = frame_counter;

    ws_pae_controller_nvm_nw_info_write(controller->interface_ptr, &controller->sec_keys_nw_info,
                                        &controller->gtks.frame_counters, &controller->lgtks.frame_counters,
                                        controller->interface_ptr->mac);
}

static int8_t ws_pae_controller_nw_key_check_and_insert(struct net_if *interface_ptr, sec_prot_gtk_keys_t *gtks, bool is_lgtk)
{
    // Adds, removes and updates network keys to MAC based on new GTKs
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    frame_counters_t *frame_counters;
    uint32_t frame_counter;
    uint8_t gak[GTK_LEN];
    gtkhash_t gtkhash;
    nw_key_t *nw_key;
    int8_t ret = -1;
    int key_offset;
    uint8_t *gtk;

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
        gtk = sec_prot_keys_gtk_get(gtks, i);

        // If network key is set and GTK key is not set or not the same, removes network key
        if (nw_key[i].set && (!gtk || memcmp(nw_key[i].gtk, gtk, GTK_LEN) != 0)) {
            // Removes key from MAC if installed
            if (nw_key[i].installed)
                controller->nw_key_set(interface_ptr, i + key_offset + 1, NULL, 0);
            nw_key[i].installed = false;
            nw_key[i].set = false;
            tr_info("NW key remove: %i", i + key_offset);
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
        if (nw_key[i].installed)
            continue;

        sec_prot_keys_gtk_hash_generate(gtk, gtkhash);
        tr_info("NW key set: %i, hash: %s", i + key_offset, trace_array(gtkhash, 8));

        ws_generate_gak(controller->sec_keys_nw_info.network_name, gtk, gak);

        if (frame_counters->counter[i].set &&
            !memcmp(gtk, frame_counters->counter[i].gtk, GTK_LEN))
            frame_counter = frame_counters->counter[i].frame_counter;
        else
            frame_counter = 0;

        // Install the new network key derived from GTK and network name (GAK) to MAC
        controller->nw_key_set(interface_ptr, i + key_offset + 1, gak, frame_counter);
        nw_key[i].installed = true;
        ret = 0;
#ifdef EXTRA_DEBUG_INFO
        tr_info("NW name: %s", controller->sec_keys_nw_info.network_name);
        size_t nw_name_len = strlen(controller->sec_keys_nw_info.network_name);
        tr_info("NW name: %s", trace_array((uint8_t *)controller->sec_keys_nw_info.network_name, nw_name_len));
        tr_info("%s: %s", is_lgtk ? "LGTK" : "GTK", trace_array(gtk, 16));
        tr_info("%s: %s", is_lgtk ? "LGAK" : "GAK", trace_array(gak, 16));
        tr_info("Frame counter set: %i, value: %"PRIu32"", i + key_offset, frame_counter);
#endif
    }

    return ret;
}

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
        tr_info("NW send key index set: %i", index + key_offset);
        controller->nw_send_key_index_set(interface_ptr, index + key_offset);
    }

    // Do not update PAN version for initial key index set
    if (gtks->key_index_set) {
        if (!is_lgtk && controller->pan_ver_increment)
            controller->pan_ver_increment(&interface_ptr->ws_info);
        if (is_lgtk && controller->lpan_ver_increment)
            controller->lpan_ver_increment(&interface_ptr->ws_info);
    } else {
        gtks->key_index_set = true;
    }
}

void ws_pae_controller_init(struct net_if *interface_ptr)
{
    BUG_ON(!interface_ptr);

    if (ws_pae_controller_get(interface_ptr) != NULL)
        return;

    pae_controller_t *controller = xalloc(sizeof(pae_controller_t));
    controller->interface_ptr = interface_ptr;
    controller->nw_key_set = NULL;
    controller->nw_send_key_index_set = NULL;
    controller->pan_ver_increment = NULL;
    controller->congestion_get = NULL;

    memset(&controller->sec_cfg, 0, sizeof(sec_cfg_t));

    ws_pae_controller_data_init(controller);

    ns_list_add_to_end(&pae_controller_list, controller);
}

int8_t ws_pae_controller_configure(struct net_if *interface_ptr,
                                   const struct sec_timing *timing_ffn,
                                   const struct sec_timing *timing_lfn,
                                   const struct sec_prot_cfg *sec_prot_cfg)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (controller == NULL) {
        return 0;
    }

    if (sec_prot_cfg)
        controller->sec_cfg.prot_cfg = *sec_prot_cfg;

    BUG_ON(!timing_ffn);
    controller->sec_cfg.timing_ffn = *timing_ffn;
    BUG_ON(!timing_lfn);
    controller->sec_cfg.timing_lfn = *timing_lfn;

    controller->sec_cfg.radius_cfg = pae_controller_config.radius_cfg;
    return 0;
}

static void ws_pae_controller_data_init(pae_controller_t *controller)
{
    memset(controller->target_eui_64, 0, sizeof(controller->target_eui_64));
    memset(controller->gtks.gtkhash, 0, sizeof(controller->gtks.gtkhash));
    memset(controller->lgtks.gtkhash, 0, sizeof(controller->lgtks.gtkhash));
    memset(controller->gtks.nw_key, 0, sizeof(controller->gtks.nw_key));
    memset(controller->lgtks.nw_key, 0, sizeof(controller->lgtks.nw_key));

    controller->target_pan_id = 0xffff;
    controller->pae_fast_timer = NULL;
    controller->pae_slow_timer = NULL;
    controller->pae_gtks_updated = NULL;
    controller->pae_gtk_hash_update = NULL;
    controller->gtks.gtks_set = false;
    controller->gtks.gtkhash_set = false;
    controller->gtks.key_index_set = false;
    controller->lgtks.gtks_set = false;
    controller->lgtks.gtkhash_set = false;
    controller->lgtks.key_index_set = false;
    controller->gtks.gtk_index = -1;
    controller->lgtks.gtk_index = -1;
    controller->auth_started = false;
    ws_pae_controller_frame_counter_reset(&controller->gtks.frame_counters);
    ws_pae_controller_frame_counter_reset(&controller->lgtks.frame_counters);
    memset(&controller->gtks.gtks, 0, sizeof(sec_prot_gtk_keys_t));
    memset(&controller->lgtks.gtks, 0, sizeof(sec_prot_gtk_keys_t));
    memset(&controller->gtks.next_gtks, 0, sizeof(sec_prot_gtk_keys_t));
    memset(&controller->lgtks.next_gtks, 0, sizeof(sec_prot_gtk_keys_t));
    sec_prot_certs_init(&controller->certs);
    sec_prot_certs_ext_certificate_validation_set(&controller->certs, pae_controller_config.ext_cert_valid_enabled);
    ws_pae_controller_keys_nw_info_init(&controller->sec_keys_nw_info, &controller->gtks.gtks, &controller->lgtks.gtks);
}

static void ws_pae_controller_frame_counter_reset(frame_counters_t *frame_counters)
{
    for (uint8_t index = 0; index < GTK_NUM; index++)
        memset(&frame_counters->counter[index], 0, sizeof(frame_counters->counter[index]));
}

static int8_t ws_pae_controller_nw_info_read(pae_controller_t *controller)
{
    uint8_t nvm_gtk_eui64[8];
    uint64_t system_time = time_now_s(CLOCK_REALTIME);

    if (ws_pae_controller_nvm_nw_info_read(controller->interface_ptr, &controller->sec_keys_nw_info, &controller->gtks.frame_counters,
                                           &controller->lgtks.frame_counters, nvm_gtk_eui64, system_time) < 0) {
        // If no stored GTKs and network info (pan_id and network name) exits
        return -1;
    }

    /* Get own EUI-64 and compare to the one read from the NVM. In case of mismatch delete GTKs and make
       full authentication to update keys with new EUI-64 and in case of authenticator to update new
       authenticator EUI-64 to the network. */
    if (memcmp(nvm_gtk_eui64, controller->interface_ptr->mac, 8) != 0) {
        WARN("NVM EUI-64 mismatch, current: %s stored: %s", tr_eui64(controller->interface_ptr->mac), tr_eui64(nvm_gtk_eui64));
        memset(controller->sec_keys_nw_info.gtks, 0, sizeof(sec_prot_gtk_keys_t));
        memset(controller->sec_keys_nw_info.lgtks, 0, sizeof(sec_prot_gtk_keys_t));
    } else {
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

                tr_info("Read GTK frame counter: index %i value %"PRIu32"", index, controller->gtks.frame_counters.counter[index].frame_counter);
            }
            if (index >= LGTK_NUM)
                continue;
            if (controller->lgtks.frame_counters.counter[index].set) {
                // If there is room on frame counter space
                if (controller->lgtks.frame_counters.counter[index].frame_counter < (UINT32_MAX - FRAME_COUNTER_INCREMENT * 2)) {
                    // Increments frame counters
                    controller->lgtks.frame_counters.counter[index].frame_counter += FRAME_COUNTER_INCREMENT;
                } else {
                    tr_error("Frame counter space exhausted");
                    controller->lgtks.frame_counters.counter[index].frame_counter = UINT32_MAX;
                }

                tr_info("Read LGTK frame counter: index %i value %"PRIu32"", index, controller->lgtks.frame_counters.counter[index].frame_counter);
            }
        }
    }

    return 0;
}

const struct name_value valid_gtk_status[] = {
    { "new",    GTK_STATUS_NEW    },
    { "fresh",  GTK_STATUS_FRESH  },
    { "active", GTK_STATUS_ACTIVE },
    { "old",    GTK_STATUS_OLD    },
    { NULL },
};

static int8_t ws_pae_controller_nvm_nw_info_write(const struct net_if *interface_ptr, const sec_prot_keys_nw_info_t *sec_keys_nw_info,
                                                  const frame_counters_t *gtk_frame_counters, const frame_counters_t *lgtk_frame_counters,
                                                  const uint8_t *gtk_eui64)
{
    unsigned long long current_time = time_now_s(CLOCK_REALTIME);
    struct storage_parse_info *info = storage_open_prefix("network-keys", "w");
    sec_prot_gtk_keys_t *gtks = sec_keys_nw_info->gtks;
    sec_prot_gtk_keys_t *lgtks = sec_keys_nw_info->lgtks;
    uint8_t gtk_hash[GTK_HASH_LEN];
    uint8_t gak[GTK_LEN];
    char str_buf[256];
    int i;

    if (!info)
        return -1;
    str_key(gtk_eui64, 8, str_buf, sizeof(str_buf));
    fprintf(info->file, "eui64 = %s\n", str_buf);
    fprintf(info->file, "# For information:\n");
    str_bytes(sec_keys_nw_info->network_name, strlen(sec_keys_nw_info->network_name),
              NULL, str_buf, sizeof(str_buf), FMT_ASCII_ALNUM);
    fprintf(info->file, "#network_name = %s\n", str_buf);
    for (i = 0; i < GTK_NUM; i++) {
        if (gtks && gtks->gtk[i].set) {
            fprintf(info->file, "\n");
            sec_prot_keys_gtk_hash_generate(gtks->gtk[i].key, gtk_hash);
            ws_generate_gak(sec_keys_nw_info->network_name, gtks->gtk[i].key, gak);
            str_key(gtks->gtk[i].key, GTK_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "gtk[%d] = %s\n", i, str_buf);
            fprintf(info->file, "gtk[%d].lifetime = %llu\n", i, gtks->gtk[i].lifetime + current_time);
            fprintf(info->file, "gtk[%d].status = %s\n", i, val_to_str(gtks->gtk[i].status, valid_gtk_status, NULL));
            fprintf(info->file, "gtk[%d].install_order = %u\n", i, gtks->gtk[i].install_order);
            fprintf(info->file, "gtk[%d].frame_counter = %u\n", i, gtk_frame_counters->counter[i].frame_counter);
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
            ws_generate_gak(sec_keys_nw_info->network_name, lgtks->gtk[i].key, gak);
            str_key(lgtks->gtk[i].key, GTK_LEN, str_buf, sizeof(str_buf));
            fprintf(info->file, "lgtk[%d] = %s\n", i, str_buf);
            fprintf(info->file, "lgtk[%d].lifetime = %llu\n", i, lgtks->gtk[i].lifetime + current_time);
            fprintf(info->file, "lgtk[%d].status = %s\n", i, val_to_str(lgtks->gtk[i].status, valid_gtk_status, NULL));
            fprintf(info->file, "lgtk[%d].install_order = %u\n", i, lgtks->gtk[i].install_order);
            fprintf(info->file, "lgtk[%d].frame_counter = %u\n", i, lgtk_frame_counters->counter[i].frame_counter);
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

static int8_t ws_pae_controller_nvm_nw_info_read(struct net_if *interface_ptr, sec_prot_keys_nw_info_t *sec_keys_nw_info,
                                                 frame_counters_t *gtk_frame_counters, frame_counters_t *lgtk_frame_counters,
                                                 uint8_t *gtk_eui64, uint64_t current_time)
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
        } else if (!fnmatch("gtk\\[*].frame_counter", info->key, 0) && info->key_array_index < 4) {
            gtk_frame_counters->counter[info->key_array_index].frame_counter = strtoul(info->value, NULL, 0);
            gtk_frame_counters->counter[info->key_array_index].set = true;
        } else if (!fnmatch("lgtk\\[*].frame_counter", info->key, 0) && info->key_array_index < 3) {
            lgtk_frame_counters->counter[info->key_array_index].frame_counter = strtoul(info->value, NULL, 0);
            lgtk_frame_counters->counter[info->key_array_index].set = true;
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);

    for (i = 0; i < GTK_NUM; i++) {
        if (!new_gtks[i].set || !new_gtks[i].lifetime || !gtk_frame_counters->counter[i].set)
            continue;
        if (sec_keys_nw_info->gtks->gtk[i].set)
            FATAL(1, "GTK out-of-date in storage (see -D)");
        memcpy(&sec_keys_nw_info->gtks->gtk[i], &new_gtks[i], sizeof(new_gtks[i]));
        memcpy(gtk_frame_counters->counter[i].gtk, new_gtks[i].key, sizeof(new_gtks[i].key));
    }
    for (i = 0; i < LGTK_NUM; i++) {
        if (!new_lgtks[i].set || !new_lgtks[i].lifetime || !lgtk_frame_counters->counter[i].set)
            continue;
        if (sec_keys_nw_info->lgtks->gtk[i].set)
            FATAL(1, "LGTK out-of-date in storage (see -D)");
        memcpy(&sec_keys_nw_info->lgtks->gtk[i], &new_lgtks[i], sizeof(new_lgtks[i]));
        memcpy(lgtk_frame_counters->counter[i].gtk, new_lgtks[i].key, sizeof(new_lgtks[i].key));
    }
    return 0;
}

int8_t ws_pae_controller_auth_init(struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return -1;
    }

    ws_pae_auth_init(controller->interface_ptr,
                     &controller->gtks.next_gtks,
                     &controller->lgtks.next_gtks,
                     &controller->certs,
                     &controller->sec_cfg,
                     &controller->sec_keys_nw_info,
                     &controller->gtks.frame_counters,
                     &controller->lgtks.frame_counters);

    controller->pae_fast_timer = ws_pae_auth_fast_timer;
    controller->pae_slow_timer = ws_pae_auth_slow_timer;
    controller->pae_gtks_updated = ws_pae_auth_gtks_updated;

    ws_pae_controller_nw_info_read(controller);
    if (sec_prot_keys_gtks_are_updated(controller->sec_keys_nw_info.gtks)) {
        // If application has set GTK keys prepare those for use
        ws_pae_auth_gtks_updated(interface_ptr, false);
        if (controller->gtks.gtk_index >= 0) {
            ws_pae_auth_nw_key_index_update(interface_ptr, controller->gtks.gtk_index, false);
        }
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.gtks);
    }
    if (sec_prot_keys_gtks_are_updated(controller->sec_keys_nw_info.lgtks)) {
        // If application has set LGTK keys prepare those for use
        ws_pae_auth_gtks_updated(interface_ptr, true);
        if (controller->lgtks.gtk_index >= 0) {
            ws_pae_auth_nw_key_index_update(interface_ptr, controller->lgtks.gtk_index, true);
        }
        sec_prot_keys_gtks_updated_reset(controller->sec_keys_nw_info.lgtks);
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

    controller->sec_cfg.radius_cfg = pae_controller_config.radius_cfg;
    ws_pae_auth_radius_address_set(controller->interface_ptr, address);
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
    if (controller)
        controller->sec_cfg.radius_cfg = pae_controller_config.radius_cfg;

    return 0;
}

int8_t ws_pae_controller_gtk_update(int8_t interface_id, const uint8_t *gtk[GTK_NUM])
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
            lifetime += controller->sec_cfg.timing_ffn.expire_offset;
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

int8_t ws_pae_controller_lgtk_update(int8_t interface_id, const uint8_t *lgtk[LGTK_NUM])
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
            lifetime += controller->sec_cfg.timing_lfn.expire_offset;
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

int8_t ws_pae_controller_node_keys_remove(int8_t interface_id, const uint8_t eui_64[8])
{
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
            controller->pan_ver_increment(&interface_ptr->ws_info);
        }
        if (is_lgtk && controller->lpan_ver_increment) {
            controller->lpan_ver_increment(&interface_ptr->ws_info);
        }
    } else {
        gtk_struct->gtkhash_set = true;
    }
    if (is_lgtk)
        ws_mngt_lpc_pae_cb(&interface_ptr->ws_info);
}

const gtkhash_t *ws_pae_controller_gtk_hash_ptr_get(const struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return NULL;
    }

    return controller->gtks.gtkhash;
}

const gtkhash_t *ws_pae_controller_lgtk_hash_ptr_get(const struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return NULL;
    }

    return controller->lgtks.gtkhash;
}

int8_t ws_pae_controller_lgtk_active_index_get(const struct net_if *interface_ptr)
{
    pae_controller_t *controller = ws_pae_controller_get(interface_ptr);
    if (!controller) {
        return 0;
    }

    return controller->lgtks.gtk_index;
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
    }
}

static pae_controller_t *ws_pae_controller_get(const struct net_if *interface_ptr)
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
        ws_pae_controller_init(cur);
        controller = ws_pae_controller_get(cur);
    }

    return controller;
}

const sec_prot_gtk_keys_t *ws_pae_controller_get_transient_keys(int8_t interface_id, bool is_lfn)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    pae_controller_t *controller = ws_pae_controller_get(cur);

    if (!cur)
        return NULL;
    if (!controller)
        return NULL;
    return is_lfn ? &controller->lgtks.gtks : &controller->gtks.gtks;
}
