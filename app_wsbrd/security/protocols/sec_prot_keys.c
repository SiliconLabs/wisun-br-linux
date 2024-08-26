/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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
#include "common/bits.h"
#include "common/string_extra.h"
#include "common/ns_list.h"
#include "common/specs/ws.h"

#include "net/protocol.h"
#include "common/specs/ipv6.h"
#include "ws/ws_config.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/kmp/kmp_addr.h"
#include "security/kmp/kmp_api.h"
#include "security/pana/pana_eap_header.h"
#include "security/eapol/eapol_helper.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot.h"
#include "security/protocols/sec_prot_lib.h"

#include "security/protocols/sec_prot_keys.h"

void sec_prot_keys_init(sec_prot_keys_t *sec_keys, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks, const sec_prot_certs_t *certs)
{
    memset(sec_keys, 0, sizeof(sec_prot_keys_t));
    sec_keys->pmk_lifetime = 0;
    sec_keys->ptk_lifetime = 0;
    sec_keys->pmk_key_replay_cnt = 0;
    sec_keys->gtks.keys = gtks;
    sec_keys->lgtks.keys = lgtks;
    sec_keys->certs = certs;
    sec_keys->gtks.gtkl = 0;
    sec_keys->gtks.gtk_set_index = -1;
    sec_keys->lgtks.gtkl = 0;
    sec_keys->lgtks.gtk_set_index = -1;
    sec_keys->pmk_set = false;
    sec_keys->ptk_set = false;
    sec_keys->pmk_key_replay_cnt_set = false;
    sec_keys->updated = false;
    sec_keys->ptk_eui_64_set = false;
    sec_keys->pmk_mismatch = false;
    sec_keys->ptk_mismatch = false;
    sec_keys->node_role = WS_NR_ROLE_UNKNOWN;
    sec_prot_keys_ptk_installed_gtk_hash_clear_all(&sec_keys->gtks);
    sec_prot_keys_ptk_installed_gtk_hash_clear_all(&sec_keys->lgtks);
}

void sec_prot_keys_pmk_write(sec_prot_keys_t *sec_keys, uint8_t *pmk, uint32_t pmk_lifetime)
{
    memcpy(sec_keys->pmk, pmk, PMK_LEN);
    sec_keys->pmk_key_replay_cnt = 0;
    sec_keys->pmk_key_replay_cnt_set = false;
    sec_keys->pmk_lifetime = pmk_lifetime;
    sec_keys->pmk_set = true;
    sec_keys->updated = true;
}

void sec_prot_keys_pmk_delete(sec_prot_keys_t *sec_keys)
{
    if (sec_keys->pmk_key_replay_cnt != 0 || sec_keys->pmk_key_replay_cnt_set ||
            sec_keys->pmk_lifetime != 0 || sec_keys->pmk_set) {
        sec_keys->updated = true;
    }
    memset(sec_keys->pmk, 0, PMK_LEN);
    sec_keys->pmk_key_replay_cnt = 0;
    sec_keys->pmk_key_replay_cnt_set = false;
    sec_keys->pmk_lifetime = 0;
    sec_keys->pmk_set = false;
}

uint8_t *sec_prot_keys_pmk_get(sec_prot_keys_t *sec_keys)
{
    if (!sec_keys->pmk_set) {
        return NULL;
    }

    return sec_keys->pmk;
}

uint64_t sec_prot_keys_pmk_replay_cnt_get(sec_prot_keys_t *sec_keys)
{
    return sec_keys->pmk_key_replay_cnt;
}

bool sec_prot_keys_pmk_replay_cnt_increment(sec_prot_keys_t *sec_keys)
{
    // Start from zero i.e. does not increment on first call
    if (!sec_keys->pmk_key_replay_cnt_set) {
        sec_keys->pmk_key_replay_cnt_set = true;
        return true;
    }
    // If counter is near to exhaust return error (ignores MSB 32bits which are re-start counter)
    if ((sec_keys->pmk_key_replay_cnt & PMK_KEY_REPLAY_CNT_LIMIT_MASK) > PMK_KEY_REPLAY_CNT_LIMIT) {
        sec_keys->pmk_key_replay_cnt |= 0xFFFF; // Invalidate counter; will result removal of keys
        return false;
    }
    sec_keys->pmk_key_replay_cnt++;
    return true;
}

void sec_prot_keys_pmk_mismatch_set(sec_prot_keys_t *sec_keys)
{
    sec_keys->pmk_mismatch = true;
}

void sec_prot_keys_pmk_mismatch_reset(sec_prot_keys_t *sec_keys)
{
    sec_keys->pmk_mismatch = false;
}

bool sec_prot_keys_pmk_mismatch_is_set(sec_prot_keys_t *sec_keys)
{
    return sec_keys->pmk_mismatch;
}

bool sec_prot_keys_pmk_lifetime_decrement(sec_prot_keys_t *sec_keys, uint8_t seconds)
{
    if (!sec_keys->pmk_set) {
        return false;
    }

    if (sec_keys->pmk_lifetime > seconds) {
        sec_keys->pmk_lifetime -= seconds;
    } else {
        if (sec_keys->pmk_lifetime > 0) {
            sec_keys->pmk_lifetime = 0;
            sec_prot_keys_ptk_delete(sec_keys);
            sec_prot_keys_pmk_delete(sec_keys);
            return true;
        }
    }
    return false;
}

void sec_prot_keys_ptk_write(sec_prot_keys_t *sec_keys, uint8_t *ptk, uint32_t ptk_lifetime)
{
    memcpy(sec_keys->ptk, ptk, PTK_LEN);
    sec_keys->ptk_lifetime = ptk_lifetime;
    sec_keys->ptk_set = true;
    sec_keys->updated = true;
}

void sec_prot_keys_ptk_delete(sec_prot_keys_t *sec_keys)
{
    if (sec_keys->ptk_lifetime != 0 || sec_keys->ptk_set) {
        sec_keys->updated = true;
    }
    memset(sec_keys->ptk, 0, PTK_LEN);
    sec_keys->ptk_lifetime = 0;
    sec_keys->ptk_set = false;
}

uint8_t *sec_prot_keys_ptk_get(sec_prot_keys_t *sec_keys)
{
    if (!sec_keys->ptk_set) {
        return NULL;
    }

    return sec_keys->ptk;
}

void sec_prot_keys_ptk_mismatch_set(sec_prot_keys_t *sec_keys)
{
    sec_keys->ptk_mismatch = true;
}

void sec_prot_keys_ptk_mismatch_reset(sec_prot_keys_t *sec_keys)
{
    sec_keys->ptk_mismatch = false;
}

bool sec_prot_keys_ptk_mismatch_is_set(sec_prot_keys_t *sec_keys)
{
    return sec_keys->ptk_mismatch;
}

void sec_prot_keys_ptk_eui_64_write(sec_prot_keys_t *sec_keys, const uint8_t *eui_64)
{
    memcpy(sec_keys->ptk_eui_64, eui_64, 8);
    sec_keys->ptk_eui_64_set = true;
    sec_keys->updated = true;
}

uint8_t *sec_prot_keys_ptk_eui_64_get(sec_prot_keys_t *sec_keys)
{
    if (!sec_keys->ptk_eui_64_set) {
        return NULL;
    }

    return sec_keys->ptk_eui_64;
}

bool sec_prot_keys_ptk_lifetime_decrement(sec_prot_keys_t *sec_keys, uint8_t seconds)
{
    if (!sec_keys->ptk_set) {
        return false;
    }

    if (sec_keys->ptk_lifetime > seconds) {
        sec_keys->ptk_lifetime -= seconds;
    } else {
        if (sec_keys->ptk_lifetime > 0) {
            sec_prot_keys_ptk_delete(sec_keys);
            sec_keys->ptk_lifetime = 0;
            return true;
        }
    }
    return false;
}

uint8_t sec_prot_keys_fresh_gtkl_get(sec_prot_gtk_keys_t *gtks)
{
    uint8_t gtkl = 0;

    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_status_is_live(gtks, i)) {
            gtkl |= BIT(i);
        }
    }

    return gtkl;
}

bool sec_prot_keys_gtkl_gtk_is_live(sec_prot_gtk_t *sec_gtks, uint8_t index)
{
    if (index >= GTK_NUM) {
        return false;
    }

    if (sec_gtks->gtkl & BIT(index)) {
        return true;
    }

    return false;
}

int8_t sec_prot_keys_gtkl_gtk_live_set(sec_prot_gtk_t *sec_gtks, uint8_t index)
{
    if (index >= GTK_NUM) {
        return -1;
    }

    sec_gtks->gtkl |= BIT(index);

    return 0;
}

int8_t sec_prot_keys_gtk_insert_index_set(sec_prot_gtk_t *sec_gtks, uint8_t index)
{
    if (index >= GTK_NUM || !sec_gtks->keys->gtk[index].set) {
        return -1;
    }

    sec_gtks->gtk_set_index = index;
    return 0;
}

int8_t sec_prot_keys_gtk_insert_index_get(sec_prot_gtk_t *sec_gtks)
{
    return sec_gtks->gtk_set_index;
}

void sec_prot_keys_gtk_insert_index_clear(sec_prot_gtk_t *sec_gtks)
{
    sec_gtks->gtk_set_index = -1;
}

void sec_prot_keys_gtkl_from_gtk_insert_index_set(sec_prot_gtk_t *sec_gtks)
{
    if (sec_gtks->gtk_set_index >= 0) {
        sec_prot_keys_gtkl_gtk_live_set(sec_gtks, sec_gtks->gtk_set_index);
        sec_prot_keys_gtk_insert_index_clear(sec_gtks);
    }
}

int8_t sec_prot_keys_gtk_insert_index_from_gtkl_get(sec_prot_gtk_t *sec_gtks)
{
    // Get currently active key index
    int8_t active_index = sec_prot_keys_gtk_status_active_get(sec_gtks->keys);

    if (active_index >= 0 && !sec_prot_keys_gtkl_gtk_is_live(sec_gtks, active_index)) {
        // If currently active key is not live on remote, inserts it
        sec_prot_keys_gtk_insert_index_set(sec_gtks, active_index);
        return active_index;
    }

    // Checks all keys
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_status_is_live(sec_gtks->keys, i) ||
                sec_prot_keys_gtk_status_get(sec_gtks->keys, i) == GTK_STATUS_OLD) {
            /* If key is live, but not indicated on GTKL inserts it. Also old keys indicated
               still on GTK hash are inserted, since supplicants do not know the status of the
               key and might need the key for receive (only) from not updated neighbors  */
            if (!sec_prot_keys_gtkl_gtk_is_live(sec_gtks, i)) {
                sec_prot_keys_gtk_insert_index_set(sec_gtks, i);
                return i;
            }
        }
    }

    return -1;
}

uint8_t *sec_prot_keys_get_gtk_to_insert(sec_prot_gtk_t *sec_gtks, uint8_t *index)
{
    if (sec_gtks->gtk_set_index >= 0 && sec_gtks->keys->gtk[sec_gtks->gtk_set_index].set) {
        *index = sec_gtks->gtk_set_index;
        return sec_gtks->keys->gtk[sec_gtks->gtk_set_index].key;
    } else {
        return NULL;
    }
}

int8_t sec_prot_keys_gtk_set(sec_prot_gtk_keys_t *gtks, uint8_t index, const uint8_t gtk[GTK_LEN], uint32_t lifetime)
{
    if (!gtk || index >= GTK_NUM) {
        return -1;
    }

    // If same GTK is given again, do not update
    if (gtks->gtk[index].set && memcmp(gtks->gtk[index].key, gtk, GTK_LEN) == 0) {
        return -1;
    }

    sec_prot_keys_gtk_clear(gtks, index);
    uint8_t install_order = sec_prot_keys_gtk_install_order_last_get(gtks);

    gtks->gtk[index].set = true;
    gtks->gtk[index].lifetime = lifetime;
    gtks->gtk[index].status = GTK_STATUS_NEW;
    gtks->gtk[index].install_order = install_order;
    memcpy(gtks->gtk[index].key, gtk, GTK_LEN);

    gtks->updated = true;

    return 0;
}

int8_t sec_prot_keys_gtk_clear(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (!gtks || index >= GTK_NUM) {
        return -1;
    }

    gtks->gtk[index].set = false;
    gtks->gtk[index].lifetime = 0;   // Should be provided by authenticator
    gtks->gtk[index].status = GTK_STATUS_NEW;
    memset(gtks->gtk[index].key, 0, GTK_LEN);

    gtks->updated = true;

    sec_prot_keys_gtk_install_order_update(gtks);

    return 0;
}

bool sec_prot_keys_gtk_is_set(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return false;
    }

    return true;
}

uint8_t *sec_prot_keys_gtk_get(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return NULL;
    }

    return gtks->gtk[index].key;
}

uint32_t sec_prot_keys_gtk_lifetime_get(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return 0;
    }

    return gtks->gtk[index].lifetime;
}

uint32_t sec_prot_keys_gtk_lifetime_decrement(sec_prot_gtk_keys_t *gtks, uint8_t index, uint64_t current_time, uint32_t seconds, bool gtk_update_enable)
{
    if (gtks->gtk[index].lifetime > seconds) {
        gtks->gtk[index].lifetime -= seconds;
    } else {
        gtks->gtk[index].lifetime = 0;
    }

    return gtks->gtk[index].lifetime;
}

bool sec_prot_keys_gtks_are_updated(sec_prot_gtk_keys_t *gtks)
{
    return gtks->updated;
}

void sec_prot_keys_gtks_updated_reset(sec_prot_gtk_keys_t *gtks)
{
    gtks->updated = false;
}

void sec_prot_keys_gtk_status_fresh_set(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return;
    }

    // Active key remains as active, old keys are never reused
    if (gtks->gtk[index].status < GTK_STATUS_FRESH) {
        gtks->gtk[index].status = GTK_STATUS_FRESH;
        gtks->updated = true;
    }
}

void sec_prot_keys_gtk_status_all_fresh_set(sec_prot_gtk_keys_t *gtks)
{
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        sec_prot_keys_gtk_status_fresh_set(gtks, i);
    }
}

int8_t sec_prot_keys_gtk_status_active_set(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return -1;
    }

    // If key is valid to be taken into use sets it active
    if (gtks->gtk[index].status == GTK_STATUS_FRESH) {
        // Sets previously active key old
        for (uint8_t i = 0; i < GTK_NUM; i++) {
            // Sets previously active key old
            if (gtks->gtk[i].status == GTK_STATUS_ACTIVE) {
                gtks->gtk[i].status = GTK_STATUS_OLD;
                gtks->updated = true;
            }
        }
        gtks->gtk[index].status = GTK_STATUS_ACTIVE;
        /* Changing fresh to active does not change the gtks updated state since active
           keys are set to fresh on nvm read on startup */
        return 0;
    }

    return -1;
}

int8_t sec_prot_keys_gtk_status_active_get(sec_prot_gtk_keys_t *gtks)
{
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (gtks->gtk[i].status == GTK_STATUS_ACTIVE) {
            return i;
        }
    }

    return -1;
}

bool sec_prot_keys_gtk_status_is_live(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return false;
    }

    if (gtks->gtk[index].status == GTK_STATUS_FRESH || gtks->gtk[index].status == GTK_STATUS_ACTIVE) {
        return true;
    }

    return false;
}

void sec_prot_keys_gtk_status_new_set(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return;
    }

    if (gtks->gtk[index].status != GTK_STATUS_NEW) {
        gtks->updated = true;
    }

    gtks->gtk[index].status = GTK_STATUS_NEW;
}

uint8_t sec_prot_keys_gtk_status_get(sec_prot_gtk_keys_t *gtks, uint8_t index)
{
    if (index >= GTK_NUM || !gtks->gtk[index].set) {
        return 0;
    }

    return gtks->gtk[index].status;
}

void sec_prot_keys_gtks_hash_generate(sec_prot_gtk_keys_t *gtks, gtkhash_t *gtkhash)
{
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            uint8_t *gtk = sec_prot_keys_gtk_get(gtks, i);
            sec_prot_lib_gtkhash_generate(gtk, gtkhash[i]);
        } else {
            memset(gtkhash[i], 0, 8);
        }
    }
}

int8_t sec_prot_keys_gtk_hash_generate(uint8_t *gtk, uint8_t *gtk_hash)
{
    return sec_prot_lib_gtkhash_generate(gtk, gtk_hash);
}

int8_t sec_prot_keys_gtk_valid_check(uint8_t *gtk)
{
    gtkhash_t gtk_hash;
    sec_prot_lib_gtkhash_generate(gtk, gtk_hash);

    // Checks if GTK hash for the GTK would be all zero
    if (memzcmp(gtk_hash, sizeof(gtk_hash)) == 0) {
        return -1;
    }

    return 0;
}

int8_t sec_prot_keys_gtk_install_order_last_get(sec_prot_gtk_keys_t *gtks)
{
    int8_t install_order = -1;

    // Gets the last key index
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            if (gtks->gtk[i].install_order > install_order) {
                install_order = gtks->gtk[i].install_order;
            }
        }
    }

    return install_order + 1;
}

int8_t sec_prot_keys_gtk_install_order_last_index_get(sec_prot_gtk_keys_t *gtks)
{
    int8_t install_order = -1;
    int8_t index = -1;

    // Gets the last key index
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            if (gtks->gtk[i].install_order > install_order) {
                install_order = gtks->gtk[i].install_order;
                index = i;
            }
        }
    }

    return index;
}

uint32_t sec_prot_keys_gtk_install_order_last_lifetime_get(sec_prot_gtk_keys_t *gtks)
{
    uint32_t lifetime = 0;
    int8_t install_order = -1;

    // Gets the last key index
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            if (gtks->gtk[i].install_order > install_order) {
                install_order = gtks->gtk[i].install_order;
                lifetime = gtks->gtk[i].lifetime;
            }
        }
    }

    return lifetime;
}

int8_t sec_prot_keys_gtk_install_order_first_index_get(sec_prot_gtk_keys_t *gtks)
{
    // Gets the first key index
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            if (gtks->gtk[i].install_order == GTK_INSTALL_ORDER_FIRST) {
                return i;
            }
        }
    }

    return -1;
}

int8_t sec_prot_keys_gtk_install_order_second_index_get(sec_prot_gtk_keys_t *gtks)
{
    // Gets the first key index
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            if (gtks->gtk[i].install_order == GTK_INSTALL_ORDER_SECOND) {
                return i;
            }
        }
    }

    return -1;
}

void sec_prot_keys_gtk_install_order_update(sec_prot_gtk_keys_t *gtks)
{
    int8_t ordered_indexes[4] = {-1, -1, -1, -1};

    // Creates table of ordered indexes
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (sec_prot_keys_gtk_is_set(gtks, i)) {
            ordered_indexes[gtks->gtk[i].install_order] = i;
        }
    }

    // Updates indexes of the GTKs
    uint8_t new_install_order = 0;
    for (uint8_t i = 0; i < GTK_NUM; i++) {
        if (ordered_indexes[i] >= 0) {
            if (gtks->gtk[ordered_indexes[i]].install_order != new_install_order) {
                gtks->updated = true;
            }
            gtks->gtk[ordered_indexes[i]].install_order = new_install_order++;
        }
    }
}

int8_t sec_prot_keys_gtk_install_index_get(sec_prot_gtk_keys_t *gtks, bool is_lgtk)
{
    // Gets the index of the last key to be installed
    int8_t install_index = sec_prot_keys_gtk_install_order_last_index_get(gtks);
    int num_keys = is_lgtk ? LGTK_NUM : GTK_NUM;

    if (install_index < 0) {
        install_index = 0;
    }

    // Checks if there is free index, and available uses that for new GTK
    for (uint8_t ctr = 0, i = install_index; ctr < num_keys; ctr++) {
        if (!sec_prot_keys_gtk_is_set(gtks, i)) {
            install_index = i;
            break;
        }
        i++;
        if (i >= num_keys) {
            i = 0;
        }
    }

    return install_index;
}

void sec_prot_keys_ptk_installed_gtk_hash_clear_all(sec_prot_gtk_t *sec_gtks)
{
    for (uint8_t index = 0; index < GTK_NUM; index++) {
        memset(sec_gtks->ins_gtk_hash[index].hash, 0, INS_GTK_HASH_LEN);
    }
    sec_gtks->ins_gtk_hash_set = 0;
}

void sec_prot_keys_ptk_installed_gtk_hash_set(sec_prot_gtk_t *sec_gtks, bool is_4wh)
{
    if (sec_gtks->gtk_set_index >= 0) {
        uint8_t *gtk = sec_prot_keys_gtk_get(sec_gtks->keys, sec_gtks->gtk_set_index);
        if (!gtk) {
            return;
        }
        uint8_t gtk_hash[GTK_HASH_LEN];
        if (sec_prot_keys_gtk_hash_generate(gtk, gtk_hash) < 0) {
            return;
        }
        /* Store two byte hash. This is long enough for the GTK installed check, since
         * possible conflict between hashes causes only that 4WH is initiated/is not
         * initiated instead of GKH.
         */
        memcpy(sec_gtks->ins_gtk_hash[sec_gtks->gtk_set_index].hash, gtk_hash, INS_GTK_HASH_LEN);
        sec_gtks->ins_gtk_hash_set |= BIT(sec_gtks->gtk_set_index);
    }
}

bool sec_prot_keys_ptk_installed_gtk_hash_mismatch_check(sec_prot_gtk_t *sec_gtks, uint8_t gtk_index)
{
    // If not set or the key has been inserted by 4WH then there is no mismatch
    if ((sec_gtks->ins_gtk_hash_set & BIT(sec_gtks->gtk_set_index)) == 0 ||
        (sec_gtks->ins_gtk_hash_set & BIT(sec_gtks->gtk_set_index)) == 1) {
        return false;
    }

    uint8_t *gtk = sec_prot_keys_gtk_get(sec_gtks->keys, gtk_index);
    if (!gtk) {
        return false;
    }

    // Calculated GTK hash for the current GTK on the defined index
    uint8_t gtk_hash[GTK_HASH_LEN];
    if (sec_prot_keys_gtk_hash_generate(gtk, gtk_hash) < 0) {
        return false;
    }

    // If PTK has been used to install different GTK to index than the current one, trigger mismatch
    if (memcmp(sec_gtks->ins_gtk_hash[sec_gtks->gtk_set_index].hash, gtk_hash, INS_GTK_HASH_LEN) != 0) {
        return true;
    }

    return false;
}
