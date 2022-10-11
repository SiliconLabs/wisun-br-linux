/*
 * Copyright (c) 2020, Pelion and affiliates.
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fnmatch.h>
#include <glob.h>
#include "common/log.h"
#include "common/rand.h"
#include "common/parsers.h"
#include "common/key_value_storage.h"
#include "stack-services/ns_list.h"
#include "stack-services/ns_trace.h"
#include "stack/mac/fhss_config.h"

#include "nwk_interface/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "security/kmp/kmp_addr.h"
#include "security/kmp/kmp_api.h"
#include "security/kmp/kmp_socket_if.h"
#include "security/protocols/sec_prot_certs.h"
#include "security/protocols/sec_prot_keys.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_pae_timers.h"
#include "6lowpan/ws/ws_pae_auth.h"
#include "6lowpan/ws/ws_pae_lib.h"
#include "6lowpan/ws/ws_pae_nvm_store.h"
#include "6lowpan/ws/ws_pae_nvm_data.h"
#include "6lowpan/ws/ws_pae_time.h"

#include "6lowpan/ws/ws_pae_key_storage.h"

#define TRACE_GROUP "wsks"

#define KEY_STORAGE_INDEX_FILE                        "key_storage_index"
#define KEY_STORAGE_FILE                              "key_storage_00_1.1"
#define KEY_STORAGE_FILE_LEN                          sizeof(KEY_STORAGE_FILE)

// Storage array header size
#define STORAGE_ARRAY_HEADER_LEN                      sizeof(key_storage_nvm_tlv_entry_t)

// Update the key storage reference time on write operations, if entry reference time differs more than a day
#define KEY_STORAGE_REF_TIME_UPDATE_THRESHOLD         86400

/* Force key storage reference time update, if reference time differs more 31 days */
#define KEY_STORAGE_REF_TIME_UPDATE_FORCE_THRESHOLD   GTK_DEFAULT_LIFETIME + 86400

// Base scatter timer value, 3 seconds */
#define KEY_STORAGE_SCATTER_TIMER_BASE_VALUE          30

typedef enum {
    WRITE_SET = 0,
    TIME_SET,
    PMK_CNT_SET,
    PMK_SET,
    PTK_SET,
    EUI64_SET,
    PTKEUI64_SET,
    GTKHASH_SET,
    LGTKHASH_SET,
    PMKLTIME_SET,
    PTKLTIME_SET,
} field_set_e;

#define FIELD_SET(field) (field_set | (1u << field))
#define FIELD_IS_SET(field) (field_set & (1u << field))

typedef struct key_storage_array {
    ns_list_link_t link;                                /**< Link */
    const void *instance;                               /**< Instance; for support of multiple authenticators */
    key_storage_nvm_tlv_entry_t *storage_array_handle;  /**< Key storage array handle (NVM header + array) */
    sec_prot_keys_storage_t *storage_array;             /**< Key storage array */
    uint16_t size;                                      /**< Array size in bytes */
    uint16_t entries;                                   /**< Entries in array */
    uint16_t free_entries;                              /**< Free entries in array */
    bool allocated : 1;                                 /**< Allocated */
    bool modified : 1;                                  /**< Array modified */
    bool pending_storing : 1;                           /**< Entry is pending storing to NVM */
} key_storage_array_t;

typedef struct key_storage_params {
    uint8_t settings_set;                               /**< Settings set, do not use defaults */
    uint8_t storages_empty;                             /**< Number of empty i.e. to be allocated storages */
    uint16_t storage_default_size;                      /**< Default size for storages */
    uint16_t replace_index;                             /**< Index to replace when storages are full */
    uint64_t store_bitfield;                            /**< Bitfield of stored files */
    uint16_t store_timer_timeout;                       /**< Storing timing timeout */
    uint32_t restart_cnt;                               /**< Re-start counter */
} key_storage_params_t;

static key_storage_params_t key_storage_params;

static NS_LIST_DEFINE(key_storage_array_list, key_storage_array_t, link);

static int8_t ws_pae_key_storage_allocate(const void *instance, uint16_t key_storage_size, void *storage);
static void ws_pae_key_storage_clear(key_storage_array_t *key_storage_array);
static void ws_pae_key_storage_list_all_free(void);
static void ws_pae_key_storage_scatter_timer_timeout(void);
static void ws_pae_key_storage_fast_timer_ticks_set(void);
static int8_t ws_pae_key_storage_array_time_update_entry(uint64_t time_difference, sec_prot_keys_storage_t *storage_array_entry);
static int8_t ws_pae_key_storage_array_time_check_and_update_all(key_storage_array_t *key_storage_array, bool modified);
static int8_t ws_pae_key_storage_array_counters_check_and_update_all(key_storage_array_t *key_storage_array);
static int8_t ws_pae_key_storage_array_lifetime_update(uint32_t time_difference, uint16_t *lifetime);
static void ws_pae_key_storage_array_pmk_invalid(sec_prot_keys_storage_t *storage_array);
static void ws_pae_key_storage_array_ptk_invalid(sec_prot_keys_storage_t *storage_array);

static void ws_pae_key_storage_filename_set(char *file_name, uint8_t file_number)
{
    // Name is "key_storage_00" where 00 is replaced by file number
    strcpy(file_name, KEY_STORAGE_FILE);
    file_name[12] = (file_number / 10) + 'A'; // 0 is ASCII 'A', 1='B',..., F='P'
    file_name[13] = (file_number % 10) + 'A'; // same as above
}

static int8_t ws_pae_key_storage_allocate(const void *instance, uint16_t key_storage_size, void *new_storage_array)
{
    key_storage_array_t *key_storage_array = malloc(sizeof(key_storage_array_t));
    if (!key_storage_array) {
        return -1;
    }

    if (new_storage_array == NULL) {
        key_storage_array->storage_array_handle = malloc(key_storage_size);
        if (!key_storage_array->storage_array_handle) {
            free(key_storage_array);
            return -1;
        }
        key_storage_array->allocated = true;
    } else {
        key_storage_array->storage_array_handle = new_storage_array;
        key_storage_array->allocated = false;
    }
    key_storage_array->storage_array = (sec_prot_keys_storage_t *)(((uint8_t *)key_storage_array->storage_array_handle) + STORAGE_ARRAY_HEADER_LEN);
    key_storage_array->size = key_storage_size;
    key_storage_array->entries = (key_storage_size - STORAGE_ARRAY_HEADER_LEN) / sizeof(sec_prot_keys_storage_t);
    key_storage_array->free_entries = key_storage_array->entries;
    key_storage_array->instance = instance;
    key_storage_array->modified = false;
    key_storage_array->pending_storing = false;

    ws_pae_nvm_store_key_storage_tlv_create((nvm_tlv_t *) key_storage_array->storage_array_handle, key_storage_array->size);

    ws_pae_key_storage_clear(key_storage_array);

    ns_list_add_to_end(&key_storage_array_list, key_storage_array);

    tr_info("KeyS new %s, array: %p entries: %i", key_storage_array->allocated ? "allocated" : "static", (void *) key_storage_array->storage_array, key_storage_array->entries);

    return 0;
}

static void ws_pae_key_storage_clear(key_storage_array_t *key_storage_array)
{
    key_storage_array->storage_array_handle->reference_time = ws_pae_current_time_get();
    key_storage_array->storage_array_handle->reference_restart_cnt = key_storage_params.restart_cnt;

    sec_prot_keys_storage_t *storage_array = (sec_prot_keys_storage_t *) key_storage_array->storage_array;
    // Set all entries empty
    for (uint16_t index = 0; index < key_storage_array->entries; index++) {
        if (key_storage_array->allocated) {
            memset(&storage_array[index], 0, sizeof(sec_prot_keys_storage_t));
        }
        storage_array[index].eui_64_set = false;
    }
}

static void ws_pae_key_storage_list_all_free(void)
{
    ns_list_foreach_safe(key_storage_array_t, entry, &key_storage_array_list) {
        if (entry->allocated) {
            free(entry->storage_array_handle);
        }
        ns_list_remove(&key_storage_array_list, entry);
        free(entry);
    }
}

bool ws_pae_key_storage_supp_delete(const void *instance, const uint8_t *eui64)
{
    char filename[256];
    char str_buf[24];
    int ret;

    if (g_storage_prefix)
        return true;
    str_key(eui64, 8, str_buf, sizeof(str_buf));
    snprintf(filename, sizeof(filename), "%skeys-%s", g_storage_prefix, str_buf);
    ret = unlink(filename);

    return !ret;
}

int8_t ws_pae_key_storage_supp_write(const void *instance, supp_entry_t *pae_supp)
{
    uint64_t current_time = ws_pae_current_time_get();
    struct storage_parse_info *info;
    char str_buf[256];
    int i;

    WARN_ON(!pae_supp->sec_keys.ptk_eui_64_set);
    strcpy(str_buf, "keys-");
    str_key(pae_supp->addr.eui_64, 8, str_buf + strlen(str_buf), sizeof(str_buf) - strlen(str_buf));
    info = storage_open_prefix(str_buf, "w");
    if (!info)
        return -1;
    if (pae_supp->sec_keys.pmk_set) {
        str_key(pae_supp->sec_keys.pmk, sizeof(pae_supp->sec_keys.pmk), str_buf, sizeof(str_buf));
        fprintf(info->file, "pmk = %s\n", str_buf);
        fprintf(info->file, "pmk.lifetime = %" PRIu64 "\n", current_time + pae_supp->sec_keys.pmk_lifetime);
    }
    if (pae_supp->sec_keys.pmk_key_replay_cnt_set)
        fprintf(info->file, "pmk.replay_counter = %" PRIu64 "\n", pae_supp->sec_keys.pmk_key_replay_cnt);
    if (pae_supp->sec_keys.ptk_set) {
        str_key(pae_supp->sec_keys.ptk, sizeof(pae_supp->sec_keys.ptk), str_buf, sizeof(str_buf));
        fprintf(info->file, "ptk = %s\n", str_buf);
        fprintf(info->file, "ptk.lifetime = %" PRIu64 "\n", current_time + pae_supp->sec_keys.ptk_lifetime);
    }
    for (i = 0; i < GTK_NUM; i++) {
        if (pae_supp->sec_keys.gtks.ins_gtk_hash_set & (1 << i)) {
            str_key(pae_supp->sec_keys.gtks.ins_gtk_hash[i].hash,
                      sizeof(pae_supp->sec_keys.gtks.ins_gtk_hash[i].hash),
                      str_buf, sizeof(str_buf));
            fprintf(info->file, "gtk[%d].installed_hash = %s\n", i, str_buf);
        }
    }
    for (i = 0; i < LGTK_NUM; i++) {
        if (pae_supp->sec_keys.lgtks.ins_gtk_hash_set & (1 << i)) {
            str_key(pae_supp->sec_keys.lgtks.ins_gtk_hash[i].hash,
                      sizeof(pae_supp->sec_keys.lgtks.ins_gtk_hash[i].hash),
                      str_buf, sizeof(str_buf));
            fprintf(info->file, "lgtk[%d].installed_hash = %s\n", i, str_buf);
        }
    }
    storage_close(info);
    return 0;
}

supp_entry_t *ws_pae_key_storage_supp_read(const void *instance, const uint8_t *eui_64, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks, const sec_prot_certs_t *certs)
{
    supp_entry_t *pae_supp = malloc(sizeof(supp_entry_t));
    uint64_t current_time = ws_pae_current_time_get();
    struct storage_parse_info *info;
    char str_buf[256];
    int ret;

    ws_pae_lib_supp_init(pae_supp);
    sec_prot_keys_init(&pae_supp->sec_keys, gtks, lgtks, certs);
    kmp_address_init(KMP_ADDR_EUI_64_AND_IP, &pae_supp->addr, eui_64);
    strcpy(str_buf, "keys-");
    str_key(eui_64, 8, str_buf + strlen(str_buf), sizeof(str_buf) - strlen(str_buf));
    info = storage_open_prefix(str_buf, "r");
    if (!info)
        return pae_supp;
    for (;;) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("pmk", info->key, 0)) {
            if (parse_byte_array(pae_supp->sec_keys.pmk, PMK_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                pae_supp->sec_keys.pmk_set = true;
        } else if (!fnmatch("pmk.lifetime", info->key, 0)) {
            if (current_time < strtoull(info->value, NULL, 0))
                pae_supp->sec_keys.pmk_lifetime = strtoull(info->value, NULL, 0) - current_time;
            else
                WARN("%s:%d: expired PMK lifetime: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("pmk.replay_counter", info->key, 0)) {
            pae_supp->sec_keys.pmk_key_replay_cnt = strtoull(info->value, NULL, 0);
            pae_supp->sec_keys.pmk_key_replay_cnt_set = true;
        } else if (!fnmatch("ptk", info->key, 0)) {
            if (parse_byte_array(pae_supp->sec_keys.ptk, PTK_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                pae_supp->sec_keys.ptk_set = true;
        } else if (!fnmatch("ptk.lifetime", info->key, 0)) {
            if (current_time < strtoull(info->value, NULL, 0))
                pae_supp->sec_keys.ptk_lifetime = strtoull(info->value, NULL, 0) - current_time;
            else
                WARN("%s:%d: expired PTK lifetime: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("gtk\\[*].installed_hash", info->key, 0) && info->key_array_index < 4) {
            if (parse_byte_array(pae_supp->sec_keys.gtks.ins_gtk_hash[info->key_array_index].hash, INS_GTK_HASH_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                pae_supp->sec_keys.gtks.ins_gtk_hash_set |= 1 << strtoull(info->value, NULL, 0);
        } else if (!fnmatch("lgtk\\[*].installed_hash", info->key, 0) && info->key_array_index < 3) {
            if (parse_byte_array(pae_supp->sec_keys.lgtks.ins_gtk_hash[info->key_array_index].hash, INS_GTK_HASH_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                pae_supp->sec_keys.lgtks.ins_gtk_hash_set |= 1 << strtoull(info->value, NULL, 0);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);
    if (!pae_supp->sec_keys.pmk_lifetime)
        pae_supp->sec_keys.pmk_set = false;
    if (!pae_supp->sec_keys.ptk_lifetime)
        pae_supp->sec_keys.ptk_set = false;
    if (!pae_supp->sec_keys.pmk_set)
        pae_supp->sec_keys.ptk_set = false;
    return pae_supp;
}

void ws_pae_key_storage_remove(void)
{
    glob_t globbuf;
    char filename[256];
    int i;

    if (!g_storage_prefix)
        return;
    snprintf(filename, sizeof(filename), "%skeys-*:*:*:*:*:*:*:*", g_storage_prefix);
    if (glob(filename, 0, NULL, &globbuf)) {
        WARN("glob %s returned an error", filename);
        return;
    }
    for (i = 0; globbuf.gl_pathv[i]; i++)
        if (unlink(globbuf.gl_pathv[i]))
            WARN("unlink %s: %m", globbuf.gl_pathv[i]);
    globfree(&globbuf);
}

uint16_t ws_pae_key_storage_storing_interval_get(void)
{
    return DEFAULT_STORING_INTERVAL;
}

static int8_t ws_pae_key_storage_array_time_update_entry(uint64_t time_difference, sec_prot_keys_storage_t *storage_array_entry)
{
    if (storage_array_entry->pmk_lifetime_set) {
#ifdef EXTRA_DEBUG_INFO
        tr_debug("KeyS time update diff: %"PRIi64" PMK OLD t: %i %i eui64: %s", time_difference, STIME_TIME_GET(storage_array_entry->pmk_lifetime), STIME_FORMAT_GET(storage_array_entry->pmk_lifetime), trace_array(storage_array_entry->ptk_eui_64, 8));
#endif
        // Calculate new PMK lifetime
        if (ws_pae_key_storage_array_lifetime_update(time_difference, &storage_array_entry->pmk_lifetime) < 0) {
            tr_info("KeyS time update PMK expired diff: %"PRIi64" t: %i %i eui64: %s", time_difference, STIME_TIME_GET(storage_array_entry->pmk_lifetime),  STIME_FORMAT_GET(storage_array_entry->pmk_lifetime), trace_array(storage_array_entry->ptk_eui_64, 8));
            // PMK expired, whole entry is invalid
            ws_pae_key_storage_array_pmk_invalid(storage_array_entry);
            return -1;
        }
#ifdef EXTRA_DEBUG_INFO
        tr_debug("KeyS time update PMK NEW t: %i %i", STIME_TIME_GET(storage_array_entry->pmk_lifetime), STIME_FORMAT_GET(storage_array_entry->pmk_lifetime));
#endif
    }

    if (storage_array_entry->ptk_lifetime_set) {
#ifdef EXTRA_DEBUG_INFO
        tr_debug("KeyS time update diff: %"PRIi64" PTK OLD t: %i %i eui64: %s", time_difference, STIME_TIME_GET(storage_array_entry->ptk_lifetime), STIME_FORMAT_GET(storage_array_entry->ptk_lifetime), trace_array(storage_array_entry->ptk_eui_64, 8));
#endif
        // Calculate new PTK lifetime
        if (ws_pae_key_storage_array_lifetime_update(time_difference, &storage_array_entry->ptk_lifetime) < 0) {
            tr_info("KeyS time update PTK expired diff: %"PRIi64" t: %i %i eui64: %s", time_difference, STIME_TIME_GET(storage_array_entry->ptk_lifetime), STIME_FORMAT_GET(storage_array_entry->ptk_lifetime), trace_array(storage_array_entry->ptk_eui_64, 8));
            // PTK is invalid, invalidate PTK related fields
            ws_pae_key_storage_array_ptk_invalid(storage_array_entry);
            // PMK is still valid
            return 0;
        }
#ifdef EXTRA_DEBUG_INFO
        tr_debug("KeyS time update PTK NEW t: %i %i", STIME_TIME_GET(storage_array_entry->ptk_lifetime), STIME_FORMAT_GET(storage_array_entry->ptk_lifetime));
#endif
    }
    return 0;
}

static int8_t ws_pae_key_storage_array_time_check_and_update_all(key_storage_array_t *key_storage_array, bool modified)
{
    uint64_t reference_time = key_storage_array->storage_array_handle->reference_time;
    uint64_t current_time = ws_pae_current_time_get();

    uint32_t time_difference;
    if (ws_pae_time_diff_calc(current_time, reference_time, &time_difference, false) < 0) {
        tr_error("KeyS array time all err: %"PRIi64", ref: %"PRIi64", diff: %"PRIi32, ws_pae_current_time_get(), reference_time, time_difference);
        return -1;
    }

    if (modified) {
        // Updates once a day on write
        if (time_difference < KEY_STORAGE_REF_TIME_UPDATE_THRESHOLD) {
            return 0;
        }
    } else if (time_difference < KEY_STORAGE_REF_TIME_UPDATE_FORCE_THRESHOLD) {
        // Or every 31 days also when no other writes triggered
        return 0;
    }

    // Checks entries in storage array
    sec_prot_keys_storage_t *storage_array = (sec_prot_keys_storage_t *) key_storage_array->storage_array;
    for (uint16_t index = 0; index < key_storage_array->entries; index++) {
        if (!storage_array[index].eui_64_set) {
            continue;
        }
        // Updates lifetimes on the entry
        ws_pae_key_storage_array_time_update_entry(time_difference, &storage_array[index]);
    }

    // Entries are now on current time; update reference time
    key_storage_array->storage_array_handle->reference_time = current_time;
    return 1;
}

static int8_t ws_pae_key_storage_array_counters_check_and_update_all(key_storage_array_t *key_storage_array)
{
    // Checks entries in storage array
    sec_prot_keys_storage_t *storage_array = (sec_prot_keys_storage_t *) key_storage_array->storage_array;
    for (uint16_t index = 0; index < key_storage_array->entries; index++) {
        if (!storage_array[index].eui_64_set) {
            continue;
        }

        if (!storage_array[index].pmk_key_replay_cnt_set) {
            continue;
        }

        // Sanity check for replay counter
        if (storage_array[index].pmk_key_replay_cnt >= PMK_KEY_REPLAY_CNT_LIMIT) {
            ws_pae_key_storage_array_pmk_invalid(&storage_array[index]);
            ws_pae_key_storage_array_ptk_invalid(&storage_array[index]);
            continue;
        }

        /* Resets replay counter (lower part). When generating 64bit replay counter used on EAPOL,
           re-start count is set to replay counter MSB 32bits. So the lower part of the counter
           is always fresh after re-start. Thus, each power cycle of device has LSB 32bits of replay
           counter space to use. In practice uses only LSB 16bits since counter is limited to 60000,
           before generating new PMK. */
        storage_array[index].pmk_key_replay_cnt = 0;
    }

    return 0;
}

static int8_t ws_pae_key_storage_array_lifetime_update(uint32_t time_difference, uint16_t *lifetime)
{
    uint32_t entry_lifetime = ws_pae_time_from_short_convert(*lifetime);
    *lifetime = 0;

    // If lifetime has expired, return failure
    if (time_difference >= entry_lifetime) {
        return -1;
    }
    entry_lifetime -= time_difference;
    *lifetime = ws_pae_time_to_short_convert(entry_lifetime);
    // If conversion results zero lifetime return failure
    if (*lifetime == 0) {
        return -1;
    }

    // Lifetime is valid
    return 0;
}

static void ws_pae_key_storage_array_pmk_invalid(sec_prot_keys_storage_t *storage_array)
{
    memset(storage_array, 0, sizeof(sec_prot_keys_storage_t));
}

static void ws_pae_key_storage_array_ptk_invalid(sec_prot_keys_storage_t *storage_array)
{
    memset(storage_array->ptk, 0, PTK_LEN);
    storage_array->ptk_set = false;
    storage_array->ptk_eui_64_set = false;
    memset(storage_array->ins_gtk_hash, 0, sizeof(storage_array->ins_gtk_hash));
    memset(storage_array->ins_lgtk_hash, 0, sizeof(storage_array->ins_lgtk_hash));
    storage_array->ins_gtk_hash_set = false;
    storage_array->ins_lgtk_hash_set = false;
    storage_array->ptk_lifetime = 0;
}


