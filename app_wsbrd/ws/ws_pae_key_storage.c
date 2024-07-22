/*
 * Copyright (c) 2020, Pelion and affiliates.
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <glob.h>
#include <fnmatch.h>
#include <inttypes.h>
#include "common/bits.h"
#include "common/log.h"
#include "common/rand.h"
#include "common/parsers.h"
#include "common/named_values.h"
#include "common/key_value_storage.h"
#include "common/time_extra.h"
#include "common/specs/ws.h"

#include "security/protocols/sec_prot_keys.h"
#include "ws/ws_pae_lib.h"

#include "ws/ws_pae_key_storage.h"

static const struct name_value nr_values[] = {
    { "br",        WS_NR_ROLE_BR      }, // should not happen
    { "lfn",       WS_NR_ROLE_LFN     },
    { "ffn-fan11", WS_NR_ROLE_ROUTER  },
    // Absence of the Node Role KDE MUST be interpreted to
    // mean the node is operating as a FAN 1.0 Router
    { "ffn-fan10", WS_NR_ROLE_UNKNOWN },
    { NULL, 0 }
};

bool ws_pae_key_storage_supp_delete(const void *instance, const uint8_t *eui64)
{
    char filename[256];
    char str_buf[24];
    int ret;

    if (!g_storage_prefix)
        return true;
    str_key(eui64, 8, str_buf, sizeof(str_buf));
    snprintf(filename, sizeof(filename), "%skeys-%s", g_storage_prefix, str_buf);
    ret = unlink(filename);

    return !ret;
}

int8_t ws_pae_key_storage_supp_write(const void *instance, supp_entry_t *pae_supp)
{
    uint64_t current_time = time_now_s(CLOCK_REALTIME);
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
        if (pae_supp->sec_keys.gtks.ins_gtk_hash_set & BIT(i)) {
            str_key(pae_supp->sec_keys.gtks.ins_gtk_hash[i].hash,
                      sizeof(pae_supp->sec_keys.gtks.ins_gtk_hash[i].hash),
                      str_buf, sizeof(str_buf));
            fprintf(info->file, "gtk[%d].installed_hash = %s\n", i, str_buf);
        }
    }
    for (i = 0; i < LGTK_NUM; i++) {
        if (pae_supp->sec_keys.lgtks.ins_gtk_hash_set & BIT(i)) {
            str_key(pae_supp->sec_keys.lgtks.ins_gtk_hash[i].hash,
                      sizeof(pae_supp->sec_keys.lgtks.ins_gtk_hash[i].hash),
                      str_buf, sizeof(str_buf));
            fprintf(info->file, "lgtk[%d].installed_hash = %s\n", i, str_buf);
        }
    }
    fprintf(info->file, "node_role = %s\n", val_to_str(pae_supp->sec_keys.node_role, nr_values, "unknown"));
    storage_close(info);
    return 0;
}

supp_entry_t *ws_pae_key_storage_supp_read(const void *instance, const uint8_t *eui_64, sec_prot_gtk_keys_t *gtks, sec_prot_gtk_keys_t *lgtks, const sec_prot_certs_t *certs)
{
    supp_entry_t *pae_supp = malloc(sizeof(supp_entry_t));
    uint64_t current_time = time_now_s(CLOCK_REALTIME);
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
    // FIXME: the caller already knows the value of eui64
    memcpy(pae_supp->sec_keys.ptk_eui_64, eui_64, 8);
    pae_supp->sec_keys.ptk_eui_64_set = true;
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
                pae_supp->sec_keys.gtks.ins_gtk_hash_set |= BIT(strtoull(info->value, NULL, 0));
        } else if (!fnmatch("lgtk\\[*].installed_hash", info->key, 0) && info->key_array_index < 3) {
            if (parse_byte_array(pae_supp->sec_keys.lgtks.ins_gtk_hash[info->key_array_index].hash, INS_GTK_HASH_LEN, info->value))
                WARN("%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
            else
                pae_supp->sec_keys.lgtks.ins_gtk_hash_set |= BIT(strtoull(info->value, NULL, 0));
        } else if (!fnmatch("node_role", info->key, 0)) {
            pae_supp->sec_keys.node_role = str_to_val(info->value, nr_values);
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

int ws_pae_key_storage_list(uint8_t eui64[][8], int len)
{
    char filename[PATH_MAX];
    glob_t globbuf;
    int i, ret;

    if (!g_storage_prefix) {
        WARN("storage disabled, cannot retrieve EUI64");
        return 0;
    }
    snprintf(filename, sizeof(filename), "%skeys-*:*:*:*:*:*:*:*", g_storage_prefix);
    ret = glob(filename, 0, NULL, &globbuf);
    if (ret) {
        WARN_ON(ret != GLOB_NOMATCH, "glob %s returned an error", filename);
        return 0;
    }
    for (i = 0; globbuf.gl_pathv[i] && i < len; i++)
        parse_byte_array(eui64[i], 8, strrchr(globbuf.gl_pathv[i], '-') + 1);
    globfree(&globbuf);
    return i;
}

bool ws_pae_key_storage_supp_exists(const uint8_t eui64[8])
{
    char eui64_str[STR_MAX_LEN_EUI64];
    char filename[PATH_MAX];
    int ret;

    str_eui64(eui64, eui64_str);
    ret = snprintf(filename, sizeof(filename), "%skeys-%s", g_storage_prefix, eui64_str);
    BUG_ON(ret >= sizeof(filename), "g_storage_prefix too big");
    return !access(filename, F_OK);
}

uint16_t ws_pae_key_storage_storing_interval_get(void)
{
    return DEFAULT_STORING_INTERVAL;
}
