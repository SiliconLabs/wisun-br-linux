/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */

#include <stdlib.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <glob.h>

#include "common/specs/ws.h"
#include "common/key_value_storage.h"
#include "common/string_extra.h"
#include "common/time_extra.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/parsers.h"
#include "common/eui64.h"
#include "common/log.h"

#include "authenticator_storage.h"
#include "authenticator_key.h"
#include "authenticator.h"

// Arbitrary
#define FRAME_COUNTER_OFFSET 200000
#define REPLAY_COUNTER_OFFSET 100

static void auth_storage_load_group(struct auth_ctx *auth, struct auth_gtk_group *gtk_group,
                                    uint64_t next_installation_ts_ms, uint64_t next_activation_ts_ms)
{
    uint64_t storage_offset_ms = time_get_storage_offset_ms();
    bool is_gtk_group = gtk_group == &auth->gtk_group;
    uint64_t now_ms = time_now_ms(CLOCK_MONOTONIC);

    if (storage_offset_ms > next_installation_ts_ms || now_ms > next_installation_ts_ms - storage_offset_ms) {
        WARN("sec: next %s installation missed, installing new key", is_gtk_group ? "GTK" : "LGTK");
        gtk_group->slot_active = auth_gtk_slot_next(gtk_group->slot_active);
        auth_install_gtk(auth, gtk_group, gtk_group->slot_active, NULL);
    } else {
        timer_start_abs(&auth->timer_group, &gtk_group->install_timer, next_installation_ts_ms - storage_offset_ms);
        TRACE(TR_SECURITY, "sec: next %s installation=%"PRIu64, is_gtk_group ? "GTK" : "LGTK",
              gtk_group->install_timer.expire_ms / 1000);
    }
    if (storage_offset_ms > next_activation_ts_ms || now_ms > next_activation_ts_ms - storage_offset_ms) {
        WARN("sec: next %s activation missed, activating new key", is_gtk_group ? "GTK" : "LGTK");
        auth_activate_next_gtk(auth, gtk_group);
    } else {
        timer_start_abs(&auth->timer_group, &gtk_group->activation_timer, next_activation_ts_ms - storage_offset_ms);
        TRACE(TR_SECURITY, "sec: next %s activation=%"PRIu64, is_gtk_group ? "GTK" : "LGTK",
              gtk_group->activation_timer.expire_ms / 1000);
    }
}

static void auth_storage_load_gtks(struct auth_ctx *auth, const uint64_t gtks_expiration_ts_ms[WS_GTK_COUNT + WS_LGTK_COUNT])
{
    uint64_t storage_offset_ms = time_get_storage_offset_ms();
    struct auth_gtk_group *lgtk_group = &auth->lgtk_group;
    struct auth_gtk_group *gtk_group = &auth->gtk_group;
    uint64_t now_ms = time_now_ms(CLOCK_MONOTONIC);
    struct ws_gtk *gtks = auth->gtks;
    bool activate;

    for (uint8_t i = 0; i < ARRAY_SIZE(auth->gtks); i++) {
        if (!gtks_expiration_ts_ms[i])
            continue;
        if (storage_offset_ms > gtks_expiration_ts_ms[i] || now_ms > gtks_expiration_ts_ms[i] - storage_offset_ms) {
            WARN("sec: %s expired", tr_gtkname(i));
            continue;
        }
        timer_start_abs(&auth->timer_group, &gtks[i].expiration_timer, gtks_expiration_ts_ms[i] - storage_offset_ms);
        TRACE(TR_SECURITY, "sec: installed %s=%s expiration=%"PRIu64, tr_gtkname(i),
              tr_key(gtks[i].key, sizeof(gtks[i].key)), gtks[i].expiration_timer.expire_ms / 1000);
        if (i < WS_GTK_COUNT)
            activate = gtk_group->slot_active == i;
        else
            activate = lgtk_group->slot_active == i;
        if (activate)
            TRACE(TR_SECURITY, "sec: activated %s=%s", tr_gtkname(i),
                  tr_key(gtks[i].key, sizeof(gtks[i].key)));
        auth->on_gtk_change(auth, gtks[i].key, gtks[i].frame_counter, i + 1, activate);
    }
}

static bool auth_storage_load_keys(struct auth_ctx *auth)
{
    uint64_t gtks_expiration_ts_ms[WS_GTK_COUNT + WS_LGTK_COUNT] = { };
    struct auth_gtk_group *lgtk_group = &auth->lgtk_group;
    struct auth_gtk_group *gtk_group = &auth->gtk_group;
    uint64_t next_lgtk_installation_ts_ms = 0;
    uint64_t next_gtk_installation_ts_ms = 0;
    uint64_t next_lgtk_activation_ts_ms = 0;
    uint64_t next_gtk_activation_ts_ms = 0;
    struct ws_gtk *gtks = auth->gtks;
    struct storage_parse_info *info;
    struct eui64 eui64;
    int ret;

    info = storage_open_prefix("network-keys", "r");
    if (!info)
        return false;

    while (true) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("eui64", info->key, 0)) {
            if (parse_byte_array(eui64.u8, sizeof(eui64.u8), info->value))
                FATAL(1, "%s:%d: invalid eui64: %s", info->filename, info->linenr, info->value);
            FATAL_ON(!eui64_eq(&eui64, &auth->eui64), 1, "eui64 mismatch between current and previous state loaded from storage");
        } else if (!fnmatch("gtk.active_slot", info->key, 0)) {
            gtk_group->slot_active = (uint8_t)strtoul(info->value, NULL, 0);
        } else if (!fnmatch("gtk.next_installation_timestamp_ms", info->key, 0)) {
            next_gtk_installation_ts_ms = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("gtk.next_activation_timestamp_ms", info->key, 0)) {
            next_gtk_activation_ts_ms = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("lgtk.active_slot", info->key, 0)) {
            lgtk_group->slot_active = (uint8_t)strtoul(info->value, NULL, 0) + WS_GTK_COUNT;
        } else if (!fnmatch("lgtk.next_installation_timestamp_ms", info->key, 0)) {
            next_lgtk_installation_ts_ms = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("lgtk.next_activation_timestamp_ms", info->key, 0)) {
            next_lgtk_activation_ts_ms = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("gtk\\[*]", info->key, 0)) {
            if (parse_byte_array(gtks[info->key_array_index].key, sizeof(gtks[info->key_array_index].key), info->value))
                FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("gtk\\[*].expiration_timestamp_ms", info->key, 0)) {
            gtks_expiration_ts_ms[info->key_array_index] = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("gtk\\[*].frame_counter", info->key, 0)) {
             gtks[info->key_array_index].frame_counter = add32sat((uint32_t)strtoul(info->value, NULL, 0),
                                                                  FRAME_COUNTER_OFFSET);
        } else if (!fnmatch("lgtk\\[*]", info->key, 0)) {
            if (parse_byte_array(gtks[info->key_array_index + WS_GTK_COUNT].key,
                sizeof(gtks[info->key_array_index + WS_GTK_COUNT].key), info->value))
                FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("lgtk\\[*].expiration_timestamp_ms", info->key, 0)) {
            gtks_expiration_ts_ms[info->key_array_index + WS_GTK_COUNT] = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("lgtk\\[*].frame_counter", info->key, 0)) {
             gtks[info->key_array_index + WS_GTK_COUNT].frame_counter = add32sat((uint32_t)strtoul(info->value, NULL, 0),
                                                                                 FRAME_COUNTER_OFFSET);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);

    auth_storage_load_gtks(auth, gtks_expiration_ts_ms);
    auth_storage_load_group(auth, gtk_group, next_gtk_installation_ts_ms, next_gtk_activation_ts_ms);
    auth_storage_load_group(auth, lgtk_group, next_lgtk_installation_ts_ms, next_lgtk_activation_ts_ms);

    return true;
}

static bool auth_storage_load_supplicant(struct auth_ctx *auth, const char *filename)
{
    time_t storage_offset_s = time_get_storage_offset_s();
    struct storage_parse_info *info;
    struct auth_supp_ctx *supp;
    struct eui64 eui64;
    const char *strptr;
    int ret;

    strptr = strrchr(filename, '-');
    if (!strptr) {
        WARN("%s: invalid filename: %s", __func__, filename);
        return false;
    }
    if (parse_byte_array(eui64.u8, sizeof(eui64.u8), strptr + 1)) {
        WARN("%s: invalid eui64 in filename: %s", __func__, filename);
        return false;
    }
    info = storage_open(filename, "r");
    if (!info) {
        WARN("%s: unable to open file: %s", __func__, filename);
        return false;
    }

    supp = auth_fetch_supp(auth, &eui64);

    while (true) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("pmk", info->key, 0)) {
            if (parse_byte_array(supp->eap_tls.tls.pmk.key, sizeof(supp->eap_tls.tls.pmk.key), info->value))
                FATAL(1, "%s:%d: invalid pmk: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("pmk.installation_timestamp_s", info->key, 0)) {
            supp->eap_tls.tls.pmk.installation_s = strtoull(info->value, NULL, 0) - storage_offset_s;
        } else if (!fnmatch("pmk.replay_counter", info->key, 0)) {
            supp->eap_tls.tls.pmk.replay_counter = strtoll(info->value, NULL, 0) + REPLAY_COUNTER_OFFSET;
        } else if (!fnmatch("ptk", info->key, 0)) {
            if (parse_byte_array(supp->eap_tls.tls.ptk.key, sizeof(supp->eap_tls.tls.ptk.key), info->value))
                FATAL(1, "%s:%d: invalid ptk: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("ptk.installation_timestamp_s", info->key, 0)) {
            supp->eap_tls.tls.ptk.installation_s = strtoull(info->value, NULL, 0) - storage_offset_s;
        } else if (!fnmatch("gtkl", info->key, 0)) {
            supp->gtkl = (uint8_t)strtoul(info->value, NULL, 0);
        } else if (!fnmatch("lgtkl", info->key, 0)) {
            supp->lgtkl = (uint8_t)strtoul(info->value, NULL, 0);
        } else if (!fnmatch("node_role", info->key, 0)) {
            supp->node_role = (uint8_t)strtoul(info->value, NULL, 0);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    if (!auth_is_supp_pmk_valid(auth, supp))
        auth_revoke_pmk(auth, &eui64);
    storage_close(info);
    return true;
}

static void auth_storage_load_supplicants(struct auth_ctx *auth)
{
    char globexpr[PATH_MAX];
    glob_t globbuf;
    int ret;

    snprintf(globexpr, sizeof(globexpr), "%s%s", g_storage_prefix, "supp-*");
    ret = glob(globexpr, 0, NULL, &globbuf);
    if (ret && ret != GLOB_NOMATCH)
        WARN("%s: glob %s returned %u", __func__, globexpr, ret);
    if (ret)
        return;
    for (int i = 0; globbuf.gl_pathv[i]; i++)
        auth_storage_load_supplicant(auth, globbuf.gl_pathv[i]);
    globfree(&globbuf);
}

bool auth_storage_load(struct auth_ctx *auth)
{
    if (!g_storage_prefix)
        return false;
    if (!auth_storage_load_keys(auth))
        return false;
    auth_storage_load_supplicants(auth);
    return true;
}

static void auth_storage_get_supp_filename(const struct auth_supp_ctx *supp, char *filename, size_t size)
{
    char str_buf[PATH_MAX];

    str_key(supp->eui64.u8, sizeof(supp->eui64.u8), str_buf, sizeof(str_buf));
    snprintf(filename, size, "%ssupp-%s", g_storage_prefix, str_buf);
}

void auth_storage_clear_supplicant(struct auth_supp_ctx *supp)
{
    char filename[PATH_MAX];

    auth_storage_get_supp_filename(supp, filename, sizeof(filename));
    storage_delete((const char *[]){ filename, NULL });
}

void auth_storage_store_supplicant(struct auth_supp_ctx *supp, bool force_write)
{
    time_t storage_offset_s = time_get_storage_offset_s();
    struct storage_parse_info *info;
    char filename[PATH_MAX];
    char str_buf[256];

    auth_storage_get_supp_filename(supp, filename, sizeof(filename));
    info = storage_open(filename, "w");
    if (!info) {
        WARN("%s: unable to open file: %s", __func__, filename);
        return;
    }

    if (supp->eap_tls.tls.pmk.installation_s) {
        str_key(supp->eap_tls.tls.pmk.key, sizeof(supp->eap_tls.tls.pmk.key), str_buf, sizeof(str_buf));
        fprintf(info->file, "pmk = %s\n", str_buf);
        fprintf(info->file, "pmk.installation_timestamp_s = %"PRIu64"\n",
                (uint64_t)supp->eap_tls.tls.pmk.installation_s + storage_offset_s);
        fprintf(info->file, "pmk.replay_counter = %"PRIu64"\n\n", supp->eap_tls.tls.pmk.replay_counter);
    }

    if (supp->eap_tls.tls.ptk.installation_s) {
        str_key(supp->eap_tls.tls.ptk.key, sizeof(supp->eap_tls.tls.ptk.key), str_buf, sizeof(str_buf));
        fprintf(info->file, "ptk = %s\n", str_buf);
        fprintf(info->file, "ptk.installation_timestamp_s = %"PRIu64"\n\n",
                (uint64_t)supp->eap_tls.tls.ptk.installation_s + storage_offset_s);
    }

    fprintf(info->file, "gtkl = %u\n", supp->gtkl);
    fprintf(info->file, "lgtkl = %u\n", supp->lgtkl);
    fprintf(info->file, "node_role = %u\n", supp->node_role);
    if (force_write) {
        fflush(info->file);
        fsync(fileno(info->file));
    }
    storage_close(info);
}

void auth_storage_store_keys(const struct auth_ctx *auth, bool force_write)
{
    uint64_t storage_offset_ms = time_get_storage_offset_ms();
    struct storage_parse_info *info;
    char str_buf[256];

    info = storage_open_prefix("network-keys", "w");
    if (!info)
        return;

    str_key(auth->eui64.u8, sizeof(auth->eui64.u8), str_buf, sizeof(str_buf));
    fprintf(info->file, "eui64 = %s\n\n", str_buf);

    fprintf(info->file, "gtk.active_slot = %u\n", auth->gtk_group.slot_active);
    fprintf(info->file, "gtk.next_installation_timestamp_ms = %"PRIu64"\n",
            auth->gtk_group.install_timer.expire_ms + storage_offset_ms);
    fprintf(info->file, "gtk.next_activation_timestamp_ms = %"PRIu64"\n",
            auth->gtk_group.activation_timer.expire_ms + storage_offset_ms);
    fprintf(info->file, "# For information:\n");
    fprintf(info->file, "#gtk.expire_offset_s = %d\n", auth->cfg->ffn.gtk_expire_offset_s);
    fprintf(info->file, "#gtk.new_install_required = %d\n", auth->cfg->ffn.gtk_new_install_required);
    fprintf(info->file, "#gtk.new_activation_time = %d\n", auth->cfg->ffn.gtk_new_activation_time);
    fprintf(info->file, "#pmk.lifetime_s = %d\n", auth->cfg->ffn.pmk_lifetime_s);
    fprintf(info->file, "#ptk.lifetime_s = %d\n\n", auth->cfg->ffn.ptk_lifetime_s);

    fprintf(info->file, "lgtk.active_slot = %u\n", auth->lgtk_group.slot_active - WS_GTK_COUNT);
    fprintf(info->file, "lgtk.next_installation_timestamp_ms = %"PRIu64"\n",
            auth->lgtk_group.install_timer.expire_ms + storage_offset_ms);
    fprintf(info->file, "lgtk.next_activation_timestamp_ms = %"PRIu64"\n",
            auth->lgtk_group.activation_timer.expire_ms + storage_offset_ms);
    fprintf(info->file, "# For information:\n");
    fprintf(info->file, "#lgtk.expire_offset_s = %d\n", auth->cfg->lfn.gtk_expire_offset_s);
    fprintf(info->file, "#lgtk.new_install_required = %d\n", auth->cfg->lfn.gtk_new_install_required);
    fprintf(info->file, "#lgtk.new_activation_time = %d\n", auth->cfg->lfn.gtk_new_activation_time);
    fprintf(info->file, "#lpmk.lifetime_s = %d\n", auth->cfg->lfn.pmk_lifetime_s);
    fprintf(info->file, "#lptk.lifetime_s = %d\n", auth->cfg->lfn.ptk_lifetime_s);

    for (uint8_t i = 0; i < ARRAY_SIZE(auth->gtks); i++) {
        if (!ws_gtk_installed(&auth->gtks[i]))
            continue;
        fprintf(info->file, "\n");
        str_key(auth->gtks[i].key, sizeof(auth->gtks[i].key), str_buf, sizeof(str_buf));
        if (i < WS_GTK_COUNT) {
            fprintf(info->file, "gtk[%d] = %s\n", i, str_buf);
            fprintf(info->file, "gtk[%d].expiration_timestamp_ms = %"PRIu64"\n", i,
                    auth->gtks[i].expiration_timer.expire_ms + storage_offset_ms);
            fprintf(info->file, "gtk[%d].frame_counter = %"PRIu32"\n", i, auth->gtks[i].frame_counter);
        } else {
            fprintf(info->file, "lgtk[%d] = %s\n", i - WS_GTK_COUNT, str_buf);
            fprintf(info->file, "lgtk[%d].expiration_timestamp_ms = %"PRIu64"\n", i - WS_GTK_COUNT,
                    auth->gtks[i].expiration_timer.expire_ms + storage_offset_ms);
            fprintf(info->file, "lgtk[%d].frame_counter = %"PRIu32"\n", i - WS_GTK_COUNT, auth->gtks[i].frame_counter);
        }
    }
    if (force_write) {
        fflush(info->file);
        fsync(fileno(info->file));
    }
    storage_close(info);
}
