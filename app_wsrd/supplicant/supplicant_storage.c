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
#include <unistd.h>
#include <limits.h>
#include <fnmatch.h>
#include <inttypes.h>

#include "common/key_value_storage.h"
#include "common/string_extra.h"
#include "common/time_extra.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/parsers.h"
#include "common/eui64.h"
#include "common/log.h"

#include "supplicant.h"

bool supp_storage_load(struct supp_ctx *supp)
{
    uint64_t gtks_expiration_ts_ms[WS_GTK_COUNT + WS_LGTK_COUNT] = { };
    uint64_t storage_offset_ms = time_get_storage_offset_ms();
    uint64_t now_ms = time_now_ms(CLOCK_MONOTONIC);
    struct storage_parse_info *info;
    struct eui64 eui64;

    info = storage_open_prefix("network-keys", "r");
    if (!info)
        return false;

    while (storage_parse_line(info) != EOF) {
        if (!fnmatch("eui64", info->key, 0)) {
            if (parse_byte_array(eui64.u8, sizeof(eui64.u8), info->value))
                FATAL(1, "%s:%d: invalid eui64: %s", info->filename, info->linenr, info->value);
            FATAL_ON(!eui64_eq(&eui64, &supp->cfg->eui64), 1, "eui64 mismatch between current and previous state loaded from storage");
        } else if (!fnmatch("pmk", info->key, 0)) {
            if (parse_byte_array(supp->keys.pmk.key, sizeof(supp->keys.pmk.key), info->value))
                FATAL(1, "%s:%d: invalid pmk: %s", info->filename, info->linenr, info->value);
            supp->keys.pmk.installation_s = time_now_s(CLOCK_MONOTONIC);
        } else if (!fnmatch("pmk.replay_counter", info->key, 0)) {
            supp->keys.pmk.replay_counter = strtoll(info->value, NULL, 0);
        } else if (!fnmatch("ptk", info->key, 0)) {
            if (parse_byte_array(supp->keys.ptk.key, sizeof(supp->keys.ptk.key), info->value))
                FATAL(1, "%s:%d: invalid ptk: %s", info->filename, info->linenr, info->value);
            supp->keys.ptk.installation_s = time_now_s(CLOCK_MONOTONIC);
        } else if (!fnmatch("gtk\\[*]", info->key, 0)) {
            if (parse_byte_array(supp->gtks[info->key_array_index].key, sizeof(supp->gtks[info->key_array_index].key), info->value))
                FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("gtk\\[*].expiration_timestamp_ms", info->key, 0)) {
            gtks_expiration_ts_ms[info->key_array_index] = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("gtk\\[*].frame_counter", info->key, 0)) {
             supp->gtks[info->key_array_index].frame_counter = add32sat((uint32_t)strtoul(info->value, NULL, 0),
                                                                        WS_GTK_COUNTER_INC);
        } else if (!fnmatch("lgtk\\[*]", info->key, 0)) {
            if (parse_byte_array(supp->gtks[info->key_array_index + WS_GTK_COUNT].key,
                sizeof(supp->gtks[info->key_array_index + WS_GTK_COUNT].key), info->value))
                FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
        } else if (!fnmatch("lgtk\\[*].expiration_timestamp_ms", info->key, 0)) {
            gtks_expiration_ts_ms[info->key_array_index + WS_GTK_COUNT] = strtoull(info->value, NULL, 0);
        } else if (!fnmatch("lgtk\\[*].frame_counter", info->key, 0)) {
             supp->gtks[info->key_array_index + WS_GTK_COUNT].frame_counter = add32sat((uint32_t)strtoul(info->value, NULL, 0),
                                                                                       WS_GTK_COUNTER_INC);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);

    for (uint8_t i = 0; i < ARRAY_SIZE(gtks_expiration_ts_ms); i++) {
        if (!gtks_expiration_ts_ms[i])
            continue;
        if (storage_offset_ms > gtks_expiration_ts_ms[i] || now_ms > gtks_expiration_ts_ms[i] - storage_offset_ms) {
            WARN("sec: %s expired", tr_gtkname(i));
            ws_gtk_clear(&supp->timer_group, &supp->gtks[i]);
            continue;
        }
        timer_start_abs(&supp->timer_group, &supp->gtks[i].expiration_timer, gtks_expiration_ts_ms[i] - storage_offset_ms);
        TRACE(TR_SECURITY, "sec: install %s=%s lifetime=%"PRIu64"s cnt=%u", tr_gtkname(i),
              tr_key(supp->gtks[i].key, sizeof(supp->gtks[i].key)),
              timer_remaining_ms(&supp->gtks[i].expiration_timer) / 1000,
              supp->gtks[i].frame_counter);
        supp->on_gtk_change(supp, supp->gtks[i].key, supp->gtks[i].frame_counter, i + 1);
    }
    return true;
}

void supp_storage_store(struct supp_ctx *supp, bool force_write)
{
    uint64_t storage_offset_ms = time_get_storage_offset_ms();
    struct storage_parse_info *info;
    char str_buf[256];

    info = storage_open_prefix("network-keys", "w");
    if (!info)
        return;

    str_key(supp->cfg->eui64.u8, sizeof(supp->cfg->eui64.u8), str_buf, sizeof(str_buf));
    fprintf(info->file, "eui64 = %s\n\n", str_buf);

    if (supp->keys.pmk.installation_s) {
        str_key(supp->keys.pmk.key, sizeof(supp->keys.pmk.key), str_buf, sizeof(str_buf));
        fprintf(info->file, "pmk = %s\n", str_buf);
        fprintf(info->file, "pmk.replay_counter = %"PRIu64"\n\n", supp->keys.pmk.replay_counter);
    }

    if (supp->keys.ptk.installation_s) {
        str_key(supp->keys.ptk.key, sizeof(supp->keys.ptk.key), str_buf, sizeof(str_buf));
        fprintf(info->file, "ptk = %s\n", str_buf);
    }

    for (uint8_t i = 0; i < ARRAY_SIZE(supp->gtks); i++) {
        if (!ws_gtk_installed(&supp->gtks[i]))
            continue;
        fprintf(info->file, "\n");
        str_key(supp->gtks[i].key, sizeof(supp->gtks[i].key), str_buf, sizeof(str_buf));
        if (i < WS_GTK_COUNT) {
            fprintf(info->file, "gtk[%d] = %s\n", i, str_buf);
            fprintf(info->file, "gtk[%d].expiration_timestamp_ms = %"PRIu64"\n", i,
                    supp->gtks[i].expiration_timer.expire_ms + storage_offset_ms);
            fprintf(info->file, "gtk[%d].frame_counter = %"PRIu32"\n", i, supp->gtks[i].frame_counter);
        } else {
            fprintf(info->file, "lgtk[%d] = %s\n", i - WS_GTK_COUNT, str_buf);
            fprintf(info->file, "lgtk[%d].expiration_timestamp_ms = %"PRIu64"\n", i - WS_GTK_COUNT,
                    supp->gtks[i].expiration_timer.expire_ms + storage_offset_ms);
            fprintf(info->file, "lgtk[%d].frame_counter = %"PRIu32"\n", i - WS_GTK_COUNT, supp->gtks[i].frame_counter);
        }
    }
    if (force_write)
        storage_close_flush(info);
    else
        storage_close(info);
}

void supp_storage_clear(void)
{
    storage_delete((const char *[]){ "network-keys", NULL });
}
