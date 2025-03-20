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

#include <fnmatch.h>
#include <unistd.h>

#include "common/key_value_storage.h"
#include "common/memutils.h"
#include "common/parsers.h"
#include "common/log.h"
#include "common/version.h"

#include "ws_pan_info_storage.h"

// If PAN version lifetime would be 10 minutes, 1000 increments is about 7 days
// i.e. storage must be written at least once a week
#define PAN_VERSION_STORAGE_READ_INCREMENT    1000
#define LFN_VERSION_STORAGE_READ_INCREMENT    1000

void ws_pan_info_storage_read(int *bsi, int *pan_id, uint16_t *pan_version, uint16_t *lfn_version,
                              char network_name[33])
{
    struct storage_parse_info *info = storage_open_prefix("br-info", "r");
    int ret;

    if (!info)
        return;
    for (;;) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("bsi", info->key, 0)) {
            *bsi = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("pan_id", info->key, 0)) {
            *pan_id = strtoul(info->value, NULL, 0);
        } else if (!fnmatch("pan_version", info->key, 0)) {
            *pan_version = strtoul(info->value, NULL, 0) + PAN_VERSION_STORAGE_READ_INCREMENT;
        } else if (!fnmatch("lfn_version", info->key, 0)) {
            *lfn_version = strtoul(info->value, NULL, 0) + LFN_VERSION_STORAGE_READ_INCREMENT;
        } else if (!fnmatch("network_name", info->key, 0)) {
            if (parse_escape_sequences(network_name, info->value, 33))
                WARN("%s:%d: parsing error (escape sequence or too long)", info->filename, info->linenr);
        } else if (!fnmatch("api_version", info->key, 0)) {
            // Ignore for now
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);
}

void ws_pan_info_storage_write(uint16_t bsi, uint16_t pan_id, uint16_t pan_version, uint16_t lfn_version,
                               const char network_name[33])
{
    struct storage_parse_info *info = storage_open_prefix("br-info", "w");
    char str_buf[256];

    if (!info)
        return;
    fprintf(info->file, "api_version = %#08x\n", version_daemon_api);
    fprintf(info->file, "bsi = %d\n", bsi);
    fprintf(info->file, "pan_id = %#04x\n", pan_id);
    fprintf(info->file, "pan_version = %d\n", pan_version);
    fprintf(info->file, "lfn_version = %d\n", lfn_version);
    str_bytes(network_name, strlen(network_name), NULL, str_buf, sizeof(str_buf), FMT_ASCII_ALNUM);
    fprintf(info->file, "network_name = %s\n", str_buf);
    fflush(info->file);
    fsync(fileno(info->file));
    storage_close(info);
}
