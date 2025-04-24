/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <fnmatch.h>
#include <unistd.h>
#include <ctype.h>

#include "common/ws/ws_interface.h"
#include "common/key_value_storage.h"
#include "common/parsers.h"

#include "wsrd_storage.h"
#include "wsrd.h"

bool wsrd_storage_load(struct wsrd *wsrd)
{
    char netname[WS_NETNAME_LEN + 1] = { };
    struct storage_parse_info *info;
    int ret;

    info = storage_open_prefix("network-config", "r");
    if (!info)
        return false;

    while (true) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("network_name", info->key, 0)) {
             if (parse_escape_sequences(netname, info->value, 33))
                WARN("%s:%d: parsing error (escape sequence or too long)", info->filename, info->linenr);
            if (memcmp(wsrd->ws.netname, netname, sizeof(wsrd->ws.netname)))
                FATAL(1, "network name mismatch between configuration and previous state loaded from storage");
        } else if (!fnmatch("pan_id", info->key, 0)) {
            wsrd->ws.pan_id = (uint16_t)strtoul(info->value, NULL, 0);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);
    return true;
}

void wsrd_storage_store(const struct wsrd *wsrd)
{
    char netname[WS_NETNAME_LEN + 1] = { };
    struct storage_parse_info *info;
    char str_buf[256] = { };

    info = storage_open_prefix("network-config", "w");
    if (!info)
        return;

    memcpy(netname, wsrd->ws.netname, sizeof(wsrd->ws.netname));
    str_bytes(netname, strlen(netname), NULL, str_buf, sizeof(str_buf), FMT_ASCII_ALNUM);
    fprintf(info->file, "network_name = %s\n", str_buf);
    fprintf(info->file, "pan_id = %#04x\n", wsrd->ws.pan_id);
    fflush(info->file);
    fsync(fileno(info->file));
    storage_close(info);
}

void wsrd_storage_clear(void)
{
    storage_delete((const char *[]){ "network-config", NULL });
}
