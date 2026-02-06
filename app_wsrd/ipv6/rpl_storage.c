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
#include <arpa/inet.h>
#include <fnmatch.h>
#include <unistd.h>

#include "common/key_value_storage.h"
#include "common/log.h"

#include "rpl.h"
#include "rpl_storage.h"

bool rpl_storage_load(struct rpl_ctx *rpl, struct in6_addr *dodag_id)
{
    struct storage_parse_info *info;
    int ret;

    info = storage_open_prefix("rpl", "r");
    if (!info)
        return false;

    while (true) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", info->filename, info->linenr, info->line);
        } else if (!fnmatch("path_seq", info->key, 0)) {
            rpl->path_seq = (uint8_t)strtoul(info->value, NULL, 0);
        } else if (!fnmatch("dodag_id", info->key, 0)) {
            ret = inet_pton(AF_INET6, info->value, dodag_id->s6_addr);
            WARN_ON(ret != 1, "%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
        } else {
            WARN("%s:%d: invalid key: '%s'", info->filename, info->linenr, info->line);
        }
    }
    storage_close(info);
    return true;
}

void rpl_storage_store(const struct rpl_ctx *rpl, const struct in6_addr *dodag_id)
{
    struct storage_parse_info *info;
    char ipv6_str[STR_MAX_LEN_IPV6];

    info = storage_open_prefix("rpl", "w");
    if (!info)
        return;

    fprintf(info->file, "path_seq = %u\n", rpl->path_seq);
    fprintf(info->file, "dodag_id = %s\n", str_ipv6(dodag_id->s6_addr, ipv6_str));
    storage_close_flush(info);
}
