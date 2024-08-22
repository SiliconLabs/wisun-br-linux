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
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "common/key_value_storage.h"
#include "common/time_extra.h"
#include "common/log.h"
#include "common/string_extra.h"
#include "rpl_storage.h"
#include "rpl.h"

void rpl_storage_store_config(const struct rpl_root *root)
{
    char ipv6_str[STR_MAX_LEN_IPV6];
    struct storage_parse_info *nvm;

    nvm = storage_open_prefix("rpl-config", "w");
    if (!nvm) {
        WARN("%s: unable to open file: \"rpl-config\"", __func__);
        return;
    }
    fprintf(nvm->file, "instance_id = %u\n", root->instance_id);
    fprintf(nvm->file, "dodag_id = %s\n", str_ipv6(root->dodag_id, ipv6_str));
    fprintf(nvm->file, "dodag_version_number = %u\n", root->dodag_version_number);
    fprintf(nvm->file, "dtsn = %u\n", root->dtsn);
    storage_close(nvm);
}

void rpl_storage_load_config(struct rpl_root *root, const char *filename)
{
    struct storage_parse_info *nvm;
    int ret;

    nvm = storage_open(filename, "r");
    if (!nvm) {
        WARN("%s %s failure", __func__, filename);
        return;
    }
    while (true) {
        ret = storage_parse_line(nvm);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", nvm->filename, nvm->linenr, nvm->line);
        } else if (!fnmatch("instance_id", nvm->key, 0)) {
            root->instance_id = strtoul(nvm->value, NULL, 0);
        } else if (!fnmatch("dodag_id", nvm->key, 0)) {
            ret = inet_pton(AF_INET6, nvm->value, nvm->key);
            WARN_ON(ret != 1, "%s:%d: invalid value: %s", nvm->filename, nvm->linenr, nvm->value);
        } else if (!fnmatch("dodag_version_number", nvm->key, 0)) {
            root->dodag_version_number = strtoul(nvm->value, NULL, 0);
        } else if (!fnmatch("dtsn", nvm->key, 0)) {
            root->dtsn = strtoul(nvm->value, NULL, 0);
        } else {
            WARN("%s:%d: invalid key: '%s'", nvm->filename, nvm->linenr, nvm->line);
        }
    }
    storage_close(nvm);
}

void rpl_storage_store_target(const struct rpl_root *root, const struct rpl_target *target)
{
    char time_str[STR_MAX_LEN_DATE];
    char ipv6_str[STR_MAX_LEN_IPV6];
    struct storage_parse_info *nvm;
    char filename[PATH_MAX];
    time_t tstamp;

    strcpy(filename, "rpl-");
    str_ipv6(target->prefix, filename + strlen(filename));
    nvm = storage_open_prefix(filename, "w");
    if (!nvm) {
        WARN("%s: unable to open file: %s", __func__, filename);
        return;
    }

    fprintf(nvm->file, "path_seq = %u\n", target->path_seq);
    tstamp = target->path_seq_tstamp_s + time_get_storage_offset();
    str_date(tstamp, time_str);
    fprintf(nvm->file, "# %s\n", time_str);
    fprintf(nvm->file, "path_seq_timestamp = %lu\n",
            target->path_seq_tstamp_s + time_get_storage_offset());
    fprintf(nvm->file, "external = %u\n", target->external);
    for (uint8_t i = 0; i < root->pcs + 1; i++) {
        if (!memzcmp(target->transits + i, sizeof(struct rpl_transit)))
            continue;
        str_ipv6(target->transits[i].parent, ipv6_str);
        fprintf(nvm->file, "parent[%u] = %s\n", i, ipv6_str);
        fprintf(nvm->file, "parent[%u].path_lifetime_s = %u\n", i,
                target->transits[i].path_lifetime_s);
    }
    storage_close(nvm);
}

void rpl_storage_del_target(const struct rpl_root *root, const struct rpl_target *target)
{
    char filename[PATH_MAX];

    strcpy(filename, "rpl-");
    str_ipv6(target->prefix, filename + strlen(filename));
    storage_delete((const char *[]){ filename, NULL });
}

void rpl_storage_load_target(struct rpl_root *root, const char *filename)
{
    struct storage_parse_info *nvm;
    struct rpl_target *target;
    const char *strptr;
    uint8_t prefix[16];
    int ret;

    strptr = strrchr(filename, '-');
    if (!strptr) {
        WARN("%s %s failure", __func__, filename);
        return;
    }
    ret = inet_pton(AF_INET6, strptr + 1, prefix);
    if (ret != 1) {
        WARN("%s %s failure", __func__, filename);
        return;
    }
    target = rpl_target_new(root, prefix);
    BUG_ON(!target);

    nvm = storage_open(filename, "r");
    if (!nvm) {
        WARN("%s %s failure", __func__, filename);
        return;
    }
    while (true) {
        ret = storage_parse_line(nvm);
        if (ret == EOF)
            break;
        if (ret) {
            WARN("%s:%d: invalid line: '%s'", nvm->filename, nvm->linenr, nvm->line);
        } else if (!fnmatch("path_seq", nvm->key, 0)) {
            target->path_seq = strtoul(nvm->value, NULL, 0);
        } else if (!fnmatch("path_seq_timestamp", nvm->key, 0)) {
            target->path_seq_tstamp_s = strtoull(nvm->value, NULL, 0) - time_get_storage_offset();
        } else if (!fnmatch("external", nvm->key, 0)) {
            target->external = strtoul(nvm->value, NULL, 0);
        } else if (!fnmatch("parent\\[*].path_lifetime_s", nvm->key, 0) && nvm->key_array_index < root->pcs + 1) {
            target->transits[nvm->key_array_index].path_lifetime_s = strtoul(nvm->value, NULL, 0);
        } else if (!fnmatch("parent\\[*]", nvm->key, 0) && nvm->key_array_index < root->pcs + 1) {
            ret = inet_pton(AF_INET6, nvm->value, target->transits[nvm->key_array_index].parent);
            WARN_ON(ret != 1, "%s:%d: invalid value: %s", nvm->filename, nvm->linenr, nvm->value);
        } else {
            WARN("%s:%d: invalid key: '%s'", nvm->filename, nvm->linenr, nvm->line);
        }
    }
    storage_close(nvm);

    // Potentially outdated transits will be checked right away
    timer_start_rel(&root->timer_group, &target->timer, 0);
}

void rpl_storage_load(struct rpl_root *root)
{
    char globexpr[PATH_MAX];
    glob_t globbuf;
    int ret;

    if (!g_storage_prefix)
        return;
    snprintf(globexpr, sizeof(globexpr), "%s%s", g_storage_prefix, "rpl-*");
    ret = glob(globexpr, 0, NULL, &globbuf);
    if (ret && ret != GLOB_NOMATCH)
        WARN("%s: glob %s returned %u", __func__, globexpr, ret);
    if (ret)
        return;
    for (int i = 0; globbuf.gl_pathv[i]; i++) {
        if (strstr(globbuf.gl_pathv[i], "rpl-config"))
            rpl_storage_load_config(root, globbuf.gl_pathv[i]);
        else
            rpl_storage_load_target(root, globbuf.gl_pathv[i]);
    }
    globfree(&globbuf);
}
