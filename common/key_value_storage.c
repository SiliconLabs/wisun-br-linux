/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <glob.h>

#include "common/log.h"
#include "common/memutils.h"

#include "key_value_storage.h"

const char *g_storage_prefix = NULL;

int storage_check_access(const char *storage_prefix)
{
    char *tmp;

    if (!storage_prefix || !strlen(storage_prefix))
        return 0;
    if (storage_prefix[strlen(storage_prefix) - 1] == '/') {
        return access(storage_prefix, W_OK);
    } else {
        tmp = strdupa(storage_prefix);
        return access(dirname(tmp), W_OK);
    }
}

struct storage_parse_info *storage_open(const char *filename, const char *mode)
{
    struct storage_parse_info *info;

    info = zalloc(sizeof(struct storage_parse_info));
    snprintf(info->filename, sizeof(info->filename), "%s", filename);
    info->file = fopen(info->filename, mode);
    if (!info->file) {
        free(info);
        return NULL;
    }
    return info;
}

struct storage_parse_info *storage_open_prefix(const char *filename, const char *mode)
{
    struct storage_parse_info *info;
    char *full_filename;
    int ret;

    if (!g_storage_prefix)
        return NULL;
    ret = asprintf(&full_filename, "%s%s", g_storage_prefix, filename);
    FATAL_ON(ret < 0, 2, "%s: cannot allocate memory", __func__);
    info = storage_open(full_filename, mode);
    free(full_filename);
    return info;
}

int storage_close(struct storage_parse_info *info)
{
    FILE *file;

    BUG_ON(!info);
    BUG_ON(!info->file);
    file = info->file;
    free(info);
    return fclose(file);
}

static char *storage_get_line(struct storage_parse_info *info)
{
    char garbage;
    int len;

    BUG_ON(!info);
    BUG_ON(!info->file);
    do {
        if (!fgets(info->line, sizeof(info->line), info->file))
            return NULL;
        info->linenr++;
        /* drop comments */
        *(strchrnul(info->line, '#')) = '\0';
        len = strlen(info->line);
        if (len > 0 && info->line[len - 1] == '\n')
            info->line[--len] = '\0';
        if (len > 0 && info->line[len - 1] == '\r')
            info->line[--len] = '\0';
        /* drop blank lines */
        if (sscanf(info->line, " %c", &garbage) == EOF)
            len = 0;
    } while (len <= 0);
    return info->line;
}

int storage_parse_line(struct storage_parse_info *info)
{
    char garbage;

    BUG_ON(!info);
    BUG_ON(!info->file);
    if (!storage_get_line(info))
        // EOF is the same value than -EPERM. Ensure that parse_line() will
        // never return -EPERM.
        return EOF;
    if (sscanf(info->line, " %256[^= ] = %256s %c", info->key, info->value, &garbage) != 2)
        return -EINVAL;
    if (sscanf(info->key, "%*[^[][%u]", &info->key_array_index) != 1)
        info->key_array_index = UINT_MAX;
    return 0;
}

void storage_delete(const char *files[])
{
    char filename[PATH_MAX];
    glob_t globbuf;
    int ret;

    if (!g_storage_prefix)
        return;

    for (; *files; files++) {
        snprintf(filename, sizeof(filename), "%s%s", g_storage_prefix, *files);
        ret = glob(filename, 0, NULL, &globbuf);
        if (ret == GLOB_NOMATCH) {
            continue;
        } else if (ret) {
            WARN("glob %s returned an error", filename);
            return;
        }
        for (int i = 0; globbuf.gl_pathv[i]; i++) {
            ret = unlink(globbuf.gl_pathv[i]);
            WARN_ON(ret < 0, "unlink %s: %m", globbuf.gl_pathv[i]);
        }
        globfree(&globbuf);
    }
}
