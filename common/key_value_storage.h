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
#ifndef KEY_VALUE_STORAGE_H
#define KEY_VALUE_STORAGE_H

/**
 * Helpers to read and write configuration files. A configuration files a series
 * of key/values assignments with possible comments.
 *
 * All the data is provided by struct storage_parse_info. Fields file and
 * filename are filled by storage_open() (and storage_open_prefix()). These
 * fields are sufficient for write access.
 *
 * If storage_open() fail, error can be read from errno.
 *
 * To parse an existing file, parse_line() can be called until it returns EOF
 * (= -1). Function storage_parse_line() fills storage_parse_info with the
 * key/value couple it find. If a parse error happens, it returns < -1.
 *
 * In addition, if storage_parse_line() detects a number under brackets (like in
 * "gtk[0]"), the value under bracket is placed in key_array_index (otherwise,
 * key_array_index value is UINT_MAX)
 */

#include <stdio.h>
#include <limits.h>

struct storage_parse_info {
    FILE *file;
    char filename[PATH_MAX];
    int linenr;
    char line[256];
    char key[256], value[256];
    unsigned int key_array_index;
};

extern const char *g_storage_prefix;

int storage_check_access(const char *storage_prefix);
struct storage_parse_info *storage_open(const char *filename, const char *mode);
struct storage_parse_info *storage_open_prefix(const char *filename, const char *mode);
int storage_close(struct storage_parse_info *file);
int storage_parse_line(struct storage_parse_info *file);
void storage_delete(const char *files[]);

#endif
