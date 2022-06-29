/*
 * Copyright (c) 2017-2020, Pelion and affiliates.
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

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "stack/ns_file_system.h"

#include "service_libs/utils/ns_file.h"

static char *file_system_root;

int ns_file_system_set_root_path(const char *root_path)
{
    char *new_root_path;

    if (root_path == NULL) {
        // File system usage disabled
        free(file_system_root);
        file_system_root = NULL;
        return 0;
    }

    new_root_path = malloc(strlen(root_path) + 1);
    if (!new_root_path) {
        // mem alloc failed
        return -2;
    }

    free(file_system_root);
    file_system_root = new_root_path;
    strcpy(file_system_root, root_path);

    return 0;
}

char *ns_file_system_get_root_path(void)
{
    return file_system_root;
}

FILE *ns_fopen(const char *file_name, const char *mode)
{
    if (!file_name || !mode || (*mode != 'r' && *mode != 'w')) {
        return NULL;
    }

    FILE *file = fopen(file_name, mode);
    if (file == NULL) {
        return NULL;
    }

    return file;
}

int ns_fclose(FILE *ns_handle)
{
    if (!ns_handle) {
        return -1;
    }

    fclose(ns_handle);
    return 0;
}

int ns_fremove(const char *file_name)
{
    if (!file_name) {
        return -1;
    }

    return remove(file_name);
}

size_t ns_fwrite(FILE *ns_handle, const void *buffer, size_t size)
{
    if (!ns_handle || !buffer || size == 0) {
        return 0;
    }

    rewind(ns_handle);
    return fwrite(buffer, 1, size, ns_handle);
}

size_t ns_fread(FILE *ns_handle, void *buffer, size_t size)
{
    if (!ns_handle || !buffer || size == 0) {
        return 0;
    }

    rewind(ns_handle);
    return fread(buffer, 1, size, ns_handle);
}

int ns_fsize(FILE *ns_handle, size_t *size)
{
    if (!ns_handle || !size) {
        return 0;
    }

    fseek(ns_handle, 0L, SEEK_END);
    return ftell(ns_handle);
}
