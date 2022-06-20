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

#include "ns_file_system.h"

static char *file_system_root;

int ns_file_system_set_root_path(const char *root_path)
{
    char *new_root_path;

    if (root_path == NULL || !root_path[0]) {
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
