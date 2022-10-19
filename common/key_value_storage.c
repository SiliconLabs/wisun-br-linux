/*
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
