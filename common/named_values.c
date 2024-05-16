/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include "common/log.h"

#include "named_values.h"

const char *val_to_str(int val, const struct name_value table[], const char *def)
{
    int i;

    for (i = 0; table[i].name; i++)
        if (val == table[i].val)
            return table[i].name;

    if (def)
        return def;

    // This function is called to print values. If val does not exists, it is a
    // bug
    BUG("invalid value: %d", val);
}

int str_to_val(const char *str, const struct name_value table[])
{
    int i;

    if (!str)
        FATAL(1, "invalid empty string");
    for (i = 0; table[i].name; i++)
        if (!strcasecmp(table[i].name, str))
            return table[i].val;

    // This function is called to convert user provided user. So exit with FATAL
    // in case of error
    FATAL(1, "invalid value: %s", str);
}
