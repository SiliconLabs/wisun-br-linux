/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */

#include "common/log.h"
#include "common/named_values.h"

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
    return NULL; /* never reached */
}

int str_to_val(const char *str, const struct name_value table[])
{
    int i;

    for (i = 0; table[i].name; i++)
        if (!strcasecmp(table[i].name, str))
            return table[i].val;

    // This function is called to convert user provided user. So exit with FATAL
    // in case of error
    FATAL(1, "invalid value: %s", str);
    return -1; /* never reached */
}
