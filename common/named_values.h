/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef NAMED_VALUES_H
#define NAMED_VALUES_H

struct name_value {
    char *name;
    int val;
};

const char *val_to_str(int val, const struct name_value table[], const char *def);
int str_to_val(const char *str, const struct name_value table[]);

#endif
