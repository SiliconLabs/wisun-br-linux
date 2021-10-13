/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_NAMED_VALUES_H
#define WSBR_NAMED_VALUES_H

struct name_value {
    char *name;
    int val;
};

extern const struct name_value valid_ws_domains[];
extern const struct name_value valid_ws_size[];
extern const struct name_value valid_traces[];
extern const struct name_value valid_booleans[];

const char *val_to_str(int val, const struct name_value table[]);
int str_to_val(const char *str, const struct name_value table[]);

#endif
