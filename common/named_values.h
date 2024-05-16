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
#ifndef NAMED_VALUES_H
#define NAMED_VALUES_H

/*
 * Allow to manipulate numbers associated to symbolic names. Typically, it is
 * used to display decoded frames (using val_to_str()) or to convert a user
 * input into numeric representation (with str_to_val()).
 *
 * Note these functions iterate on "table" array until "name" field is NULL.
 */

struct name_value {
    char *name;
    int val;
};

const char *val_to_str(int val, const struct name_value table[], const char *def);
int str_to_val(const char *str, const struct name_value table[]);

#endif
