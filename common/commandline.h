/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#include "common/named_values.h"

struct storage_parse_info;

struct number_limit {
    int min;
    int max;
};

struct option_struct {
    const char *key;
    void *dest_hint;
    void (*fn)(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
    const void *param;
};

extern const struct number_limit valid_unsigned;
extern const struct number_limit valid_positive;
extern const struct number_limit valid_int8;
extern const struct number_limit valid_uint16;

extern const struct name_value valid_tristate[];
extern const struct name_value valid_booleans[];

void conf_deprecated(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_bool(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_enum(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_enum_int_hex(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_enum_int(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_number(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_seconds_from_minutes(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_ms_from_s(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_string(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_netmask(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_netaddr(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_bitmask(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_add_flags(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_flags(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_phy_op_modes(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_pem(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);

void parse_config_line(const struct option_struct opts[], struct storage_parse_info *info);
void parse_config_file(const struct option_struct opts[], const char *filename);

#endif
