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

#include <netdb.h>

#include "common/named_values.h"

struct storage_parse_info;

/*
 * This module allows to implement a configuration file parser. Paramaters can
 * also be parsed individually to expose a command line interface. Integrators
 * define an array of option_struct to declare a list of parameter names, each
 * with a parsing function, and the output location as a structure field offset.
 *
 * To ease code factorization, a notion of option groups is introduced, which
 * allows to define a list of configration parameters for a module and reuse it
 * in different projects. API functions take an array of option_group instead
 * of options directly. Group lists require a sentinel value, and each group
 * entry consists of an option list with sentinel, and a pointer to a structure
 * to populate.
 *
 * Example:
 *
 * struct main_config {
 *     int foo;
 *     char bar[100];
 *     struct module_config mod;
 * };
 *
 * static const struct option_struct main_opts[] = {
 *     { "foo", offsetof(struct context, foo), conf_set_number, NULL },
 *     { "bar", offsetof(struct context, bar), conf_set_string, (void *)sizeof(NULL) },
 *     { }
 * };
 * extern const struct option_struct module_opts; // Defined in module.h
 * const struct option_group groups[] = {
 *     { main_opts,   config },       // Populate config->foo and config->bar
 *     { module_opts, &config->mod }, // Populate config->mod
 *     { }
 * };
 */

struct number_limit {
    int min;
    int max;
};

struct option_struct {
    const char *key;
    uintptr_t offset;
    void (*fn)(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
    const void *param;
};

struct option_group {
    const struct option_struct *opts;
    void *ptr;
};

extern const struct number_limit valid_gtk_new_install_required;
extern const struct number_limit valid_unsigned;
extern const struct number_limit valid_positive;
extern const struct number_limit valid_int8;
extern const struct number_limit valid_uint16;
extern const struct number_limit valid_percent;

extern const struct name_value valid_tristate[];
extern const struct name_value valid_booleans[];

extern const struct addrinfo valid_ipv4or6;
extern const struct addrinfo valid_ipv6;

void conf_deprecated(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_bool(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_enum(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_enum_int_hex(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_enum_int(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_number(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_u8(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
void conf_set_u16(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
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
void conf_set_array(const struct storage_parse_info *info, void *raw_dest, const void *raw_param);

void parse_config_line(const struct option_group opts[], struct storage_parse_info *info);
void parse_config_file(const struct option_group opts[], const char *filename);

#endif
