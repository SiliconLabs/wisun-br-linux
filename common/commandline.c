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
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

#include "common/specs/ws.h"
#include "common/bits.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/named_values.h"
#include "common/netinet_in_extra.h"
#include "common/parsers.h"
#include "common/ws_regdb.h"

#include "commandline.h"

const struct number_limit valid_gtk_new_install_required = {
    0, 100
};

const struct number_limit valid_unsigned = {
    0, INT_MAX
};

const struct number_limit valid_positive = {
    1, INT_MAX
};

const struct number_limit valid_int8 = {
    INT8_MIN, INT8_MAX
};

const struct number_limit valid_uint16 = {
    0, UINT16_MAX
};

const struct name_value valid_tristate[] = {
    { "auto",    -1 },
    { "true",    1 },
    { "false",   0 },
    { "enable",  1 },
    { "disable", 0 },
    { "yes",     1 },
    { "no",      0 },
    { "y",       1 },
    { "n",       0 },
    { "1",       1 },
    { "0",       0 },
    { NULL },
};

const struct name_value valid_booleans[] = {
    { "true",    1 },
    { "false",   0 },
    { "enable",  1 },
    { "disable", 0 },
    { "yes",     1 },
    { "no",      0 },
    { "y",       1 },
    { "n",       0 },
    { "1",       1 },
    { "0",       0 },
    { NULL },
};

void conf_deprecated(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    FATAL(1, "%s:%d \"%s\" is deprecated", info->filename, info->linenr, info->key);
}

void conf_set_bool(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    bool *dest = raw_dest;

    BUG_ON(raw_param);
    *dest = str_to_val(info->value, valid_booleans);
}

void conf_set_enum(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    const struct name_value *specs = raw_param;
    int *dest = raw_dest;

    *dest = str_to_val(info->value, specs);
}

void conf_set_enum_int_hex(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    const int *specs = raw_param;
    int *dest = raw_dest;
    char *end;
    int i;

    *dest = strtol(info->value, &end, 16);
    if (*end)
        FATAL(1, "%s:%d: invalid number: %s", info->filename, info->linenr, info->value);

    for (i = 0; specs[i] != INT_MIN; i++)
        if (specs[i] == *dest)
            return;
    FATAL(1, "%s:%d: invalid value: %s", info->filename, info->linenr, info->value);
}

void conf_set_enum_int(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    const int *specs = raw_param;
    int *dest = raw_dest;
    char *end;
    int i;

    *dest = strtol(info->value, &end, 0);
    if (*end)
        FATAL(1, "%s:%d: invalid number: %s", info->filename, info->linenr, info->value);

    for (i = 0; specs[i] != INT_MIN; i++)
        if (specs[i] == *dest)
            return;
    FATAL(1, "%s:%d: invalid %s: %s", info->filename, info->linenr, info->key, info->value);
}

void conf_set_number(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    const struct number_limit *specs = raw_param;
    int *dest = raw_dest;
    char *end;

    *dest = strtol(info->value, &end, 0);
    if (*end)
        FATAL(1, "%s:%d: invalid number: %s", info->filename, info->linenr, info->value);
    if (specs && (specs->min > *dest || specs->max < *dest))
        FATAL(1, "%s:%d: invalid %s: %s", info->filename, info->linenr, info->key, info->value);
}

void conf_set_seconds_from_minutes(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    int *dest = raw_dest;

    conf_set_number(info, raw_dest, raw_param);
    *dest *= 60;
}

void conf_set_ms_from_s(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    int *dest = raw_dest;

    conf_set_number(info, raw_dest, raw_param);
    *dest *= 1000;
}

void conf_set_string(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    uintptr_t max_len = (uintptr_t)raw_param;
    char *dest = raw_dest;
    int ret;

    ret = parse_escape_sequences(dest, info->value, max_len);
    if (ret == -EINVAL)
        FATAL(1, "%s:%d: invalid escape sequence", info->filename, info->linenr);
    else if (ret == -ERANGE)
        FATAL(1, "%s:%d: maximum length for '%s' is %zu characters",
              info->filename, info->linenr, info->key, max_len - 1);
    else if (ret < 0)
        FATAL(1, "%s:%d: parsing error", info->filename, info->linenr);
}

void conf_set_netmask(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    char mask[STR_MAX_LEN_IPV6];
    int len;

    BUG_ON(raw_param);
    if (sscanf(info->value, "%[0-9a-zA-Z:]/%d", mask, &len) != 2)
        FATAL(1, "%s:%d: invalid %s: %s", info->filename, info->linenr, info->key, info->value);
    if (len != 64)
        FATAL(1, "%s:%d: invalid prefix length: %d", info->filename, info->linenr, len);
    if (inet_pton(AF_INET6, mask, raw_dest) != 1)
        FATAL(1, "%s:%d: invalid prefix: %s", info->filename, info->linenr, mask);
    if (!IN6_IS_ADDR_UC_GLOBAL(raw_dest))
        FATAL(1, "%s:%d: invalid prefix not global unicast: %s", info->filename, info->linenr, mask);
}

void conf_set_netaddr(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    struct sockaddr *dest = raw_dest;
    struct addrinfo *results;
    int err;

    BUG_ON(raw_param);
    err = getaddrinfo(info->value, NULL, NULL, &results);
    if (err != 0)
        FATAL(1, "%s:%d: %s: %s", info->filename, info->linenr, info->value, gai_strerror(err));
    BUG_ON(!results);
    memcpy(dest, results->ai_addr, results->ai_addrlen);
    freeaddrinfo(results);
}

void conf_set_bitmask(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    BUG_ON(raw_param);
    if (parse_bitmask(raw_dest, 32, info->value) < 0)
        FATAL(1, "%s:%d: invalid range: %s", info->filename, info->linenr, info->value);
}

void conf_add_flags(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    const struct name_value *specs = raw_param;
    unsigned int *dest = raw_dest;
    char *tmp, *substr;

    tmp = strdup(info->value);
    substr = strtok(tmp, ",");
    do {
        *dest |= str_to_val(substr, specs);
    } while ((substr = strtok(NULL, ",")));
    free(tmp);
}

void conf_set_flags(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    unsigned int *dest = raw_dest;

    *dest = 0;
    conf_add_flags(info, dest, raw_param);
}

void conf_set_phy_op_modes(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    struct storage_parse_info sub_info = *info; // Copy struct to reuse conf_set_enum_int
    uint8_t *dest = raw_dest;
    char *tmp, *substr;
    int phy_mode_id;
    int i;

    memset(dest, 0, FIELD_MAX(WS_MASK_POM_COUNT) + 1 - 1);
    // FIXME: expect trouble if 0xFF become valid PHY IDs.
    if (!strcmp(info->value, "auto")) {
        dest[0] = -1;
        return;
    }
    if (!strcmp(info->value, "none"))
        return;
    i = 0;
    tmp = strdup(info->value);
    for (substr = strtok(tmp, ","); substr; substr = strtok(NULL, ",")) {
        // Keep room for sentinel
        FATAL_ON(i >= FIELD_MAX(WS_MASK_POM_COUNT) - 1, 1,
                 "%s:%d: too many entries (max: %u)",
                 info->filename, info->linenr,
                 FIELD_MAX(WS_MASK_POM_COUNT) - 1);
        strcpy(sub_info.value, substr);
        conf_set_enum_int(&sub_info, &phy_mode_id, raw_param);
        dest[i++] = phy_mode_id;
    }
    free(tmp);
}

void conf_set_pem(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    struct iovec *dest = raw_dest;
    char *dest_str;
    struct stat st;
    ssize_t ret;
    int fd;

    BUG_ON(raw_param);
    fd = open(info->value, O_RDONLY);
    FATAL_ON(fd < 0, 1, "%s:%d: %s: %m", info->filename, info->linenr, info->value);
    ret = fstat(fd, &st);
    FATAL_ON(fd < 0, 1, "%s:%d: %s: %m", info->filename, info->linenr, info->value);
    dest->iov_base = realloc(dest->iov_base, st.st_size + 1);
    FATAL_ON(!dest->iov_base, 2, "%s: realloc(): %m", __func__);
    dest_str = (char *)dest->iov_base;
    // See https://github.com/ARMmbed/mbedtls/issues/3896 and mbedtls_x509_crt_parse()
    dest_str[st.st_size] = '\0';
    ret = read(fd, dest->iov_base, st.st_size);
    if (ret != st.st_size)
        FATAL(1, "%s:%d: %s: %s", info->filename, info->linenr, info->value,
              ret < 0 ? strerror(errno) : "Short read");
    dest->iov_len = ret;
    if (strstr(dest_str, "-----BEGIN CERTIFICATE-----") ||
        strstr(dest_str, "-----BEGIN PRIVATE KEY-----"))
        dest->iov_len++;
    close(fd);
}

void conf_set_array(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    uintptr_t array_len = (uintptr_t)raw_param;

    if (parse_byte_array(raw_dest, array_len, info->value))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
}

void parse_config_line(const struct option_struct opts[], struct storage_parse_info *info)
{
    for (const struct option_struct *opt = opts; opt->key; opt++)
        if (!fnmatch(opt->key, info->key, 0))
            return opt->fn(info, opt->dest_hint, opt->param);
    FATAL(1, "%s:%d: unknown key: '%s'", info->filename, info->linenr, info->line);
}

void parse_config_file(const struct option_struct opts[], const char *filename)
{
    struct storage_parse_info *info = storage_open(filename, "r");
    int ret;

    if (!info)
        FATAL(1, "%s: %m", filename);
    for (;;) {
        ret = storage_parse_line(info);
        if (ret == EOF)
            break;
        if (ret)
            FATAL(1, "%s:%d: syntax error: '%s'", info->filename, info->linenr, info->line);
        parse_config_line(opts, info);
    }
    storage_close(info);
}
