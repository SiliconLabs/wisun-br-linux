/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include "nsconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "common/named_values.h"
#include "common/os_types.h"
#include "common/ws_regdb.h"
#include "common/parsers.h"
#include "common/utils.h"
#include "common/log.h"
#include "stack/ws_management_api.h"

#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/core/ns_address_internal.h"

#include "commandline_values.h"
#include "wsbr.h"

#include "commandline.h"

struct parser_info {
    const char *filename;
    int line_no;
    char line[256];
};

struct number_limit {
    int min;
    int max;
};

struct number_limit valid_unsigned = {
    0, INT_MAX
};

struct number_limit valid_positive = {
    1, INT_MAX
};

struct number_limit valid_int8 = {
    INT8_MIN, INT8_MAX
};

struct number_limit valid_gtk_new_install_required = {
    0, 100
};

struct number_limit valid_unicast_dwell_interval = {
    15, 0xFF
};

struct number_limit valid_broadcast_dwell_interval = {
    100, 0xFF
};

struct number_limit valid_broadcast_interval = {
    100, 0xFFFFFF
};

static const int valid_ws_modes[] = {
    0x1a, 0x1b, 0x2a, 0x2b, 0x03, 0x4a, 0x4b, 0x05,
    0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
    0xb3, 0xb4, 0xb5, 0xb6,
    0xc4, 0xc5, 0xc6,
    0xd4, 0xd5, 0xd6,
    INT_MIN
};

static const int valid_ws_classes[] = {
    0x01, 0x02, 0x03, 0x04,                         // Legacy
    0x81, 0x82, 0x83, 0x84, 0x85,                   // ChanPlanIDs NA/BZ
    0x95, 0x96, 0x97, 0x98,                         // ChanPlanIDs JP
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, // ChanPlanIDs EU
    INT_MIN
};

static const int valid_ws_chan_spacing[] = {
    100000, 200000, 400000, 600000, 800000, 1200000,
    INT_MIN
};

void print_help_br(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN border router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsbrd [OPTIONS]\n");
    fprintf(stream, "  wsbrd [OPTIONS] --list-rf-configs\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -t TUN                Map a specific TUN device (eg. allocated with 'ip tuntap add tun0')\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif, hif-extra,\n");
    fprintf(stream, "                           trickle, 15.4-mngt, 15.4, eap, icmp-rf, icmp-tun, dhcp\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -l, --list-rf-configs Retrieve the possible RF configurations from teh RCP then exit. Most\n");
    fprintf(stream, "                          of parameters are ignored in this mode\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU, NA, JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b (default), 2a, 2b, 3, 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1 (default), 2, 3 or 4\n");
    fprintf(stream, "  -S, --size=SIZE       Optimize network timings considering the number of expected nodes on\n");
    fprintf(stream, "                          the network. Valid values: S (< 100, default), M (100-1000),\n");
    fprintf(stream, "                          L (> 1000)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN network authentication:\n");
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM od DER\n");
    fprintf(stream, "  format.\n");
    fprintf(stream, "  -K, --key=FILE         Private key (keep it secret)\n");
    fprintf(stream, "  -C, --certificate=FILE Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE   Certificate of the authority (CA) (shared with all devices of the\n");
    fprintf(stream, "                           network)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsbrd -u /dev/ttyUSB0 -n Wi-SUN -d EU -C cert.pem -A ca.pem -K key.pem\n");
}

void print_help_node(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Simulate a Wi-SUN node\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsnode [OPTIONS]\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif, hif-extra\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -n, --network=NAME    Set Wi-SUN network name\n");
    fprintf(stream, "  -d, --domain=COUNTRY  Set Wi-SUN regulatory domain. Valid values: WW, EU, NA, JP...\n");
    fprintf(stream, "  -m, --mode=VAL        Set operating mode. Valid values: 1a, 1b (default), 2a, 2b, 3, 4a,\n");
    fprintf(stream, "                          4b and 5\n");
    fprintf(stream, "  -c, --class=VAL       Set operating class. Valid values: 1 (default), 2, 3 or 4\n");
    fprintf(stream, "  -S, --size=SIZE       Optimize network timings considering the number of expected nodes on\n");
    fprintf(stream, "                          the network. Valid values: S (< 100, default), M (100-1000),\n");
    fprintf(stream, "                          L (> 1000)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN network authentication:\n");
    fprintf(stream, "  The following option are mandatory. Every option has to specify a file in PEM\n");
    fprintf(stream, "  or DER format.\n");
    fprintf(stream, "  -K, --key=FILE         Private key (keep it secret)\n");
    fprintf(stream, "  -C, --certificate=FILE Certificate for the key\n");
    fprintf(stream, "  -A, --authority=FILE   Certificate of the authority (CA) (shared with all devices of the\n");
    fprintf(stream, "                           network)\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsnode -u /dev/ttyUSB0 -n Wi-SUN -d EU -C cert.pem -A ca.pem -K key.pem\n");
}

static void conf_set_bool(struct wsbrd_conf *config, const struct parser_info *info, bool *dest, const char *raw_value)
{
    *dest = str_to_val(raw_value, valid_booleans);
}

static void conf_set_enum(struct wsbrd_conf *config, const struct parser_info *info, int *dest, const struct name_value *specs, const char *raw_value)
{
    *dest = str_to_val(raw_value, specs);
}

static void conf_set_enum_int_hex(struct wsbrd_conf *config, const struct parser_info *info, int *dest, const int *specs, const char *raw_value)
{
    char *end;
    int i;

    *dest = strtol(raw_value, &end, 16);
    if (*end)
        FATAL(1, "%s:%d: invalid number: %s", info->filename, info->line_no, raw_value);

    for (i = 0; specs[i] != INT_MIN; i++)
        if (specs[i] == *dest)
            return;
    FATAL(1, "%s:%d: invalid value: %s", info->filename, info->line_no, raw_value);
}

static void conf_set_enum_int(struct wsbrd_conf *config, const struct parser_info *info, int *dest, const int *specs, const char *raw_value)
{
    char *end;
    int i;

    *dest = strtol(raw_value, &end, 0);
    if (*end)
        FATAL(1, "%s:%d: invalid number: %s", info->filename, info->line_no, raw_value);

    for (i = 0; specs[i] != INT_MIN; i++)
        if (specs[i] == *dest)
            return;
    FATAL(1, "%s:%d: invalid value: %s", info->filename, info->line_no, raw_value);
}

static void conf_set_number(struct wsbrd_conf *config, const struct parser_info *info, int *dest, const struct number_limit *specs, const char *raw_value)
{
    char *end;

    *dest = strtol(raw_value, &end, 0);
    if (*end)
        FATAL(1, "%s:%d: invalid number: %s", info->filename, info->line_no, raw_value);
    if (specs && (specs->min > *dest || specs->max < *dest))
        FATAL(1, "%s:%d: invalid value: %s", info->filename, info->line_no, raw_value);
}

static void conf_set_string(struct wsbrd_conf *config, const struct parser_info *info, char *dest, const char *raw_value)
{
    if (parse_escape_sequences(dest, raw_value))
        FATAL(1, "%s:%d: invalid escape sequence", info->filename, info->line_no);
}

static void conf_set_netmask(struct wsbrd_conf *config, const struct parser_info *info, void *dest, const char *raw_value)
{
    char mask[STR_MAX_LEN_IPV6];
    int len;

    if (sscanf(raw_value, "%[0-9a-zA-Z:]/%d", mask, &len) != 2)
        FATAL(1, "%s:%d: invalid netmask: %s", info->filename, info->line_no, raw_value);
    if (len != 64)
        FATAL(1, "%s:%d: invalid mask length: %d", info->filename, info->line_no, len);
    if (inet_pton(AF_INET6, mask, dest) != 1)
        FATAL(1, "%s:%d: invalid mask: %s", info->filename, info->line_no, mask);
}

static void conf_set_netaddr(struct wsbrd_conf *config, const struct parser_info *info, struct sockaddr *dest, const char *raw_value)
{
    struct addrinfo *results;
    int err;

    err = getaddrinfo(raw_value, NULL, NULL, &results);
    if (err != 0)
        FATAL(1, "%s:%d: %s: %s", info->filename, info->line_no, raw_value, gai_strerror(err));
    BUG_ON(!results);
    memcpy(dest, results->ai_addr, results->ai_addrlen);
    freeaddrinfo(results);
}

static void conf_set_bitmask(struct wsbrd_conf *config, const struct parser_info *info, uint32_t *dest, const char *raw_value)
{
    BUG_ON(dest != config->ws_allowed_channels);
    BUG_ON(ARRAY_SIZE(config->ws_allowed_channels) != 8);
    if (parse_bitmask(dest, 8, raw_value) < 0)
        FATAL(1, "%s:%d: invalid range: %s", info->filename, info->line_no, raw_value);
}

static void conf_set_flags(struct wsbrd_conf *config, const struct parser_info *info, unsigned int *dest, const struct name_value *specs, const char *raw_value)
{
    char *tmp, *substr;

    tmp = strdup(raw_value);
    substr = strtok(tmp, ",");
    do {
        *dest |= str_to_val(substr, specs);
    } while ((substr = strtok(NULL, ",")));
    free(tmp);
}

static int read_cert(const char *filename, const uint8_t **ptr)
{
    uint8_t *tmp;
    int fd, ret;
    struct stat st;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;
    ret = fstat(fd, &st);
    if (ret < 0)
        return -1;

    /* See https://github.com/ARMmbed/mbedtls/issues/3896 and
     * mbedtls_x509_crt_parse()
     */
    tmp = malloc(st.st_size + 1);
    tmp[st.st_size] = 0;
    ret = read(fd, tmp, st.st_size);
    if (ret != st.st_size)
        return -1;
    close(fd);
    if (*ptr)
        free((uint8_t *)*ptr);
    *ptr = tmp;

    if (strstr((char *)tmp, "-----BEGIN CERTIFICATE-----"))
        return st.st_size + 1;
    else if (strstr((char *)tmp, "-----BEGIN PRIVATE KEY-----"))
        return st.st_size + 1;
    else
        return st.st_size;
}

static void parse_config_line(struct wsbrd_conf *config, const struct parser_info *info)
{
    char garbage; // detect garbage at end of the line
    char str_arg[256];
    int int_arg;

    if (sscanf(info->line, " %c", &garbage) == EOF) {
        /* blank info->line*/;
    } else if (sscanf(info->line, " uart_device = %s %c", str_arg, &garbage) == 1) {
        conf_set_string(config, info, config->uart_dev, str_arg);
    } else if (sscanf(info->line, " uart_baudrate = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->uart_baudrate, NULL, str_arg);
    } else if (sscanf(info->line, " uart_rtscts = %s %c", str_arg, &garbage) == 1) {
        conf_set_bool(config, info, &config->uart_rtscts, str_arg);
    } else if (sscanf(info->line, " cpc_instance = %s %c", str_arg, &garbage) == 1) {
        conf_set_string(config, info, config->cpc_instance, str_arg);
    } else if (sscanf(info->line, " cpc_verbose = %s %c", str_arg, &garbage) == 1) {
        conf_set_bool(config, info, &config->cpc_verbose, str_arg);
    } else if (sscanf(info->line, " tun_device = %s %c", str_arg, &garbage) == 1) {
        conf_set_string(config, info, config->tun_dev, str_arg);
    } else if (sscanf(info->line, " tun_autoconf = %s %c", str_arg, &garbage) == 1) {
        conf_set_bool(config, info, &config->tun_autoconf, str_arg);
    } else if (sscanf(info->line, " network_name = %s %c", str_arg, &garbage) == 1) {
        conf_set_string(config, info, config->ws_name, str_arg);
    } else if (sscanf(info->line, " ipv6_prefix = %s %c", str_arg, &garbage) == 2) {
        conf_set_netmask(config, info, config->ipv6_prefix, str_arg);
    } else if (sscanf(info->line, " dhcpv6_server = %s %c", str_arg, &garbage) == 1) {
        conf_set_netaddr(config, info, (struct sockaddr *)&config->dhcpv6_server, str_arg);
    } else if (sscanf(info->line, " certificate = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", info->filename, info->line_no);
        int_arg = read_cert(str_arg, &config->tls_own.cert);
        if (int_arg < 0)
            FATAL(1, "%s:%d: %s: %m", info->filename, info->line_no, str_arg);
        config->tls_own.cert_len = int_arg;
    } else if (sscanf(info->line, " key = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", info->filename, info->line_no);
        int_arg = read_cert(str_arg, &config->tls_own.key);
        if (int_arg < 0)
            FATAL(1, "%s:%d: %s: %m", info->filename, info->line_no, str_arg);
        config->tls_own.key_len = int_arg;
    } else if (sscanf(info->line, " authority = %s %c", str_arg, &garbage) == 1) {
        if (parse_escape_sequences(str_arg, str_arg))
            FATAL(1, "%s:%d: invalid escape sequence", info->filename, info->line_no);
        int_arg = read_cert(str_arg, &config->tls_ca.cert);
        if (int_arg < 0)
            FATAL(1, "%s:%d: %s: %m", info->filename, info->line_no, str_arg);
        config->tls_ca.cert_len = int_arg;
    } else if (sscanf(info->line, " radius_server = %s %c", str_arg, &garbage) == 1) {
        conf_set_netaddr(config, info, (struct sockaddr *)&config->radius_server, str_arg);
    } else if (sscanf(info->line, " radius_secret = %s %c", str_arg, &garbage) == 1) {
        conf_set_string(config, info, config->radius_secret, str_arg);
    } else if (sscanf(info->line, " trace = %s %c", str_arg, &garbage) == 1) {
        g_enabled_traces = 0;
        conf_set_flags(config, info, &g_enabled_traces, valid_traces, str_arg);
    } else if (sscanf(info->line, " domain = %s %c", str_arg, &garbage) == 1) {
        conf_set_enum(config, info, &config->ws_domain, valid_ws_domains, str_arg);
    } else if (sscanf(info->line, " mode = %s %c", str_arg, &garbage) == 1) {
        conf_set_enum_int_hex(config, info, &config->ws_mode, valid_ws_modes, str_arg);
    } else if (sscanf(info->line, " class = %s %c", str_arg, &garbage) == 1) {
        conf_set_enum_int(config, info, &config->ws_class, valid_ws_classes, str_arg);
    } else if (sscanf(info->line, " chan0_freq = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_chan0_freq, NULL, str_arg);
    } else if (sscanf(info->line, " chan_spacing = %s %c", str_arg, &garbage) == 1) {
        conf_set_enum_int(config, info, &config->ws_chan_spacing, valid_ws_chan_spacing, str_arg);
    } else if (sscanf(info->line, " chan_count = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_chan_count, NULL, str_arg);
    } else if (sscanf(info->line, " allowed_channels = %s %c", str_arg, &garbage) == 1) {
        conf_set_bitmask(config, info, config->ws_allowed_channels, str_arg);
    } else if (sscanf(info->line, " pan_id = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_pan_id, NULL, str_arg);
    } else if (sscanf(info->line, " gtk[%d] = %s %c", &int_arg, str_arg, &garbage) == 2) {
        if (int_arg < 0 || int_arg > 3)
            FATAL(1, "%s:%d: invalid key index: %d", info->filename, info->line_no, int_arg);
        if (parse_byte_array(config->ws_gtk[int_arg], 16, str_arg))
            FATAL(1, "%s:%d: invalid key: %s", info->filename, info->line_no, str_arg);
        config->ws_gtk_force[int_arg] = true;
    } else if (sscanf(info->line, " size = %s %c", str_arg, &garbage) == 1) {
        conf_set_enum(config, info, &config->ws_size, valid_ws_size, str_arg);
    } else if (sscanf(info->line, " tx_power = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->tx_power, &valid_int8, str_arg);
    } else if (sscanf(info->line, " storage_prefix = %s %c", str_arg, &garbage) == 1) {
        conf_set_string(config, info, config->storage_prefix, str_arg);
    } else if (sscanf(info->line, " unicast_dwell_interval = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->uc_dwell_interval, &valid_unicast_dwell_interval, str_arg);
    } else if (sscanf(info->line, " broadcast_interval = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->bc_interval, &valid_broadcast_interval, str_arg);
    } else if (sscanf(info->line, " broadcast_dwell_interval = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->bc_interval, &valid_broadcast_dwell_interval, str_arg);
    } else if (sscanf(info->line, " pmk_lifetime = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_pmk_lifetime, &valid_unsigned, str_arg);
    } else if (sscanf(info->line, " ptk_lifetime = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_ptk_lifetime, &valid_unsigned, str_arg);
    } else if (sscanf(info->line, " gtk_expire_offset = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_gtk_expire_offset, &valid_unsigned, str_arg);
    } else if (sscanf(info->line, " gtk_new_activation_time = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_gtk_new_activation_time, &valid_positive, str_arg);
    } else if (sscanf(info->line, " gtk_new_install_required = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_gtk_new_install_required, &valid_gtk_new_install_required, str_arg);
    } else if (sscanf(info->line, " revocation_lifetime_reduction = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_revocation_lifetime_reduction, &valid_unsigned, str_arg);
    } else if (sscanf(info->line, " gtk_max_mismatch = %s %c", str_arg, &garbage) == 1) {
        conf_set_number(config, info, &config->ws_gtk_max_mismatch, &valid_unsigned, str_arg);
    } else if (sscanf(info->line, " allowed_mac64 = %s %c", str_arg, &garbage) == 1) {
        if (config->ws_allowed_mac_address_count >= ARRAY_SIZE(config->ws_allowed_mac_addresses))
            FATAL(1, "%s:%d: maximum number of allowed MAC addresses reached", info->filename, info->line_no);
        if (parse_byte_array(config->ws_allowed_mac_addresses[config->ws_allowed_mac_address_count], 8, str_arg))
            FATAL(1, "%s:%d: invalid key: %s", info->filename, info->line_no, str_arg);
        config->ws_allowed_mac_address_count++;
    } else if (sscanf(info->line, " denied_mac64 = %s %c", str_arg, &garbage) == 1) {
        if (config->ws_denied_mac_address_count >= ARRAY_SIZE(config->ws_denied_mac_addresses))
            FATAL(1, "%s:%d: maximum number of denied MAC addresses reached", info->filename, info->line_no);
        if (parse_byte_array(config->ws_denied_mac_addresses[config->ws_denied_mac_address_count], 8, str_arg))
            FATAL(1, "%s:%d: invalid key: %s", info->filename, info->line_no, str_arg);
        config->ws_denied_mac_address_count++;
    } else if (sscanf(info->line, " regional_regulation = %s %c", str_arg, &garbage) == 1) {
        conf_set_enum(config, info, &config->ws_regional_regulation, valid_ws_regional_regulations, str_arg);
    } else if (sscanf(info->line, " use_tap = %s %c", str_arg, &garbage) == 1) {
        conf_set_bool(config, info, &config->tun_use_tap, str_arg);
    } else {
        FATAL(1, "%s:%d: syntax error: '%s'", info->filename, info->line_no, info->line);
    }
}

static void parse_config_file(struct wsbrd_conf *config, const char *filename)
{
    struct parser_info info = {
        .filename = filename
    };
    FILE *f = fopen(filename, "r");
    int len;

    if (!f)
        FATAL(1, "%s: %m", info.filename);
    while (fgets(info.line, sizeof(info.line), f)) {
        info.line_no++;
        len = strlen(info.line);
        if (len > 0 && info.line[len - 1] == '\n')
            info.line[--len] = '\0';
        if (len > 0 && info.line[len - 1] == '\r')
            info.line[--len] = '\0';
        if (len <= 0)
            continue;
        *(strchrnul(info.line, '#')) = '\0';
        parse_config_line(config, &info);
    }
    fclose(f);
}

int check_storage_access(const char *storage_prefix)
{
    char *tmp;

    if (!strlen(storage_prefix))
        return 0;
    if (storage_prefix[strlen(storage_prefix) - 1] == '/')
        return access(storage_prefix, W_OK);
    tmp = strdupa(storage_prefix);
    return access(dirname(tmp), W_OK);
}

void parse_commandline(struct wsbrd_conf *config, int argc, char *argv[],
                       void (*print_help)(FILE *stream))
{
    static const char *opts_short = "u:sF:o:t:T:n:d:m:c:S:K:C:A:b:Hhv";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
        { "list-rf-configs", no_argument,   0,  'l' },
        { "tun",         required_argument, 0,  't' },
        { "trace",       required_argument, 0,  'T' },
        { "network",     required_argument, 0,  'n' },
        { "domain",      required_argument, 0,  'd' },
        { "mode",        required_argument, 0,  'm' },
        { "class",       required_argument, 0,  'c' },
        { "size",        required_argument, 0,  'S' },
        { "key",         required_argument, 0,  'K' },
        { "cert",        required_argument, 0,  'C' },
        { "certificate", required_argument, 0,  'C' },
        { "authority",   required_argument, 0,  'A' },
        { "baudrate",    required_argument, 0,  'b' },
        { "hardflow",    no_argument,       0,  'H' },
        { "help",        no_argument,       0,  'h' },
        { "version",     no_argument,       0,  'v' },
        { 0,             0,                 0,   0  }
    };
    struct parser_info info = {
        .filename = "command line",
    };
    int opt, ret;

    config->uart_baudrate = 115200;
    config->tun_autoconf = true;
    config->ws_class = 0;
    config->ws_domain = REG_DOMAIN_UNDEF;
    config->ws_mode = 0;
    config->ws_size = NETWORK_SIZE_SMALL;
    config->ws_pan_id = -1;
    config->tx_power = 20;
    config->uc_dwell_interval = WS_FHSS_UC_DWELL_INTERVAL;
    config->bc_interval = WS_FHSS_BC_INTERVAL;
    config->bc_dwell_interval = WS_FHSS_BC_DWELL_INTERVAL;
    config->ws_allowed_mac_address_count = 0;
    config->ws_denied_mac_address_count = 0;
    config->ws_regional_regulation = 0,
    strcpy(config->storage_prefix, "/var/lib/wsbrd/");
    memset(config->ws_allowed_channels, 0xFF, sizeof(config->ws_allowed_channels));
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                parse_config_file(config, optarg);
                break;
            case '?':
                print_help(stderr);
                exit(1);
                break;
            default:
                break;
        }
    }
    optind = 1; /* reset getopt */
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                break;
            case 'u':
                strncpy(config->uart_dev, optarg, sizeof(config->uart_dev) - 1);
                break;
            case 'o':
                strncpy(info.line, optarg, sizeof(info.line));
                parse_config_line(config, &info);
                break;
            case 'l':
                config->list_rf_configs = true;
                break;
            case 't':
                strncpy(config->tun_dev, optarg, sizeof(config->tun_dev) - 1);
                break;
            case 'T':
                conf_set_flags(config, &info, &g_enabled_traces, valid_traces, optarg);
                break;
            case 'n':
                strncpy(config->ws_name, optarg, sizeof(config->ws_name) - 1);
                break;
            case 'd':
                conf_set_enum(config, &info, &config->ws_domain, valid_ws_domains, optarg);
                break;
            case 'm':
                conf_set_enum_int_hex(config, &info, &config->ws_mode, valid_ws_modes, optarg);
                break;
            case 'c':
                conf_set_enum_int(config, &info, &config->ws_class, valid_ws_classes, optarg);
                break;
            case 'S':
                conf_set_enum(config, &info, &config->ws_size, valid_ws_size, optarg);
                break;
            case 'K':
                ret = read_cert(optarg, &config->tls_own.key);
                if (ret < 0)
                    FATAL(1, "%s: %m", optarg);
                config->tls_own.key_len = ret;
                break;
            case 'C':
                ret = read_cert(optarg, &config->tls_own.cert);
                if (ret < 0)
                    FATAL(1, "%s: %m", optarg);
                config->tls_own.cert_len = ret;
                break;
            case 'A':
                ret = read_cert(optarg, &config->tls_ca.cert);
                if (ret < 0)
                    FATAL(1, "%s: %m", optarg);
                config->tls_ca.cert_len = ret;
                break;
            case 'b':
                FATAL(1, "deprecated option: -b/--baudrate");
                break;
            case 'H':
                FATAL(1, "deprecated option: -H/--hardflow");
                break;
            case 'h':
                print_help(stdout);
                exit(0);
                break;
            case 'v':
                /* version is printed at the start of main */
                exit(0);
            default:
                BUG(); /* Cannot happen */
                break;
        }
    }
    if (optind != argc)
        FATAL(1, "unexpected argument: %s", argv[optind]);
    if (!config->ws_name[0])
        FATAL(1, "missing \"network_name\" parameter");
    if (config->ws_chan0_freq || config->ws_chan_spacing || config->ws_chan_count) {
        if (config->ws_domain != REG_DOMAIN_UNDEF || config->ws_class)
            FATAL(1, "custom channel plan is exclusive with \"domain\" and \"class\"");
        if (!config->ws_chan0_freq)
            FATAL(1, "custom channel plan need \"chan0_freq\"");
        if (!config->ws_chan_spacing)
            FATAL(1, "custom channel plan need \"chan_spacing\"");
        if (!config->ws_chan_count)
            FATAL(1, "custom channel plan need \"chan_count\"");
    } else {
        if (config->ws_domain == REG_DOMAIN_UNDEF)
            FATAL(1, "missing \"domain\" parameter");
        if (!config->ws_class)
            FATAL(1, "missing \"class\" parameter");
    }
    if (config->ws_domain == REG_DOMAIN_JP && config->ws_regional_regulation != REG_REGIONAL_ARIB)
        WARN("Japanese regulation domain used without ARIB regional regulation");
    if (config->ws_domain != REG_DOMAIN_JP && config->ws_regional_regulation == REG_REGIONAL_ARIB)
        FATAL(1, "ARIB is only supported with Japanese regulation domain");
    if (!config->ws_mode)
        FATAL(1, "missing \"mode\" parameter");
    if (config->ws_mode & OPERATING_MODE_PHY_MODE_ID_BIT)
        config->ws_phy_mode_id = config->ws_mode & OPERATING_MODE_PHY_MODE_ID_MASK;
    if (config->ws_class & OPERATING_CLASS_CHAN_PLAN_ID_BIT)
        config->ws_chan_plan_id = config->ws_class & OPERATING_CLASS_CHAN_PLAN_ID_MASK;
    if (config->bc_interval < config->bc_dwell_interval)
        FATAL(1, "broadcast interval %d can't be lower than broadcast dwell interval %d", config->bc_interval, config->bc_dwell_interval);
    if (config->ws_allowed_mac_address_count > 0 && config->ws_denied_mac_address_count > 0)
        FATAL(1, "allowed_mac64 and denied_mac64 are exclusive");
    if (!config->uart_dev[0] && !config->cpc_instance[0])
        FATAL(1, "missing \"uart_device\" (or \"cpc_instance\") parameter");
    if (config->uart_dev[0] && config->cpc_instance[0])
        FATAL(1, "\"uart_device\" and \"cpc_instance\" are exclusive %s", config->uart_dev);
    if (!strcmp(config->storage_prefix, "-"))
        config->storage_prefix[0]= '\0';
    if (check_storage_access(config->storage_prefix))
        FATAL(1, "%s: %m", config->storage_prefix);
    if (config->radius_server.ss_family == AF_UNSPEC) {
        if (!config->tls_own.key)
            FATAL(1, "missing \"key\" (or \"radius_server\") parameter");
        if (!config->tls_own.cert)
            FATAL(1, "missing \"certificate\" (or \"radius_server\") parameter");
        if (!config->tls_ca.cert)
            FATAL(1, "missing \"authority\" (or \"radius_server\") parameter");
    } else {
        if (config->tls_own.cert_len != 0 || config->tls_own.key_len != 0 || config->tls_ca.cert_len != 0)
            WARN("ignore certificates and key since an external radius server is in use");
    }
#ifdef HAVE_WS_BORDER_ROUTER
    if (config->dhcpv6_server.sin6_family == AF_INET6) {
        if (memcmp(config->ipv6_prefix, ADDR_UNSPECIFIED, 16) != 0)
            WARN("ipv6_prefix will be ignored because you specified a dhcpv6_server address");
    } else if (config->dhcpv6_server.sin6_family == AF_INET) {
        FATAL(1, "dhcpv6_server does not support IPv4 server");
    } else {
        if (!memcmp(config->ipv6_prefix, ADDR_UNSPECIFIED, 16))
            FATAL(1, "You must specify a ipv6_prefix");
    }
#else
    if (!config->uart_dev[0])
        FATAL(1, "missing \"uart_device\" parameter");
    if (memcmp(config->ipv6_prefix, ADDR_UNSPECIFIED, 16))
        WARN("ipv6_prefix is ignored");
#endif
}
