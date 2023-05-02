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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "common/key_value_storage.h"
#include "common/named_values.h"
#include "common/os_types.h"
#include "common/ws_regdb.h"
#include "common/parsers.h"
#include "common/utils.h"
#include "common/log.h"
#include "stack/ws_management_api.h"

#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/6lowpan/lowpan_mtu.h"
#include "stack/source/core/ns_address_internal.h"

#include "commandline_values.h"
#include "wsbr.h"

#include "commandline.h"

struct option_struct {
    const char *key;
    void *dest_hint;
    void (*fn)(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param);
    const void *param;
};

struct number_limit {
    int min;
    int max;
};

static const struct number_limit valid_unsigned = {
    0, INT_MAX
};

static const struct number_limit valid_positive = {
    1, INT_MAX
};

static const struct number_limit valid_int8 = {
    INT8_MIN, INT8_MAX
};

static const struct number_limit valid_uint16 = {
    0, UINT16_MAX
};

static const struct number_limit valid_gtk_new_install_required = {
    0, 100
};

static const struct number_limit valid_async_frag_duration = {
    500, UINT32_MAX
};

static const struct number_limit valid_unicast_dwell_interval = {
    15, 0xFF
};

static const struct number_limit valid_broadcast_dwell_interval = {
    100, 0xFF
};

static const struct number_limit valid_broadcast_interval = {
    100, 0xFFFFFF
};

static const struct number_limit valid_lfn_broadcast_interval = {
    10000, 600000 // 10s-10min
};

static const struct number_limit valid_lfn_broadcast_sync_period = {
    1, 60
};

static const struct number_limit valid_lowpan_mtu = {
    LOWPAN_MTU_MIN, LOWPAN_MTU_MAX
};

static const int valid_ws_modes[] = {
    0x1a, 0x1b, 0x2a, 0x2b, 0x03, 0x4a, 0x4b, 0x05,
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
    0xb3, 0xb4, 0xb5, 0xb6,
    0xc4, 0xc5, 0xc6,
    0xd4, 0xd5, 0xd6,
    INT_MIN
};

static const int valid_ws_phy_mode_ids[] = {
     1,  2,  3,  4,  5,  6,  7,  8, // FSK
    17, 18, 19, 20, 21, 22, 23, 24, // FSK w/ FEC
    34, 35, 36, 37, 38,             // OFDM 1
    51, 52, 53, 54,                 // OFDM 2
    68, 69, 70,                     // OFDM 3
    84, 85, 86,                     // OFDM 4
    INT_MIN
};

static const int valid_ws_classes[] = {
    0x01, 0x02, 0x03, 0x04,                         // Legacy
    0x81, 0x82, 0x83, 0x84, 0x85,                   // ChanPlanIDs NA/BZ
    0x95, 0x96, 0x97, 0x98,                         // ChanPlanIDs JP
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, // ChanPlanIDs EU
    INT_MIN
};

static const int valid_ws_chan_plan_ids[] = {
     1,  2,  3,  4,  5,     // NA/BZ
    21, 22, 23, 24,         // JP
    32, 33, 34, 35, 36, 37, // EU
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
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, cpc, hdlc, hif,\n");
    fprintf(stream, "                           hif-extra, trickle, 15.4-mngt, 15.4, eap, icmp-rf, icmp-tun,\n");
    fprintf(stream, "                           dhcp, timers\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
    fprintf(stream, "\n");
    fprintf(stream, "Wi-SUN related options:\n");
    fprintf(stream, "  -l, --list-rf-configs Retrieve the possible RF configurations from the RCP then exit. Most\n");
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
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, hdlc, hif,\n");
    fprintf(stream, "                          hif-extra, timers\n");
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

static void conf_deprecated(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    FATAL(1, "%s:%d \"%s\" is deprecated", info->filename, info->linenr, info->key);
}

static void conf_set_bool(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    bool *dest = raw_dest;

    BUG_ON(raw_param);
    *dest = str_to_val(info->value, valid_booleans);
}

static void conf_set_enum(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    const struct name_value *specs = raw_param;
    int *dest = raw_dest;

    *dest = str_to_val(info->value, specs);
}

static void conf_set_enum_int_hex(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
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

static void conf_set_enum_int(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
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

static void conf_set_number(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
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

static void conf_set_string(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    uintptr_t max_len = (uintptr_t)raw_param;
    char *dest = raw_dest;

    if (parse_escape_sequences(dest, info->value, max_len))
        FATAL(1, "%s:%d: invalid escape sequence", info->filename, info->linenr);
}

static void conf_set_netmask(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    char mask[STR_MAX_LEN_IPV6];
    int len;

    BUG_ON(raw_param);
    if (sscanf(info->value, "%[0-9a-zA-Z:]/%d", mask, &len) != 2)
        FATAL(1, "%s:%d: invalid %s: %s", info->filename, info->linenr, info->key, info->value);
    if (len != 64)
        FATAL(1, "%s:%d: invalid mask length: %d", info->filename, info->linenr, len);
    if (inet_pton(AF_INET6, mask, raw_dest) != 1)
        FATAL(1, "%s:%d: invalid mask: %s", info->filename, info->linenr, mask);
}

static void conf_set_netaddr(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
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

static void conf_set_bitmask(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    BUG_ON(raw_param);
    BUG_ON(raw_dest != config->ws_allowed_channels);
    BUG_ON(ARRAY_SIZE(config->ws_allowed_channels) != 32);
    if (parse_bitmask(config->ws_allowed_channels, 32, info->value) < 0)
        FATAL(1, "%s:%d: invalid range: %s", info->filename, info->linenr, info->value);
}

static void conf_set_flags(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
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

static void conf_set_cert(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    arm_certificate_entry_s *dest = raw_dest;
    int ret;

    BUG_ON(raw_param);
    ret = read_cert(info->value, &dest->cert);
    FATAL_ON(ret < 0, 1, "%s:%d: %s: %m", info->filename, info->linenr, info->value);
    dest->cert_len = ret;
}

static void conf_set_key(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    arm_certificate_entry_s *dest = raw_dest;
    int ret;

    BUG_ON(raw_param);
    ret = read_cert(info->value, &dest->key);
    FATAL_ON(ret < 0, 1, "%s:%d: %s: %m", info->filename, info->linenr, info->value);
    dest->key_len = ret;
}

static void conf_set_allowed_macaddr(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    BUG_ON(raw_param);
    BUG_ON(raw_dest != config->ws_allowed_mac_addresses);
    if (config->ws_allowed_mac_address_count >= ARRAY_SIZE(config->ws_allowed_mac_addresses))
        FATAL(1, "%s:%d: maximum number of allowed MAC addresses reached", info->filename, info->linenr);
    if (parse_byte_array(config->ws_allowed_mac_addresses[config->ws_allowed_mac_address_count], 8, info->value))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
    config->ws_allowed_mac_address_count++;
}

static void conf_set_denied_macaddr(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    BUG_ON(raw_param);
    BUG_ON(raw_dest != config->ws_denied_mac_addresses);
    if (config->ws_denied_mac_address_count >= ARRAY_SIZE(config->ws_denied_mac_addresses))
        FATAL(1, "%s:%d: maximum number of denied MAC addresses reached", info->filename, info->linenr);
    if (parse_byte_array(config->ws_denied_mac_addresses[config->ws_denied_mac_address_count], 8, info->value))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
    config->ws_denied_mac_address_count++;
}

static void conf_set_gtk(struct wsbrd_conf *config, const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    int max_key_index = (raw_dest == config->ws_lgtk) ? 3 : 4;
    uint8_t (*dest)[16] = raw_dest;

    BUG_ON(raw_param);
    BUG_ON(raw_dest != config->ws_gtk && raw_dest != config->ws_lgtk);
    if (info->key_array_index < 0 || info->key_array_index >= max_key_index)
        FATAL(1, "%s:%d: invalid key index: %d", info->filename, info->linenr, info->key_array_index);
    if (parse_byte_array(dest[info->key_array_index], 16, info->value))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
    if (raw_dest == config->ws_gtk)
        config->ws_gtk_force[info->key_array_index] = true;
    if (raw_dest == config->ws_lgtk)
        config->ws_lgtk_force[info->key_array_index] = true;
}

static void parse_config_line(struct wsbrd_conf *config, struct storage_parse_info *info)
{
    const struct option_struct options[] = {
        { "uart_device",                   config->uart_dev,                          conf_set_string,      (void *)sizeof(config->uart_dev) },
        { "uart_baudrate",                 &config->uart_baudrate,                    conf_set_number,      NULL },
        { "uart_rtscts",                   &config->uart_rtscts,                      conf_set_bool,        NULL },
        { "cpc_instance",                  config->cpc_instance,                      conf_set_string,      (void *)sizeof(config->cpc_instance) },
        { "tun_device",                    config->tun_dev,                           conf_set_string,      (void *)sizeof(config->tun_dev) },
        { "tun_autoconf",                  &config->tun_autoconf,                     conf_set_bool,        NULL },
        { "neighbor_proxy",                config->neighbor_proxy,                    conf_set_string,      (void *)sizeof(config->neighbor_proxy) },
        { "color_output",                  &config->color_output,                     conf_set_enum,        &valid_tristate },
        { "use_tap",                       NULL,                                      conf_deprecated,      NULL },
        { "ipv6_prefix",                   &config->ipv6_prefix,                      conf_set_netmask,     NULL },
        { "storage_prefix",                config->storage_prefix,                    conf_set_string,      (void *)sizeof(config->storage_prefix) },
        { "trace",                         &g_enabled_traces,                         conf_set_flags,       &valid_traces },
        { "internal_dhcp",                 &config->internal_dhcp,                    conf_set_bool,        NULL },
        { "radius_server",                 &config->radius_server,                    conf_set_netaddr,     NULL },
        { "radius_secret",                 config->radius_secret,                     conf_set_string,      (void *)sizeof(config->radius_secret) },
        { "key",                           &config->tls_own,                          conf_set_key,         NULL },
        { "certificate",                   &config->tls_own,                          conf_set_cert,        NULL },
        { "authority",                     &config->tls_ca,                           conf_set_cert,        NULL },
        { "network_name",                  config->ws_name,                           conf_set_string,      (void *)sizeof(config->ws_name) },
        { "size",                          &config->ws_size,                          conf_set_enum,        &valid_ws_size },
        { "domain",                        &config->ws_domain,                        conf_set_enum,        &valid_ws_domains },
        { "mode",                          &config->ws_mode,                          conf_set_enum_int_hex, &valid_ws_modes },
        { "phy_mode_id",                   &config->ws_phy_mode_id,                   conf_set_enum_int,    &valid_ws_phy_mode_ids },
        { "class",                         &config->ws_class,                         conf_set_enum_int,    &valid_ws_classes },
        { "chan_plan_id",                  &config->ws_chan_plan_id,                  conf_set_enum_int,    &valid_ws_chan_plan_ids },
        { "regional_regulation",           &config->ws_regional_regulation,           conf_set_enum,        &valid_ws_regional_regulations },
        { "chan0_freq",                    &config->ws_chan0_freq,                    conf_set_number,      NULL },
        { "chan_spacing",                  &config->ws_chan_spacing,                  conf_set_enum_int,    &valid_ws_chan_spacing },
        { "chan_count",                    &config->ws_chan_count,                    conf_set_number,      NULL },
        { "allowed_channels",              config->ws_allowed_channels,               conf_set_bitmask,     NULL },
        { "pan_id",                        &config->ws_pan_id,                        conf_set_number,      NULL },
        { "fan_version",                   &config->ws_fan_version,                   conf_set_enum,        &valid_fan_versions },
        { "gtk\\[*]",                      config->ws_gtk,                            conf_set_gtk,         NULL },
        { "lgtk\\[*]",                     config->ws_lgtk,                           conf_set_gtk,         NULL },
        { "tx_power",                      &config->tx_power,                         conf_set_number,      &valid_int8 },
        { "unicast_dwell_interval",        &config->uc_dwell_interval,                conf_set_number,      &valid_unicast_dwell_interval },
        { "broadcast_dwell_interval",      &config->bc_dwell_interval,                conf_set_number,      &valid_broadcast_dwell_interval },
        { "broadcast_interval",            &config->bc_interval,                      conf_set_number,      &valid_broadcast_interval },
        { "lfn_broadcast_interval",        &config->lfn_bc_interval,                  conf_set_number,      &valid_lfn_broadcast_interval },
        { "lfn_broadcast_sync_period",     &config->lfn_bc_sync_period,               conf_set_number,      &valid_lfn_broadcast_sync_period },
        { "pmk_lifetime",                  &config->ws_pmk_lifetime,                  conf_set_number,      &valid_unsigned },
        { "ptk_lifetime",                  &config->ws_ptk_lifetime,                  conf_set_number,      &valid_unsigned },
        { "gtk_expire_offset",             &config->ws_gtk_expire_offset,             conf_set_number,      &valid_unsigned },
        { "gtk_new_activation_time",       &config->ws_gtk_new_activation_time,       conf_set_number,      &valid_positive },
        { "gtk_new_install_required",      &config->ws_gtk_new_install_required,      conf_set_number,      &valid_gtk_new_install_required },
        { "gtk_max_mismatch",              &config->ws_gtk_max_mismatch,              conf_set_number,      &valid_unsigned },
        { "ffn_revocation_lifetime_reduction", &config->ws_ffn_revocation_lifetime_reduction, conf_set_number,      &valid_unsigned },
        { "lgtk_expire_offset",             &config->ws_lgtk_expire_offset,             conf_set_number,      &valid_unsigned },
        { "lgtk_new_activation_time",       &config->ws_lgtk_new_activation_time,       conf_set_number,      &valid_positive },
        { "lgtk_new_install_required",      &config->ws_lgtk_new_install_required,      conf_set_number,      &valid_gtk_new_install_required },
        { "lgtk_max_mismatch",              &config->ws_lgtk_max_mismatch,              conf_set_number,      &valid_unsigned },
        { "lfn_revocation_lifetime_reduction", &config->ws_lfn_revocation_lifetime_reduction, conf_set_number,      &valid_unsigned },
        { "allowed_mac64",                 config->ws_allowed_mac_addresses,          conf_set_allowed_macaddr, NULL },
        { "denied_mac64",                  config->ws_denied_mac_addresses,           conf_set_denied_macaddr, NULL },
        { "async_frag_duration",           &config->ws_async_frag_duration,           conf_set_number,      &valid_async_frag_duration },
        { "lowpan_mtu",                    &config->lowpan_mtu,                       conf_set_number,      &valid_lowpan_mtu },
        { "pan_size",                      &config->pan_size,                         conf_set_number,      &valid_uint16 },
        { "pcap_file",                     config->pcap_file,                         conf_set_string,      (void *)sizeof(config->pcap_file) },
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(options); i++)
        if (!fnmatch(options[i].key, info->key, 0))
            return options[i].fn(config, info, options[i].dest_hint, options[i].param);
    FATAL(1, "%s:%d: unknown key: '%s'", info->filename, info->linenr, info->line);
}

static void parse_config_file(struct wsbrd_conf *config, const char *filename)
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
        parse_config_line(config, info);
    }
    storage_close(info);
}

void parse_commandline(struct wsbrd_conf *config, int argc, char *argv[],
                       void (*print_help)(FILE *stream))
{
    static const char *opts_short = "u:F:o:t:T:n:d:m:c:S:K:C:A:b:Hhv";
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
    struct storage_parse_info info = {
        .filename = "command line",
    };
    int opt;

    config->uart_baudrate = 115200;
    config->tun_autoconf = true;
    config->internal_dhcp = true;
    config->ws_class = 0;
    config->ws_domain = REG_DOMAIN_UNDEF;
    config->ws_mode = 0;
    config->ws_size = NETWORK_SIZE_SMALL;
    config->ws_pan_id = -1;
    config->color_output = -1;
    config->tx_power = 20;
    config->uc_dwell_interval = WS_FHSS_UC_DWELL_INTERVAL;
    config->bc_interval = WS_FHSS_BC_INTERVAL;
    config->bc_dwell_interval = WS_FHSS_BC_DWELL_INTERVAL;
    config->lfn_bc_interval = 60000;
    config->lfn_bc_sync_period = 5;
    config->ws_allowed_mac_address_count = 0;
    config->ws_denied_mac_address_count = 0;
    config->ws_regional_regulation = 0;
    config->ws_async_frag_duration = 500;
    config->pan_size = -1;
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
        if (optarg)
            strcpy(info.value, optarg);
        switch (opt) {
            case 'F':
                break;
            case 'u':
                snprintf(config->uart_dev, sizeof(config->uart_dev), "%s", optarg); // safe strncpy()
                break;
            case 'o':
                snprintf(info.line, sizeof(info.line), "%s", optarg); // safe strncpy()
                if (sscanf(info.line, " %256[^= ] = %256s", info.key, info.value) != 2)
                    FATAL(1, "%s:%d: syntax error: '%s'", info.filename, info.linenr, info.line);
                if (sscanf(info.key, "%*[^[][%u]", &info.key_array_index) != 1)
                    info.key_array_index = UINT_MAX;
                parse_config_line(config, &info);
                break;
            case 'l':
                config->list_rf_configs = true;
                break;
            case 't':
                snprintf(config->tun_dev, sizeof(config->tun_dev), "%s", optarg); // safe strncpy()
                break;
            case 'T':
                strcpy(info.key, "trace");
                conf_set_flags(config, &info, &g_enabled_traces, valid_traces);
                break;
            case 'n':
                snprintf(config->ws_name, sizeof(config->ws_name), "%s", optarg); // safe strncpy()
                break;
            case 'd':
                strcpy(info.key, "domain");
                conf_set_enum(config, &info, &config->ws_domain, valid_ws_domains);
                break;
            case 'm':
                strcpy(info.key, "mode");
                conf_set_enum_int_hex(config, &info, &config->ws_mode, valid_ws_modes);
                break;
            case 'c':
                strcpy(info.key, "class");
                conf_set_enum_int(config, &info, &config->ws_class, valid_ws_classes);
                break;
            case 'S':
                strcpy(info.key, "size");
                conf_set_enum(config, &info, &config->ws_size, valid_ws_size);
                break;
            case 'K':
                strcpy(info.key, "key");
                conf_set_key(config, &info, &config->tls_own, NULL);
                break;
            case 'C':
                strcpy(info.key, "cert");
                conf_set_cert(config, &info, &config->tls_own, NULL);
                break;
            case 'A':
                strcpy(info.key, "authority");
                conf_set_cert(config, &info, &config->tls_ca, NULL);
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
    if (!config->uart_dev[0] && !config->cpc_instance[0])
        FATAL(1, "missing \"uart_device\" (or \"cpc_instance\") parameter");
    if (config->uart_dev[0] && config->cpc_instance[0])
        FATAL(1, "\"uart_device\" and \"cpc_instance\" are exclusive %s", config->uart_dev);
    if (config->list_rf_configs)
        return;
    if (!config->ws_name[0])
        FATAL(1, "missing \"network_name\" parameter");
    if (config->ws_chan0_freq || config->ws_chan_spacing || config->ws_chan_count) {
        if (config->ws_domain != REG_DOMAIN_UNDEF || config->ws_class || config->ws_chan_plan_id)
            FATAL(1, "custom channel plan is exclusive with \"class\", \"chan_plan_id\" and \"domain\"");
        if (!config->ws_chan0_freq)
            FATAL(1, "custom channel plan need \"chan0_freq\"");
        if (!config->ws_chan_spacing)
            FATAL(1, "custom channel plan need \"chan_spacing\"");
        if (!config->ws_chan_count)
            FATAL(1, "custom channel plan need \"chan_count\"");
    } else {
        if (config->ws_domain == REG_DOMAIN_UNDEF)
            FATAL(1, "missing \"domain\" parameter");
        if (!config->ws_class && !config->ws_chan_plan_id)
            FATAL(1, "missing \"chan_plan_id\" parameter");
    }
    if (config->ws_domain == REG_DOMAIN_JP && config->ws_regional_regulation != REG_REGIONAL_ARIB)
        WARN("Japanese regulation domain used without ARIB regional regulation");
    if (config->ws_domain != REG_DOMAIN_JP && config->ws_regional_regulation == REG_REGIONAL_ARIB)
        FATAL(1, "ARIB is only supported with Japanese regulation domain");
    if (!config->ws_mode && !config->ws_phy_mode_id)
        FATAL(1, "missing \"phy_mode_id\" parameter");
    if (config->ws_mode && config->ws_phy_mode_id)
        FATAL(1, "\"phy_mode_id\" and \"mode\" are mutually exclusive");
    if (config->ws_class && config->ws_chan_plan_id)
        FATAL(1, "\"chan_plan_id\" and \"class\" are mutually exclusive");
    if (config->ws_mode & OPERATING_MODE_PHY_MODE_ID_BIT) {
        config->ws_phy_mode_id = config->ws_mode & OPERATING_MODE_PHY_MODE_ID_MASK;
        config->ws_mode = 0;
    }
    if (config->ws_class & OPERATING_CLASS_CHAN_PLAN_ID_BIT) {
        config->ws_chan_plan_id = config->ws_class & OPERATING_CLASS_CHAN_PLAN_ID_MASK;
        config->ws_class = 0;
    }
    if (config->ws_class && config->ws_phy_mode_id)
        WARN("mix FAN 1.1 PHY mode with FAN1.0 class");
    if (config->ws_chan_plan_id && !config->ws_phy_mode_id)
        WARN("mix FAN 1.0 mode with FAN1.1 channel plan");
    if (config->ws_class && !config->ws_fan_version)
        config->ws_fan_version = WS_FAN_VERSION_1_0;
    if (config->ws_chan_plan_id && !config->ws_fan_version)
        config->ws_fan_version = WS_FAN_VERSION_1_1;
    if (!config->ws_fan_version)
        config->ws_fan_version = WS_FAN_VERSION_1_1;
    if (config->bc_interval < config->bc_dwell_interval)
        FATAL(1, "broadcast interval %d can't be lower than broadcast dwell interval %d", config->bc_interval, config->bc_dwell_interval);
    if (config->ws_allowed_mac_address_count > 0 && config->ws_denied_mac_address_count > 0)
        FATAL(1, "allowed_mac64 and denied_mac64 are exclusive");
    if (!strcmp(config->storage_prefix, "-"))
        config->storage_prefix[0]= '\0';
    if (storage_check_access(config->storage_prefix))
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
    if (config->ws_fan_version == WS_FAN_VERSION_1_0) {
        if (config->ws_lgtk_force[0] || config->ws_lgtk_force[1] || config->ws_lgtk_force[2])
            FATAL(1, "\"lgtk[i]\" is incompatible with \"fan_version = 1.0\"");
    }
#ifdef HAVE_WS_BORDER_ROUTER
    if (!memcmp(config->ipv6_prefix, ADDR_UNSPECIFIED, 16) && config->tun_autoconf)
        FATAL(1, "missing \"ipv6_prefix\" parameter");
    if (memcmp(config->ipv6_prefix, ADDR_UNSPECIFIED, 16) && !config->tun_autoconf)
        FATAL(1, "\"ipv6_prefix\" is only available when \"tun_autoconf\" is set");
#else
    if (!config->uart_dev[0])
        FATAL(1, "missing \"uart_device\" parameter");
    if (memcmp(config->ipv6_prefix, ADDR_UNSPECIFIED, 16))
        WARN("ipv6_prefix is ignored");
#endif
}
