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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include "common/ws/ws_regdb.h"
#include "common/commandline.h"
#include "common/key_value_storage.h"
#include "common/named_values.h"
#include "common/bus.h"
#include "common/parsers.h"
#include "common/memutils.h"
#include "common/log.h"
#include "common/specs/ws.h"
#include "common/string_extra.h"

#include "6lowpan/lowpan_mtu.h"
#include "net/netaddr_types.h"

#include "commandline_values.h"
#include "wsbr_cfg.h"
#include "wsbrd.h"

#include "commandline.h"

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

// 0xffff is not a valid pan_id and means 'undefined' or 'broadcast'
// See IEEE 802.15.4
static const struct number_limit valid_pan_id = {
    0, 0xfffe
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
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, cpc, hif, hif-extra\n");
    fprintf(stream, "                           tun, timers, trickle, 15.4-mngt, 15.4, eap, icmp, dhcp, rpl, neigh,\n");
    fprintf(stream, "                           drop, queue\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -D, --delete-storage  Delete storage upon start, which deauhenticates any previously\n");
    fprintf(stream, "                          connected nodes. Useful for testing.\n");
    fprintf(stream, "                          Setting this option twice (-DD) deletes the storage then exits.\n");
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
    fprintf(stream, "Debug:\n");
    fprintf(stream, "  --capture=FILE        Record raw data received on UART and network interfaces, and save it\n");
    fprintf(stream, "                          to FILE. Also record timer ticks, and use a predicable RNG for\n");
    fprintf(stream, "                          replay using wsbrd-fuzz.\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wsbrd -u /dev/ttyUSB0 -n Wi-SUN -d EU -C cert.pem -A ca.pem -K key.pem\n");
}

static void conf_set_macaddr(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    struct wsbrd_conf *config = raw_dest;
    bool allow = *(bool *)raw_param;
    uint8_t (*macaddr_list)[8];
    uint8_t macaddr_maxcount;
    uint8_t *macaddr_count;

    if (allow) {
        macaddr_list = config->ws_allowed_mac_addresses;
        macaddr_count = &config->ws_allowed_mac_address_count;
        macaddr_maxcount = ARRAY_SIZE(config->ws_allowed_mac_addresses);
    } else {
        macaddr_list = config->ws_denied_mac_addresses;
        macaddr_count = &config->ws_denied_mac_address_count;
        macaddr_maxcount = ARRAY_SIZE(config->ws_denied_mac_addresses);
    }
    if (*macaddr_count >= macaddr_maxcount)
        FATAL(1, "%s:%d: maximum number of denied MAC addresses reached", info->filename, info->linenr);
    if (parse_byte_array(macaddr_list[*macaddr_count], 8, info->value))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
    (*macaddr_count)++;
}

static void conf_set_gtk(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    uintptr_t gtk_count = (uintptr_t)raw_param;
    uint8_t (*gtks)[16] = raw_dest;

    if (info->key_array_index < 0 || info->key_array_index >= gtk_count)
        FATAL(1, "%s:%d: invalid key index: %d", info->filename, info->linenr, info->key_array_index);
    if (parse_byte_array(gtks[info->key_array_index], 16, info->value) ||
        !memzcmp(gtks[info->key_array_index], 16))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
}

static void conf_set_dhcp_internal(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    struct sockaddr_in6 *dest = raw_dest;
    bool internal_dhcp;

    WARN("\"internal_dhcp\" is deprecated, use \"dhcp_server\" instead");
    conf_set_bool(info, &internal_dhcp, NULL);
    if (internal_dhcp)
        dest->sin6_addr = in6addr_any;
    else
        dest->sin6_addr = in6addr_loopback;
}

void parse_commandline(struct wsbrd_conf *config, int argc, char *argv[],
                       void (*print_help)(FILE *stream))
{
    const struct option_struct opts_conf[] = {
        { "uart_device",                   config->rcp_cfg.uart_dev,               conf_set_string,      (void *)sizeof(config->rcp_cfg.uart_dev) },
        { "uart_baudrate",                 &config->rcp_cfg.uart_baudrate,         conf_set_number,      NULL },
        { "uart_rtscts",                   &config->rcp_cfg.uart_rtscts,           conf_set_bool,        NULL },
        { "cpc_instance",                  config->rcp_cfg.cpc_instance,           conf_set_string,      (void *)sizeof(config->rcp_cfg.cpc_instance) },
        { "tun_device",                    config->tun_dev,                           conf_set_string,      (void *)sizeof(config->tun_dev) },
        { "tun_autoconf",                  &config->tun_autoconf,                     conf_set_bool,        NULL },
        { "neighbor_proxy",                config->neighbor_proxy,                    conf_set_string,      (void *)sizeof(config->neighbor_proxy) },
        { "user",                          config->user,                              conf_set_string,      (void *)sizeof(config->user) },
        { "group",                         config->group,                             conf_set_string,      (void *)sizeof(config->group) },
        { "color_output",                  &config->color_output,                     conf_set_enum,        &valid_tristate },
        { "use_tap",                       NULL,                                      conf_deprecated,      NULL },
        { "ipv6_prefix",                   &config->ipv6_prefix,                      conf_set_netmask,     NULL },
        { "storage_prefix",                config->storage_prefix,                    conf_set_string,      (void *)sizeof(config->storage_prefix) },
        { "trace",                         &g_enabled_traces,                         conf_add_flags,       &valid_traces },
        { "internal_dhcp",                 &config->dhcp_server,                      conf_set_dhcp_internal, NULL },
        { "dhcp_server",                   &config->dhcp_server,                      conf_set_netaddr,     &valid_ipv6 },
        { "radius_server",                 &config->auth_cfg.radius_addr,             conf_set_netaddr,     &valid_ipv4or6 },
        { "radius_secret",                 config->auth_cfg.radius_secret,            conf_set_string,      (void *)sizeof(config->auth_cfg.radius_secret) },
        { "key",                           &config->auth_cfg.key,                     conf_set_pem,         NULL },
        { "certificate",                   &config->auth_cfg.cert,                    conf_set_pem,         NULL },
        { "authority",                     &config->auth_cfg.ca_cert,                 conf_set_pem,         NULL },
        { "network_name",                  config->ws_name,                           conf_set_string,      (void *)sizeof(config->ws_name) },
        { "size",                          &config->ws_size,                          conf_set_enum,        &valid_ws_size },
        { "domain",                        &config->ws_domain,                        conf_set_enum,        &valid_ws_domains },
        { "mode",                          &config->ws_mode,                          conf_set_enum_int_hex, &valid_ws_modes },
        { "phy_mode_id",                   &config->ws_phy_mode_id,                   conf_set_enum_int,    &valid_ws_phy_mode_ids },
        { "phy_operating_modes",           &config->ws_phy_op_modes,                  conf_set_phy_op_modes, &valid_ws_phy_mode_ids },
        { "class",                         &config->ws_class,                         conf_set_enum_int,    &valid_ws_classes },
        { "chan_plan_id",                  &config->ws_chan_plan_id,                  conf_set_enum_int,    &valid_ws_chan_plan_ids },
        { "regional_regulation",           &config->ws_regional_regulation,           conf_set_enum,        &valid_ws_regional_regulations },
        { "chan0_freq",                    &config->ws_chan0_freq,                    conf_set_number,      NULL },
        { "chan_spacing",                  &config->ws_chan_spacing,                  conf_set_number,      NULL },
        { "chan_count",                    &config->ws_chan_count,                    conf_set_number,      NULL },
        { "allowed_channels",              config->ws_allowed_channels,               conf_set_bitmask,     NULL },
        { "pan_id",                        &config->ws_pan_id,                        conf_set_number,      &valid_pan_id },
        { "enable_lfn",                    &config->enable_lfn,                       conf_set_bool,        NULL },
        { "enable_ffn10",                  &config->enable_ffn10,                     conf_set_bool,        NULL },
        { "rpl_compat",                    &config->rpl_compat,                       conf_set_bool,        NULL },
        { "rpl_rpi_ignorable",             &config->rpl_rpi_ignorable,                conf_set_bool,        NULL },
        { "fan_version",                   &config->ws_fan_version,                   conf_set_enum,        &valid_fan_versions },
        { "gtk\\[*]",                      config->auth_cfg.gtk_init,                 conf_set_gtk,         (void *)WS_GTK_COUNT },
        { "lgtk\\[*]",                     config->auth_cfg.gtk_init + WS_GTK_COUNT,  conf_set_gtk,         (void *)WS_LGTK_COUNT },
        { "tx_power",                      &config->tx_power,                         conf_set_number,      &valid_int8 },
        { "unicast_dwell_interval",        &config->uc_dwell_interval,                conf_set_number,      &valid_unicast_dwell_interval },
        { "broadcast_dwell_interval",      &config->bc_dwell_interval,                conf_set_number,      &valid_broadcast_dwell_interval },
        { "broadcast_interval",            &config->bc_interval,                      conf_set_number,      &valid_broadcast_interval },
        { "lfn_broadcast_interval",        &config->lfn_bc_interval,                  conf_set_number,      &valid_lfn_broadcast_interval },
        { "lfn_broadcast_sync_period",     &config->lfn_bc_sync_period,               conf_set_number,      &valid_lfn_broadcast_sync_period },
        { "pmk_lifetime",                  &config->auth_cfg.ffn.pmk_lifetime_s,      conf_set_seconds_from_minutes, &valid_unsigned },
        { "ptk_lifetime",                  &config->auth_cfg.ffn.ptk_lifetime_s,      conf_set_seconds_from_minutes, &valid_unsigned },
        { "gtk_expire_offset",             &config->auth_cfg.ffn.gtk_expire_offset_s, conf_set_seconds_from_minutes, &valid_unsigned },
        { "gtk_new_activation_time",       &config->auth_cfg.ffn.gtk_new_activation_time, conf_set_number,  &valid_positive },
        { "gtk_new_install_required",      &config->auth_cfg.ffn.gtk_new_install_required, conf_set_number, &valid_gtk_new_install_required },
        { "ffn_revocation_lifetime_reduction", &config->ws_ffn_revocation_lifetime_reduction, conf_set_number,      &valid_unsigned },
        { "lpmk_lifetime",                 &config->auth_cfg.lfn.pmk_lifetime_s,      conf_set_seconds_from_minutes, &valid_unsigned },
        { "lptk_lifetime",                 &config->auth_cfg.lfn.ptk_lifetime_s,      conf_set_seconds_from_minutes, &valid_unsigned },
        { "lgtk_expire_offset",            &config->auth_cfg.lfn.gtk_expire_offset_s, conf_set_seconds_from_minutes, &valid_unsigned },
        { "lgtk_new_activation_time",      &config->auth_cfg.lfn.gtk_new_activation_time, conf_set_number,  &valid_positive },
        { "lgtk_new_install_required",     &config->auth_cfg.lfn.gtk_new_install_required, conf_set_number, &valid_gtk_new_install_required },
        { "lfn_revocation_lifetime_reduction", &config->ws_lfn_revocation_lifetime_reduction, conf_set_number,      &valid_unsigned },
        { "mac_address",                   config->ws_mac_address,                    conf_set_array,       (void *)sizeof(config->ws_mac_address) },
        { "allowed_mac64",                 config,                                    conf_set_macaddr,     (bool[1]){ true } },
        { "denied_mac64",                  config,                                    conf_set_macaddr,     (bool[1]){ false } },
        { "async_frag_duration",           &config->ws_async_frag_duration,           conf_set_number,      &valid_async_frag_duration },
        { "join_metrics",                  &config->ws_join_metrics,                  conf_set_flags,       &valid_join_metrics },
        { "lowpan_mtu",                    &config->lowpan_mtu,                       conf_set_number,      &valid_lowpan_mtu },
        { "pan_size",                      &config->pan_size,                         conf_set_number,      &valid_uint16 },
        { "pcap_file",                     config->pcap_file,                         conf_set_string,      (void *)sizeof(config->pcap_file) },
        { }
    };
    static const char *opts_short = "u:F:o:t:T:n:d:m:c:S:K:C:A:b:HhvD";
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
        { "capture",     required_argument, 0,  'r' },
        { "hardflow",    no_argument,       0,  'H' },
        { "help",        no_argument,       0,  'h' },
        { "version",     no_argument,       0,  'v' },
        { "delete-storage", no_argument,    0,  'D' },
        { 0,             0,                 0,   0  }
    };
    const struct phy_params *phy_params;
    struct storage_parse_info info = {
        .filename = "command line",
    };
    int opt;

    // Keep these values in sync with examples/wsbrd.conf
    config->rcp_cfg.uart_baudrate = 115200;
    config->tun_autoconf = true;
    config->dhcp_server.sin6_family = AF_INET6;
    config->dhcp_server.sin6_addr = in6addr_any;
    config->ws_class = 0;
    config->ws_domain = REG_DOMAIN_UNDEF;
    config->ws_mode = 0;
    config->ws_size = WS_NETWORK_SIZE_SMALL;
    config->ws_pan_id = -1;
    config->ws_phy_op_modes[0] = -1;
    config->color_output = -1;
    config->tx_power = 14;
    config->uc_dwell_interval = 255;
    config->bc_interval = 1020;
    config->lfn_bc_interval = 60000;
    config->lfn_bc_sync_period = 5;
    config->bc_dwell_interval = 255;
    config->lowpan_mtu = 2043;
    config->auth_cfg.ffn.pmk_lifetime_s = 172800 * 60;
    config->auth_cfg.ffn.ptk_lifetime_s = 86400 * 60;
    config->auth_cfg.ffn.gtk_expire_offset_s = 43200 * 60;
    config->auth_cfg.ffn.gtk_new_activation_time = 720;
    config->auth_cfg.ffn.gtk_new_install_required = 80;
    config->ws_ffn_revocation_lifetime_reduction = 30;
    config->auth_cfg.lfn.pmk_lifetime_s = 172800 * 60;
    config->auth_cfg.lfn.ptk_lifetime_s = 525600 * 60;
    config->auth_cfg.lfn.gtk_expire_offset_s = 129600 * 60;
    config->auth_cfg.lfn.gtk_new_activation_time = 180;
    config->auth_cfg.lfn.gtk_new_install_required = 90;
    config->ws_lfn_revocation_lifetime_reduction = 30;
    config->ws_allowed_mac_address_count = 0;
    config->ws_denied_mac_address_count = 0;
    config->ws_regional_regulation = 0;
    config->ws_async_frag_duration = 500;
    config->pan_size = -1;
    config->ws_join_metrics = (unsigned int)-1;
    config->ws_fan_version = WS_FAN_VERSION_1_1;
    config->enable_lfn = true;
    config->enable_ffn10 = false;
    config->rpl_compat = true;
    config->rpl_rpi_ignorable = false;
    strcpy(config->storage_prefix, "/var/lib/wsbrd/");
    memset(config->ws_mac_address, 0xff, sizeof(config->ws_mac_address));
    memset(config->ws_allowed_channels, 0xFF, sizeof(config->ws_allowed_channels));
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                parse_config_file(opts_conf, optarg);
                break;
            case '?':
                print_help(stderr);
                exit(1);
            default:
                break;
        }
    }
    optind = 1; /* reset getopt */
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        if (optarg)
            strlcpy(info.value, optarg, sizeof(info.value));
        switch (opt) {
            case 'F':
                break;
            case 'u':
                strlcpy(config->rcp_cfg.uart_dev, optarg, sizeof(config->rcp_cfg.uart_dev));
                break;
            case 'o':
                strlcpy(info.line, optarg, sizeof(info.line));
                if (sscanf(info.line, " %256[^= ] = %256s", info.key, info.value) != 2)
                    FATAL(1, "%s:%d: syntax error: '%s'", info.filename, info.linenr, info.line);
                if (sscanf(info.key, "%*[^[][%u]", &info.key_array_index) != 1)
                    info.key_array_index = UINT_MAX;
                parse_config_line(opts_conf, &info);
                break;
            case 'l':
                config->list_rf_configs = true;
                break;
            case 't':
                strlcpy(config->tun_dev, optarg, sizeof(config->tun_dev));
                break;
            case 'T':
                strcpy(info.key, "trace");
                conf_add_flags(&info, &g_enabled_traces, valid_traces);
                break;
            case 'n':
                strlcpy(config->ws_name, optarg, sizeof(config->ws_name));
                break;
            case 'd':
                strcpy(info.key, "domain");
                conf_set_enum(&info, &config->ws_domain, valid_ws_domains);
                break;
            case 'm':
                strcpy(info.key, "mode");
                conf_set_enum_int_hex(&info, &config->ws_mode, valid_ws_modes);
                break;
            case 'c':
                strcpy(info.key, "class");
                conf_set_enum_int(&info, &config->ws_class, valid_ws_classes);
                break;
            case 'S':
                strcpy(info.key, "size");
                conf_set_enum(&info, &config->ws_size, valid_ws_size);
                break;
            case 'K':
                strcpy(info.key, "key");
                conf_set_pem(&info, &config->auth_cfg.key, NULL);
                break;
            case 'C':
                strcpy(info.key, "cert");
                conf_set_pem(&info, &config->auth_cfg.cert, NULL);
                break;
            case 'A':
                strcpy(info.key, "authority");
                conf_set_pem(&info, &config->auth_cfg.ca_cert, NULL);
                break;
            case 'b':
                FATAL(1, "deprecated option: -b/--baudrate");
                break;
            case 'H':
                FATAL(1, "deprecated option: -H/--hardflow");
                break;
            case 'D':
                if (config->storage_delete)
                    config->storage_exit = true;
                config->storage_delete = true;
                break;
            case 'r':
                strlcpy(config->capture, optarg, sizeof(config->capture));
                break;
            case 'h':
                print_help(stdout);
                // fall through
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
    if ((config->storage_exit || !config->list_rf_configs) && storage_check_access(config->storage_prefix))
        FATAL(1, "%s: %m", config->storage_prefix);
    if (config->storage_exit)
        return;
    if (!config->rcp_cfg.uart_dev[0] && !config->rcp_cfg.cpc_instance[0])
        FATAL(1, "missing \"uart_device\" (or \"cpc_instance\") parameter");
    if (config->rcp_cfg.uart_dev[0] && config->rcp_cfg.cpc_instance[0])
        FATAL(1, "\"uart_device\" and \"cpc_instance\" are exclusive %s", config->rcp_cfg.uart_dev);
    if (!config->user[0] && config->group[0])
        WARN("group is set while user is not: privileges will not be dropped if started as root");
    if (config->user[0] && !config->group[0])
        WARN("user is set while group is not: privileges will not be dropped if started as root");
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
    if (config->ws_domain == REG_DOMAIN_JP && config->ws_regional_regulation != HIF_REG_ARIB)
        WARN("Japanese regulation domain used without ARIB regional regulation");
    if (config->ws_domain != REG_DOMAIN_JP && config->ws_regional_regulation == HIF_REG_ARIB)
        FATAL(1, "ARIB is only supported with Japanese regulation domain");
    if (config->ws_domain == REG_DOMAIN_IN && config->ws_regional_regulation != HIF_REG_WPC)
        WARN("domain = IN used without regional_regulation = wpc");
    phy_params = ws_regdb_phy_params(config->ws_phy_mode_id, config->ws_mode);
    if (config->ws_regional_regulation == HIF_REG_ARIB && phy_params && phy_params->fec)
        FATAL(1, "ARIB is not supported with FSK FEC");
    if (!config->ws_mode && !config->ws_phy_mode_id)
        FATAL(1, "missing \"phy_mode_id\" parameter");
    if (config->ws_mode && config->ws_phy_mode_id)
        FATAL(1, "\"phy_mode_id\" and \"mode\" are mutually exclusive");
    if (config->ws_class && config->ws_chan_plan_id)
        FATAL(1, "\"chan_plan_id\" and \"class\" are mutually exclusive");
    if (config->ws_class && config->ws_phy_mode_id)
        WARN("mix FAN 1.1 PHY mode with FAN1.0 class");
    if (config->ws_chan_plan_id && !config->ws_phy_mode_id)
        WARN("mix FAN 1.0 mode with FAN1.1 channel plan");
    if (config->enable_ffn10 && config->enable_lfn)
        WARN("mixing enable_lfn and enable_ffn10 is unreliable and insecure");
    if (!config->ws_chan_plan_id && config->enable_lfn)
        WARN("enable_lfn without chan_plan_id");
    if (config->ws_chan_plan_id && config->enable_ffn10)
        WARN("enable_ffn10 with chan_plan_id");
    if (config->ws_mode && config->ws_phy_op_modes[0])
        WARN("mix \"phy_operating_modes\" and FAN1.0 mode");
    if (config->bc_interval < config->bc_dwell_interval)
        FATAL(1, "broadcast interval %d can't be lower than broadcast dwell interval %d", config->bc_interval, config->bc_dwell_interval);
    if (config->ws_allowed_mac_address_count > 0 && config->ws_denied_mac_address_count > 0)
        FATAL(1, "allowed_mac64 and denied_mac64 are exclusive");
    if (config->auth_cfg.radius_addr.ss_family == AF_UNSPEC) {
        if (!config->auth_cfg.key.iov_base)
            FATAL(1, "missing \"key\" (or \"auth_cfg.radius_addr\") parameter");
        if (!config->auth_cfg.cert.iov_base)
            FATAL(1, "missing \"certificate\" (or \"auth_cfg.radius_addr\") parameter");
        if (!config->auth_cfg.ca_cert.iov_base)
            FATAL(1, "missing \"authority\" (or \"auth_cfg.radius_addr\") parameter");
    } else {
        if (config->auth_cfg.key.iov_len || config->auth_cfg.cert.iov_len || config->auth_cfg.ca_cert.iov_len)
            WARN("ignore certificates and key since an external radius server is in use");
    }
    if (!config->enable_lfn && memzcmp(config->auth_cfg.gtk_init + WS_GTK_COUNT, 16 * WS_LGTK_COUNT))
        FATAL(1, "\"lgtk[i]\" is incompatible with \"enable_lfn = false\"");
    if (config->auth_cfg.ffn.gtk_new_install_required >= (100 - 100 / config->ws_ffn_revocation_lifetime_reduction))
        FATAL(1, "unsatisfied condition gtk_new_install_required < 100 * (1 - 1 / ffn_revocation_lifetime_reduction)");
    if (config->auth_cfg.lfn.gtk_new_install_required >= (100 - 100 / config->ws_lfn_revocation_lifetime_reduction))
        FATAL(1, "unsatisfied condition lgtk_new_install_required < 100 * (1 - 1 / lfn_revocation_lifetime_reduction)");
    if (IN6_IS_ADDR_UNSPECIFIED(&config->ipv6_prefix) && config->tun_autoconf)
        FATAL(1, "missing \"ipv6_prefix\" parameter");
    if (!IN6_IS_ADDR_UNSPECIFIED(&config->ipv6_prefix) && !config->tun_autoconf)
        FATAL(1, "\"ipv6_prefix\" is only available when \"tun_autoconf\" is set");
    for (int i = 0; config->ws_phy_op_modes[i]; i++)
        if (config->ws_phy_op_modes[i] != (uint8_t)-1 &&
            !ws_regdb_is_std(config->ws_domain, config->ws_phy_op_modes[i]))
            WARN("PHY %d is not standard in domain %s", config->ws_phy_op_modes[i],
                 val_to_str(config->ws_domain, valid_ws_domains, "<unknown>"));
    if (memzcmp(config->auth_cfg.gtk_init, sizeof(config->auth_cfg.gtk_init)) &&
         config->ws_pan_id != -1)
        WARN("setting both PAN_ID and (L)GTKs may generate inconsistencies on the network");
    if (config->capture[0] && !config->storage_delete)
        WARN("--capture used without --delete-storage");
    if (config->tun_autoconf && !IN6_IS_ADDR_UNSPECIFIED(&config->dhcp_server.sin6_addr))
        WARN("\"dhcp_server\" is set: make sure that \"ipv6_prefix\" matches");
}
