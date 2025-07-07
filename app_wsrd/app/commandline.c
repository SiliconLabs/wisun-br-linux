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
#define _GNU_SOURCE
#include <getopt.h>

#include "common/ws/ws_regdb.h"
#include "common/commandline.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/named_values.h"
#include "common/string_extra.h"
#include "common/parsers.h"

#include "commandline.h"

const struct name_value valid_traces[] = {
    { "bus",        TR_BUS },
    { "cpc",        TR_CPC },
    { "hif",        TR_HIF },
    { "hif-extra",  TR_HIF_EXTRA },
    { "15.4",       TR_15_4_DATA | TR_15_4_MNGT },
    { "15.4-mngt",  TR_15_4_MNGT },
    { "ipv6",       TR_IPV6 },
    { "icmp",       TR_ICMP },
    { "dhcp",       TR_DHCP },
    { "rpl",        TR_RPL },
    { "neigh-15.4", TR_NEIGH_15_4 },
    { "neigh-ipv6", TR_NEIGH_IPV6 },
    { "security",   TR_SECURITY },
    { "mbedtls",    TR_MBEDTLS },
    { "drop",       TR_DROP | TR_IGNORE | TR_TX_ABORT },
    { "trickle",    TR_TRICKLE },
    { "tun",        TR_TUN },
    { NULL },
};

// Wi-SUN FAN 1.1v08 6.3.2.3.2.1.3 Field Definitions
static const struct number_limit valid_uc_dwell_interval = {
    15, 255
};

static void conf_set_macaddr(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    struct wsrd_conf *config = raw_dest;
    bool allow = *(bool *)raw_param;
    struct eui64 *macaddr_list;
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
    if (parse_byte_array(macaddr_list[*macaddr_count].u8, sizeof(struct eui64), info->value))
        FATAL(1, "%s:%d: invalid key: %s", info->filename, info->linenr, info->value);
    (*macaddr_count)++;
}

void print_help(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN router\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wsrd [OPTIONS]\n");
    fprintf(stream, "  wsrd [OPTIONS] --list-rf-configs\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, cpc, hif, hif-extra,\n");
    fprintf(stream, "                          15.4, 15.4-mngt, ipv6, dhcp, rpl, neigh-15.4, neigh-ipv6, drop,\n");
    fprintf(stream, "                          security, mbedtls, trickle\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -l, --list-rf-configs Retrieve the possible RF configurations from the RCP then exit. Most\n");
    fprintf(stream, "                          of parameters are ignored in this mode\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
    fprintf(stream, "\n");
}

void parse_commandline(struct wsrd_conf *config, int argc, char *argv[])
{
    const struct option_struct opts_conf[] = {
        { "uart_device",                   config->rcp_cfg.uart_dev,               conf_set_string,      (void *)sizeof(config->rcp_cfg.uart_dev) },
        { "uart_baudrate",                 &config->rcp_cfg.uart_baudrate,         conf_set_number,      NULL },
        { "uart_rtscts",                   &config->rcp_cfg.uart_rtscts,           conf_set_bool,        NULL },
        { "cpc_instance",                  config->rcp_cfg.cpc_instance,           conf_set_string,      (void *)sizeof(config->rcp_cfg.cpc_instance) },
        { "tun_device",                    config->tun_dev,                           conf_set_string,      (void *)sizeof(config->tun_dev) },
        { "tun_autoconf",                  &config->tun_autoconf,                     conf_set_bool,        NULL },
        { "user",                          config->user,                              conf_set_string,      (void *)sizeof(config->user) },
        { "group",                         config->group,                             conf_set_string,      (void *)sizeof(config->group) },
        { "network_name",                  config->ws_netname,                        conf_set_string,      (void *)sizeof(config->ws_netname) },
        { "domain",                        &config->ws_domain,                        conf_set_enum,        &valid_ws_domains },
        { "mode",                          &config->ws_mode,                          conf_set_enum_int_hex, &valid_ws_modes },
        { "phy_mode_id",                   &config->ws_phy_mode_id,                   conf_set_enum_int,    &valid_ws_phy_mode_ids },
        { "phy_operating_modes",           &config->ws_phy_op_modes,                  conf_set_phy_op_modes, &valid_ws_phy_mode_ids },
        { "class",                         &config->ws_class,                         conf_set_enum_int,    &valid_ws_classes },
        { "duty_cycle_budget",             &config->duty_cycle.budget_ms,             conf_set_number,      &valid_budget },
        { "duty_cycle_threshold\\[*]",     &config->duty_cycle.threshold,             conf_set_threshold,   (void *)DUTY_CYCLE_LEVEL_MAX },
        { "duty_chan_cycle_budget",        &config->duty_cycle.chan_budget_ms,        conf_set_number,      &valid_budget },
        { "duty_cycle_chan_threshold\\[*]", &config->duty_cycle.chan_threshold,       conf_set_threshold,   (void *)DUTY_CYCLE_LEVEL_MAX },
        { "chan_plan_id",                  &config->ws_chan_plan_id,                  conf_set_enum_int,    &valid_ws_chan_plan_ids },
        { "chan0_freq",                    &config->ws_chan0_freq,                    conf_set_number,      NULL },
        { "chan_spacing",                  &config->ws_chan_spacing,                  conf_set_number,      NULL },
        { "chan_count",                    &config->ws_chan_count,                    conf_set_number,      NULL },
        { "allowed_channels",              config->ws_allowed_channels,               conf_set_bitmask,     NULL },
        { "unicast_dwell_interval",        &config->ws_uc_dwell_interval_ms,          conf_set_number,      &valid_uc_dwell_interval },
        { "tx_power",                      &config->tx_power,                         conf_set_number,      &valid_int8 },
        { "trace",                         &g_enabled_traces,                         conf_add_flags,       &valid_traces },
        { "color_output",                  &config->color_output,                     conf_set_enum,        &valid_tristate },
        { "authority",                     &config->supp_cfg.tls.ca_cert,             conf_set_pem,         NULL },
        { "certificate",                   &config->supp_cfg.tls.cert,                conf_set_pem,         NULL },
        { "key",                           &config->supp_cfg.tls.key,                 conf_set_pem,         NULL },
        { "eap_identity",                  &config->supp_cfg.eap_identity,            conf_set_string,      (void *)sizeof(config->supp_cfg.eap_identity) },
        { "disc_imin",                     &config->disc_cfg.Imin_ms,                 conf_set_ms_from_s,   NULL },
        { "disc_imax",                     &config->disc_cfg.Imax_ms,                 conf_set_ms_from_s,   NULL },
        { "disc_k",                        &config->disc_cfg.k,                       conf_set_number,      &valid_positive },
        { "mac_address",                   &config->ws_mac_address,                   conf_set_array,       (void *)sizeof(config->ws_mac_address) },
        { "allowed_mac64",                 config,                                    conf_set_macaddr,     (bool[1]){ true } },
        { "denied_mac64",                  config,                                    conf_set_macaddr,     (bool[1]){ false } },
        { "rpl_compat",                    &config->rpl_compat,                       conf_set_bool,        NULL },
        { "storage_prefix",                config->storage_prefix,                    conf_set_string,      (void *)sizeof(config->storage_prefix) },
        { "gtk_max_mismatch",              &config->supp_cfg.gtk_max_mismatch_s,      conf_set_seconds_from_minutes, &valid_positive },
        { }
    };
    static const char *opts_short = "F:o:u:T:lhvD";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
        { "trace",       required_argument, 0,  'T' },
        { "list-rf-configs", no_argument,   0,  'l' },
        { "help",        no_argument,       0,  'h' },
        { "version",     no_argument,       0,  'v' },
        { "delete-storage", no_argument,    0,  'D' },
        { 0,             0,                 0,   0  }
    };
    struct storage_parse_info info = {
        .filename = "command line",
    };
    int opt;

    config->ws_phy_op_modes[0] = -1;

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
    optind = 1; // Reset getopt
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        if (optarg)
            strlcpy(info.value, optarg, sizeof(info.value));
        switch (opt) {
            case 'F':
                break;
            case 'o':
                strlcpy(info.line, optarg, sizeof(info.line));
                if (sscanf(info.line, " %256[^= ] = %256s", info.key, info.value) != 2)
                    FATAL(1, "%s:%d: syntax error: '%s'", info.filename, info.linenr, info.line);
                if (sscanf(info.key, "%*[^[][%u]", &info.key_array_index) != 1)
                    info.key_array_index = UINT_MAX;
                parse_config_line(opts_conf, &info);
                break;
            case 'u':
                strcpy(info.key, "uart_device");
                conf_set_string(&info, &config->rcp_cfg.uart_dev, (void *)sizeof(config->rcp_cfg.uart_dev));
                break;
            case 'T':
                strcpy(info.key, "trace");
                conf_add_flags(&info, &g_enabled_traces, valid_traces);
                break;
            case 'l':
                config->list_rf_configs = true;
                break;
            case 'D':
                config->storage_delete = true;
                break;
            case 'h':
                print_help(stdout);
                // fall through
            case 'v':
                // Version is printed at the start of main
                exit(EXIT_SUCCESS);
            default:
                BUG();
        }
    }
    if (optind != argc)
        FATAL(1, "unexpected argument: %s", argv[optind]);
    if (storage_check_access(config->storage_prefix))
        FATAL(1, "%s: %m", config->storage_prefix);
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
    if (!config->ws_netname[0])
        FATAL(1, "missing \"network_name\" parameter");
    if (config->ws_chan0_freq || config->ws_chan_spacing || config->ws_chan_count) {
        if (config->ws_domain != REG_DOMAIN_UNDEF || config->ws_class || config->ws_chan_plan_id)
            FATAL(1, "custom channel plan is exclusive with \"class\", \"chan_plan_id\" and \"domain\"");
        if (!config->ws_chan0_freq)
            FATAL(1, "custom channel plan needs \"chan0_freq\"");
        if (!config->ws_chan_spacing)
            FATAL(1, "custom channel plan needs \"chan_spacing\"");
        if (!config->ws_chan_count)
            FATAL(1, "custom channel plan needs \"chan_count\"");
    } else {
        if (config->ws_domain == REG_DOMAIN_UNDEF)
            FATAL(1, "missing \"domain\" parameter");
        if (!config->ws_class && !config->ws_chan_plan_id)
            FATAL(1, "missing \"chan_plan_id\" parameter");
    }
    if (!config->ws_mode && !config->ws_phy_mode_id)
        FATAL(1, "missing \"phy_mode_id\" parameter");
    if (config->ws_mode && config->ws_phy_mode_id)
        FATAL(1, "\"phy_mode_id\" and \"mode\" are mutually exclusive");
    if (config->ws_class && config->ws_chan_plan_id)
        FATAL(1, "\"chan_plan_id\" and \"class\" are mutually exclusive");
    if (config->ws_class && config->ws_phy_mode_id)
        WARN("mix FAN 1.1 \"phy_mode_id\" with FAN 1.0 \"class\"");
    if (config->ws_chan_plan_id && !config->ws_phy_mode_id)
        WARN("mix FAN 1.0 \"mode\" with FAN 1.1 \"chan_plan_id\"");
    if (!config->supp_cfg.tls.key.iov_base)
        FATAL(1, "missing \"key\" parameter");
    if (!config->supp_cfg.tls.cert.iov_base)
        FATAL(1, "missing \"certificate\" parameter");
    if (!config->supp_cfg.tls.ca_cert.iov_base)
        FATAL(1, "missing \"authority\" parameter");
    if (!config->disc_cfg.Imin_ms)
        FATAL(1, "invalid \"disc_imin\" parameter");
    if (!config->disc_cfg.Imax_ms)
        FATAL(1, "invalid \"disc_imax\" parameter");
    if (config->disc_cfg.Imin_ms >= config->disc_cfg.Imax_ms)
        FATAL(1, "inconsistent disc_imin and disc_imax values (disc_imin >= disc_imax)");
    if (config->ws_allowed_mac_address_count && config->ws_denied_mac_address_count)
        FATAL(1, "allowed_mac64 and denied_mac64 are exclusive");
    if (config->ws_mode && config->ws_phy_op_modes[0])
        WARN("mix \"phy_operating_modes\" and FAN1.0 mode");
    for (int i = 0; config->ws_phy_op_modes[i]; i++)
        if (config->ws_phy_op_modes[i] != (uint8_t)-1 &&
            !ws_regdb_is_std(config->ws_domain, config->ws_phy_op_modes[i]))
            WARN("PHY %d is not standard in domain %s", config->ws_phy_op_modes[i],
                 val_to_str(config->ws_domain, valid_ws_domains, "<unknown>"));
    duty_cycle_cfg_check(&config->duty_cycle);
}
