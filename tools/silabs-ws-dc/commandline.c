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

#include "common/key_value_storage.h"
#include "common/commandline.h"
#include "common/ws_regdb.h"
#include "common/log.h"

#include "commandline.h"

static const struct name_value valid_traces[] = {
    { "bus",        TR_BUS },
    { "cpc",        TR_CPC },
    { "hif",        TR_HIF },
    { "hif-extra",  TR_HIF_EXTRA },
    { "drop",       TR_DROP | TR_IGNORE | TR_TX_ABORT },
    { "neigh-15.4", TR_NEIGH_15_4 },
    { "15.4",       TR_15_4_DATA | TR_15_4_MNGT },
    { NULL },
};

// Wi-SUN FAN 1.1v08 6.3.2.3.2.1.3 Field Definitions
static const struct number_limit valid_uc_dwell_interval = {
    15, 255
};

static void print_help(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN Direct Connect Daemon\n");
    fprintf(stream, "Open an IPv6 link external to any operating Wi-SUN with the specified target.\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  silabs-ws-dc [OPTIONS]\n");
    fprintf(stream, "  silabs-ws-dc [OPTIONS] --list-rf-configs\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -u UART_DEVICE        Use UART bus\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: bus, cpc, hif, hif-extra,\n");
    fprintf(stream, "                          drop, 15.4, neigh-15.4\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -l, --list-rf-configs Retrieve the possible RF configurations from the RCP then exit. Most\n");
    fprintf(stream, "                          of parameters are ignored in this mode\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
    fprintf(stream, "\n");
}

void parse_commandline(struct dc_cfg *config, int argc, char *argv[])
{
    const struct option_struct opts_conf[] = {
        { "uart_device",                   config->rcp_cfg.uart_dev,                  conf_set_string,      (void *)sizeof(config->rcp_cfg.uart_dev) },
        { "uart_baudrate",                 &config->rcp_cfg.uart_baudrate,            conf_set_number,      NULL },
        { "uart_rtscts",                   &config->rcp_cfg.uart_rtscts,              conf_set_bool,        NULL },
        { "cpc_instance",                  config->rcp_cfg.cpc_instance,              conf_set_string,      (void *)sizeof(config->rcp_cfg.cpc_instance) },
        { "domain",                        &config->ws_domain,                        conf_set_enum,        &valid_ws_domains },
        { "mode",                          &config->ws_mode,                          conf_set_enum_int_hex, &valid_ws_modes },
        { "phy_mode_id",                   &config->ws_phy_mode_id,                   conf_set_enum_int,    &valid_ws_phy_mode_ids },
        { "class",                         &config->ws_class,                         conf_set_enum_int,    &valid_ws_classes },
        { "chan_plan_id",                  &config->ws_chan_plan_id,                  conf_set_enum_int,    &valid_ws_chan_plan_ids },
        { "chan0_freq",                    &config->ws_chan0_freq,                    conf_set_number,      NULL },
        { "chan_spacing",                  &config->ws_chan_spacing,                  conf_set_number,      NULL },
        { "chan_count",                    &config->ws_chan_count,                    conf_set_number,      NULL },
        { "allowed_channels",              config->ws_allowed_channels,               conf_set_bitmask,     NULL },
        { "unicast_dwell_interval",        &config->ws_uc_dwell_interval_ms,          conf_set_number,      &valid_uc_dwell_interval },
        { "trace",                         &g_enabled_traces,                         conf_add_flags,       &valid_traces },
        { "color_output",                  &config->color_output,                     conf_set_enum,        &valid_tristate },
        { }
    };
    static const char *opts_short = "F:o:u:T:lhv";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
        { "trace",       required_argument, 0,  'T' },
        { "list-rf-configs", no_argument,   0,  'l' },
        { "help",        no_argument,       0,  'h' },
        { "version",     no_argument,       0,  'v' },
        { 0,             0,                 0,   0  }
    };
    struct storage_parse_info info = {
        .filename = "command line",
    };
    int opt;

    config->rcp_cfg.uart_baudrate = 115200;
    config->ws_domain = REG_DOMAIN_UNDEF;
    config->ws_uc_dwell_interval_ms = 255;
    memset(config->ws_allowed_channels, 0xff, sizeof(config->ws_allowed_channels));
    config->color_output = -1;
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
            case 'F':
                parse_config_file(opts_conf, optarg);
                break;
            case '?':
                print_help(stderr);
                exit(1);
                break;
            default:
                break;
        }
    }
    optind = 1; // Reset getopt
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        if (optarg)
            strcpy(info.value, optarg);
        switch (opt) {
            case 'F':
                break;
            case 'o':
                snprintf(info.line, sizeof(info.line), "%s", optarg); // safe strncpy()
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
            case 'h':
                print_help(stdout);
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                // Version is printed at the start of main
                exit(EXIT_SUCCESS);
            default:
                BUG();
        }
    }
    if (optind != argc)
        FATAL(1, "unexpected argument: %s", argv[optind]);
    if (!config->rcp_cfg.uart_dev[0] && !config->rcp_cfg.cpc_instance[0])
        FATAL(1, "missing \"uart_device\" (or \"cpc_instance\") parameter");
    if (config->rcp_cfg.uart_dev[0] && config->rcp_cfg.cpc_instance[0])
        FATAL(1, "\"uart_device\" and \"cpc_instance\" are exclusive %s", config->rcp_cfg.uart_dev);
    if (config->list_rf_configs)
        return;
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
}
