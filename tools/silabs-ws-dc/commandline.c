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
#include "common/log.h"

#include "commandline.h"

static const struct name_value valid_traces[] = {
    { NULL },
};

static void print_help(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Wi-SUN Direct Connect Daemon\n");
    fprintf(stream, "Open an IPv6 link external to any operating Wi-SUN with the specified target.\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  silabs-ws-dc [OPTIONS]\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags:");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
    fprintf(stream, "\n");
}

void parse_commandline(struct dc_cfg *config, int argc, char *argv[])
{
    const struct option_struct opts_conf[] = {
        { "trace",                         &g_enabled_traces,                         conf_add_flags,       &valid_traces },
        { "color_output",                  &config->color_output,                     conf_set_enum,        &valid_tristate },
        { }
    };
    static const char *opts_short = "F:o:u:T:lhv";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
        { "trace",       required_argument, 0,  'T' },
        { "help",        no_argument,       0,  'h' },
        { "version",     no_argument,       0,  'v' },
        { 0,             0,                 0,   0  }
    };
    struct storage_parse_info info = {
        .filename = "command line",
    };
    int opt;

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
            case 'T':
                strcpy(info.key, "trace");
                conf_add_flags(&info, &g_enabled_traces, valid_traces);
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
}
