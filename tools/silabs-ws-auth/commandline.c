/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2026 Silicon Laboratories Inc. (www.silabs.com)
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <getopt.h>
#include "common/ws/ws_regdb.h"
#include "common/key_value_storage.h"
#include "common/named_values.h"
#include "common/parsers.h"
#include "common/memutils.h"
#include "common/log.h"
#include "common/string_extra.h"

#include "commandline.h"

const struct name_value valid_traces[] = {
    { "drop",       TR_DROP | TR_TX_ABORT | TR_IGNORE },
    { "security",   TR_SECURITY },
    { "mbedtls",    TR_MBEDTLS },
    { "mqtt",       TR_MQTT },
    { }
};

static void print_help(FILE *stream) {
    fprintf(stream, "\n");
    fprintf(stream, "Start Silicon Labs Wi-SUN authenticator\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  silabs-ws-auth [OPTIONS]\n");
    fprintf(stream, "\n");
    fprintf(stream, "Common options:\n");
    fprintf(stream, "  -T, --trace=TAG[,TAG] Enable traces marked with TAG. Valid tags: security, drop, mbedtls,\n");
    fprintf(stream, "                          mqtt\n");
    fprintf(stream, "  -F, --config=FILE     Read parameters from FILE. Command line options always have priority\n");
    fprintf(stream, "                          on config file\n");
    fprintf(stream, "  -o, --opt=PARM=VAL    Assign VAL to the parameter PARM. PARM can be any parameter accepted\n");
    fprintf(stream, "                          in the config file\n");
    fprintf(stream, "  -D, --delete-storage  Delete storage upon start, which deauhenticates any previously\n");
    fprintf(stream, "                          connected nodes. Useful for testing.\n");
    fprintf(stream, "                          Setting this option twice (-DD) deletes the storage then exits.\n");
    fprintf(stream, "  -v, --version         Print version and exit\n");
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
    fprintf(stream, "  silabs-ws-auth -C cert.pem -A ca.pem -K key.pem\n");
}

void parse_commandline(struct sl_auth_cfg *cfg, int argc, char *argv[])
{
    const struct option_struct sl_auth_opts[] = {
        { "mac_address",    offsetof(struct sl_auth_cfg, eui64),            conf_set_array,  (void *)sizeof(struct eui64) },
        { "enable_ffn10",   offsetof(struct sl_auth_cfg, auth.allow_fan10), conf_set_bool,   NULL },
        { "enable_lfn",     offsetof(struct sl_auth_cfg, enable_lfn),       conf_set_bool,   NULL },
        { }
    };
    static const struct option_struct trace_opts[] = {
        { "trace", 0, conf_add_flags, &valid_traces },
        { }
    };
    const struct option_group opt_groups[] = {
        { sl_auth_opts, cfg },
        { trace_opts,   &g_enabled_traces },
        { storage_opts, &g_storage_prefix },
        { auth_opts,    &cfg->auth },
        { tls_opts,     &cfg->auth.tls },
        { }
    };
    static const char *opts_short = "F:o:T:K:C:A:hvD";
    static const struct option opts_long[] = {
        { "config",      required_argument, 0,  'F' },
        { "opt",         required_argument, 0,  'o' },
        { "trace",       required_argument, 0,  'T' },
        { "key",         required_argument, 0,  'K' },
        { "certificate", required_argument, 0,  'C' },
        { "authority",   required_argument, 0,  'A' },
        { "help",        no_argument,       0,  'h' },
        { "version",     no_argument,       0,  'v' },
        { "delete-storage", no_argument,    0,  'D' },
        { 0,             0,                 0,   0  }
    };
    struct storage_parse_info info = {
        .filename = "command line",
    };
    int opt;

    cfg->auth = auth_cfg_default;
    cfg->eui64 = EUI64_BC;
    cfg->enable_lfn = true;
    strcpy(g_storage_prefix, "/var/lib/silabs-ws-auth/");
    while ((opt = getopt_long(argc, argv, opts_short, opts_long, NULL)) != -1) {
        switch (opt) {
        case 'F':
            parse_config_file(opt_groups, optarg);
            break;
        case '?':
            print_help(stderr);
            exit(EXIT_FAILURE);
        }
    }
    optind = 1; // reset getopt
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
            parse_config_line(opt_groups, &info);
            break;
        case 'T':
            strcpy(info.key, "trace");
            conf_add_flags(&info, &g_enabled_traces, valid_traces);
            break;
        case 'K':
            strcpy(info.key, "key");
            conf_set_pem(&info, &cfg->auth.tls.key, NULL);
            break;
        case 'C':
            strcpy(info.key, "cert");
            conf_set_pem(&info, &cfg->auth.tls.cert, NULL);
            break;
        case 'A':
            strcpy(info.key, "authority");
            conf_set_pem(&info, &cfg->auth.tls.ca_cert, NULL);
            break;
        case 'D':
            if (cfg->storage_delete)
                cfg->storage_exit = true;
            cfg->storage_delete = true;
            break;
        case 'h':
            print_help(stdout);
            // fall through
        case 'v':
            // version is printed at the start of main
            exit(EXIT_SUCCESS);
        default:
            BUG();
        }
    }
    if (optind != argc)
        FATAL(1, "unexpected argument: %s", argv[optind]);
    if (storage_check_access(g_storage_prefix))
        FATAL(1, "%s: %m", g_storage_prefix);
    if (cfg->storage_exit)
        return;
    if (eui64_is_bc(&cfg->eui64))
        FATAL(1, "missing \"mac_address\" parameter");
    if (!cfg->enable_lfn && memzcmp(cfg->auth.gtk_init + WS_GTK_COUNT, 16 * WS_LGTK_COUNT))
        FATAL(1, "\"lgtk[i]\" is incompatible with \"enable_lfn = false\"");
}
