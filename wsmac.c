/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "wsmac.h"

// See warning in wsmac.h
struct wsmac_ctxt g_ctxt = { };

void print_help(FILE *stream, int exit_code) {
    fprintf(stream, "Start Wi-SUN MAC emulation\n");
    fprintf(stream, "\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  wisun-mac [OPTIONS] UART_DEVICE\n");
    fprintf(stream, "\n");
    fprintf(stream, "Examples:\n");
    fprintf(stream, "  wisun-mac /dev/pts/15\n");
    exit(exit_code);
}

void configure(struct wsmac_ctxt *ctxt, int argc, char *argv[])
{
    static const struct option opt_list[] = {
        { "help", no_argument, 0, 'h' },
        { 0,      0,           0,  0  }
    };
    int opt;

    while ((opt = getopt_long(argc, argv, "h", opt_list, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help(stdout, 0);
                break;
            case '?':
            default:
                print_help(stderr, 1);
                break;
        }
    }
    if (argc != optind + 1)
        print_help(stderr, 1);
}

int main(int argc, char *argv[])
{
    struct wsmac_ctxt *ctxt = &g_ctxt;

    configure(ctxt, argc, argv);

    return 0;
}

