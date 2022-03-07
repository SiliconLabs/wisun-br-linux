/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_COMMANDLINE_H
#define WSBR_COMMANDLINE_H

#include <stdio.h>

struct wsbr_ctxt;

void print_help_br(FILE *stream, int exit_code);
void print_help_node(FILE *stream, int exit_code);

void parse_commandline(struct wsbr_ctxt *ctxt, int argc, char *argv[],
                       void (*print_help)(FILE *stream, int exit_code));

#endif

