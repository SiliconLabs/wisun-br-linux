/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_COMMANDLINE_H
#define WSBR_COMMANDLINE_H

struct wsbr_ctxt;

void parse_commandline(struct wsbr_ctxt *ctxt, int argc, char *argv[]);

#endif

