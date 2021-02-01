/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef TUN_H
#define TUN_H

struct wsbr_ctxt;

int wsbr_tun_open(char *devname);
void wsbr_tun_read(struct wsbr_ctxt *ctxt);

#endif

