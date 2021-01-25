/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef CPCD_H
#define CPCD_H

#define MAX_CLIENTS 10

struct mux_ctxt;

struct mux_ctxt {
    int (*tx_bus)(struct mux_ctxt *ctxt, const void *buf, unsigned int len);
    int (*rx_bus)(struct mux_ctxt *ctxt, void *buf, unsigned int len);
    int fd_trig;
    int fd_bus;
    int fd_sock;
    int clients[MAX_CLIENTS];
};

#endif

