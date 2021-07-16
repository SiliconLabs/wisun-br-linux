/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef BUS_UART_H
#define BUS_UART_H

#include <stdbool.h>

struct os_ctxt;

int uart_open(const char *device, int bitrate, bool hardflow);
int uart_tx(struct os_ctxt *ctxt, const void *buf, unsigned int len);
int uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int len);

#endif

