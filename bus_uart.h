/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef BUS_UART_H
#define BUS_UART_H

#include <stdbool.h>

int mux_uart_open(const char *device, int bitrate, bool hardflow);

#endif

