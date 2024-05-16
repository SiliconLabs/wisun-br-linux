/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef BUS_UART_H
#define BUS_UART_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct bus;

#define UART_HDR_LEN_MASK 0x07ff

struct bus_uart {
    bool    data_ready;
    int     rx_buf_len;
    uint8_t rx_buf[2048];
    bool    init_phase;
};

int uart_open(const char *device, int bitrate, bool hardflow);

int uart_tx(struct bus *bus, const void *buf, unsigned int len);
int uart_rx(struct bus *bus, void *buf, unsigned int len);

int uart_legacy_tx(struct bus *bus, const void *buf, unsigned int len);
int uart_legacy_rx(struct bus *bus, void *buf, unsigned int len);

// Try to find a valid APIv2 header within the first bytes received.
bool uart_detect_v2(struct bus *bus);

// Wait for the kernel transmission queue to send all of its content.
void uart_tx_flush(struct bus *bus);

#endif

