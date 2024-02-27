/*
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

struct os_ctxt;

#define UART_HDR_LEN_MASK 0x07ff

int uart_open(const char *device, int bitrate, bool hardflow);

int uart_tx(struct os_ctxt *ctxt, const void *buf, unsigned int len);
int uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int len);

int uart_legacy_tx(struct os_ctxt *ctxt, const void *buf, unsigned int len);
int uart_legacy_rx(struct os_ctxt *ctxt, void *buf, unsigned int len);

// Try to find a valid APIv2 header within the first bytes received.
bool uart_detect_v2(struct os_ctxt *ctxt);

#endif

