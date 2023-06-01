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

int uart_open(const char *device, int bitrate, bool hardflow);
int uart_tx(struct os_ctxt *ctxt, const void *buf, unsigned int len);
int uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int len);
void uart_handle_crc_error(struct os_ctxt *ctxt, uint16_t crc, uint32_t frame_len, uint8_t header, uint8_t irq_err_counter);

// These functions are exported for debug purposes
size_t uart_rx_hdlc(struct os_ctxt *ctxt, uint8_t *buf, size_t buf_len);
size_t uart_decode_hdlc(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, bool inhibit_crc_warning);
size_t uart_encode_hdlc(uint8_t *out, const uint8_t *in, size_t in_len, uint16_t crc);

#endif

