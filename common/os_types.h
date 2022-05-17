/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef OS_H
#define OS_H

#include <stdint.h>
#include <stdbool.h>

struct slist;


struct retransmission_frame {
    uint8_t frame[2048];
    uint16_t frame_len;
    uint16_t crc;
};

struct os_ctxt {
    int     trig_fd;
    int     data_fd;
    int     spi_recv_window;
    bool    uart_next_frame_ready;
    int     uart_rx_buf_len;
    uint8_t uart_rx_buf[2048];

    int event_fd[2];
    
    // For retransmission in case of crc error on the rcp
    // FIXME: rename this and the structure / naive circular buffer : rearch
    int retransmission_index;
    struct retransmission_frame retransmission_buffers[64];
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct os_ctxt g_os_ctxt;

#endif
