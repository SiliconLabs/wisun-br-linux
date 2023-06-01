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
#ifndef COMMON_OS_TYPES_H
#define COMMON_OS_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#ifdef HAVE_LIBCPC
#include <sl_cpc.h>
#endif

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
    int     spinel_tid;
    int     spinel_iid;
    bool    uart_next_frame_ready;
    int     uart_rx_buf_len;
    uint8_t uart_rx_buf[2048];
    bool    uart_inhibit_crc_warning;
#ifdef HAVE_LIBCPC
    cpc_endpoint_t cpc_ep;
#endif

    // For retransmission in case of crc error on the rcp
    // FIXME: rename this and the structure / naive circular buffer : rearch
    int retransmission_index;
    struct retransmission_frame retransmission_buffers[15]; // spinel header range from 1 to 15
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct os_ctxt g_os_ctxt;

#endif
