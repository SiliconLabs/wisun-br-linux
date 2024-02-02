/*
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include <unistd.h>

#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/rcp_api_legacy.h"
#include "common/bits.h"
#include "common/bus_uart.h"
#include "common/crc.h"
#include "common/endian.h"
#include "common/log.h"
#include "common/hif.h"
#include "common/spinel.h"
#include "common/iobuf.h"
#include "common/memutils.h"
#include "common/version.h"
#include "wsbrd_fuzz.h"
#include "interfaces.h"
#include "capture.h"

void fuzz_capture_uart(struct fuzz_ctxt *ctxt, const void *buf, size_t buf_len)
{
    uint8_t hdr[4], fcs[2];
    const struct iovec iov[] = {
        { .iov_base = hdr,         .iov_len = sizeof(hdr) },
        { .iov_base = (void *)buf, .iov_len = buf_len     },
        { .iov_base = fcs,         .iov_len = sizeof(fcs) },
    };
    ssize_t ret;
    int fd;

    if (ctxt->capture_init_fd >= 0 && !fuzz_is_main_loop(&g_ctxt))
        fd = ctxt->capture_init_fd;
    else
        fd = ctxt->capture_fd;

    BUG_ON(buf_len > FIELD_MAX(UART_HDR_LEN_MASK));
    write_le16(hdr,     buf_len);
    write_le16(hdr + 2, crc16(CRC_INIT_HCS, hdr, 2));
    write_le16(fcs,     crc16(CRC_INIT_FCS, buf, buf_len));

    ret = writev(fd, iov, ARRAY_SIZE(iov));
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    if (ret != sizeof(hdr) + buf_len + sizeof(fcs))
        FATAL(2 ,"%s: write: Short write", __func__);
}

void fuzz_capture_timers(struct fuzz_ctxt *ctxt)
{
    struct iobuf_write buf = { };

    if (!ctxt->timer_counter)
        return;

    hif_push_u8(&buf, HIF_CMD_IND_REPLAY_TIMER);
    hif_push_u16(&buf, ctxt->timer_counter);
    fuzz_capture_uart(ctxt, buf.data, buf.len);
    iobuf_free(&buf);
    ctxt->timer_counter = 0;
}

void fuzz_capture_interface(struct fuzz_ctxt *ctxt, uint8_t interface,
                            const uint8_t src_addr[16], const uint8_t dst_addr[16],
                            uint16_t src_port, const void *data, size_t size)
{
    struct iobuf_write buf = { };

    hif_push_u8(&buf, HIF_CMD_IND_REPLAY_SOCKET);
    hif_push_u8(&buf, interface);
    hif_push_fixed_u8_array(&buf, src_addr, 16);
    hif_push_fixed_u8_array(&buf, dst_addr, 16);
    hif_push_u16(&buf, src_port);
    hif_push_data(&buf, data, size);
    fuzz_capture_uart(ctxt, buf.data, buf.len);
    iobuf_free(&buf);
}
