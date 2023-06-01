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
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/file.h>

#include "endian.h"
#include "crc.h"
#include "log.h"
#include "utils.h"
#include "os_types.h"
#include "bus_uart.h"
#include "spinel_buffer.h"

int uart_open(const char *device, int bitrate, bool hardflow)
{
    static const struct {
        int val;
        int symbolic;
    } conversion[] = {
        { 9600, B9600 },
        { 19200, B19200 },
        { 38400, B38400 },
        { 57600, B57600 },
        { 115200, B115200 },
        { 230400, B230400 },
        { 460800, B460800 },
        { 921600, B921600 },
        { 1000000, B1000000 },
        { 1500000, B1500000 },
        { 2000000, B2000000 },
        { 2500000, B2500000 },
        { 3000000, B3000000 },
        { 3500000, B3500000 },
        { 4000000, B4000000 },
    };
    struct termios tty;
    int sym_bitrate = -1;
    int fd, i;

    fd = open(device, O_RDWR);
    if (fd < 0)
        FATAL(1, "%s: %m", device);

    if (tcgetattr(fd, &tty) == -1)
        FATAL(1, "%s: tcgetattr: %m", device);
    for (i = 0; i < ARRAY_SIZE(conversion); i++)
        if (conversion[i].val == bitrate)
            sym_bitrate = conversion[i].symbolic;
    if (sym_bitrate < 0)
        FATAL(1, "invalid bitrate: %d", bitrate);
    cfsetispeed(&tty, sym_bitrate);
    cfsetospeed(&tty, sym_bitrate);
    cfmakeraw(&tty);
    tty.c_cc[VTIME] = 0;
    tty.c_cc[VMIN] = 1;
    tty.c_iflag &= ~IXON;
    tty.c_iflag &= ~IXOFF;
    tty.c_iflag &= ~IXANY;
    tty.c_cflag &= ~HUPCL;
    tty.c_cflag |= CLOCAL;
    if (hardflow)
        tty.c_cflag |= CRTSCTS;
    else
        tty.c_cflag &= ~CRTSCTS;
    if (tcsetattr(fd, TCSAFLUSH, &tty) < 0)
        FATAL(1, "%s: tcsetattr: %m", device);
    if (flock(fd, LOCK_EX | LOCK_NB) < 0)
        FATAL(1, "%s: flock: %m", device);
    return fd;
}

static int uart_tx_append(uint8_t *buf, uint8_t byte)
{
    if (byte == 0x7D || byte == 0x7E) {
        buf[0] = 0x7D;
        buf[1] = byte ^ 0x20;
        return 2;
    } else {
        buf[0] = byte;
        return 1;
    }
}

size_t uart_encode_hdlc(uint8_t *out, const uint8_t *in, size_t in_len, uint16_t crc)
{
    uint8_t crc_bytes[2];
    int frame_len;

    frame_len = 0;
    for (int i = 0; i < in_len; i++)
        frame_len += uart_tx_append(out + frame_len, in[i]);
    write_le16(crc_bytes, crc);
    frame_len += uart_tx_append(out + frame_len, crc_bytes[0]);
    frame_len += uart_tx_append(out + frame_len, crc_bytes[1]);
    out[frame_len++] = 0x7E;
    return frame_len;
}

int uart_tx(struct os_ctxt *ctxt, const void *buf, unsigned int buf_len)
{
    uint16_t crc = crc16(buf, buf_len);
    uint8_t *frame = malloc(buf_len * 2 + 3);
    int frame_len;
    int ret;

    frame_len = uart_encode_hdlc(frame, buf, buf_len, crc);
    TRACE(TR_BUS, "bus tx: %s (%d bytes)",
          tr_bytes(frame, frame_len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), frame_len);
    TRACE(TR_HDLC, "hdlc tx: %s (%d bytes)",
          tr_bytes(buf, buf_len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), buf_len);
    ret = write(ctxt->data_fd, frame, frame_len);
    BUG_ON(ret != frame_len, "write: %m");
    
    ctxt->retransmission_index = (ctxt->retransmission_index + 1) % ARRAY_SIZE(ctxt->retransmission_buffers);
    memcpy(ctxt->retransmission_buffers[ctxt->retransmission_index].frame, frame, frame_len);
    ctxt->retransmission_buffers[ctxt->retransmission_index].frame_len = frame_len;
    ctxt->retransmission_buffers[ctxt->retransmission_index].crc = crc;

    free(frame);

    return frame_len;
}

/*
 * Returns the next HDLC frame if available, terminator included.
 */
size_t uart_rx_hdlc(struct os_ctxt *ctxt, uint8_t *buf, size_t buf_len)
{
    int frame_start, frame_len;
    int ret, i;

    if (!ctxt->uart_next_frame_ready) {
        ret = read(ctxt->data_fd,
                   ctxt->uart_rx_buf + ctxt->uart_rx_buf_len,
                   sizeof(ctxt->uart_rx_buf) - ctxt->uart_rx_buf_len);
        FATAL_ON(ret < 0, 2, "%s: read: %m", __func__);
        FATAL_ON(!ret, 2, "%s: read: Empty read", __func__);
        TRACE(TR_BUS, "bus rx: %s (%d bytes)",
               tr_bytes(ctxt->uart_rx_buf + ctxt->uart_rx_buf_len, ret, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), ret);
        ctxt->uart_rx_buf_len += ret;
    }

    i = 0;
    while (ctxt->uart_rx_buf[i] == 0x7E && i < ctxt->uart_rx_buf_len)
        i++;
    frame_start = i;
    while (ctxt->uart_rx_buf[i] != 0x7E && i < ctxt->uart_rx_buf_len)
        i++;
    frame_len = i - frame_start + 1;
    BUG_ON(ctxt->uart_next_frame_ready && i >= ctxt->uart_rx_buf_len);
    if (i >= ctxt->uart_rx_buf_len)
        return 0;

    BUG_ON(buf_len < frame_len);
    memcpy(buf, ctxt->uart_rx_buf + frame_start, frame_len);

    while (ctxt->uart_rx_buf[i] == 0x7E && i < ctxt->uart_rx_buf_len)
        i++;
    memmove(ctxt->uart_rx_buf, ctxt->uart_rx_buf + i, ctxt->uart_rx_buf_len - i);
    ctxt->uart_rx_buf_len -= i;

    i = 0;
    ctxt->uart_next_frame_ready = false;
    while (i < ctxt->uart_rx_buf_len) {
        if (ctxt->uart_rx_buf[i] == 0x7E) {
            ctxt->uart_next_frame_ready = true;
            break;
        }
        i++;
    }

    return frame_len;
}

size_t uart_decode_hdlc(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, bool inhibit_crc_warning)
{
    int i = 0, frame_len = 0;

    while (i < in_len - 1) {
        BUG_ON(frame_len > out_len);
        if (in[i] == 0x7D) {
            i++;
            out[frame_len++] = in[i] ^ 0x20;
        } else {
            BUG_ON(in[i] == 0x7E);
            out[frame_len++] = in[i];
        }
        i++;
    }
    if (frame_len <= 2) {
        WARN("frame length < 2, frame dropped");
        return 0;
    } else {
        frame_len -= sizeof(uint16_t);
        if (!crc_check(out, frame_len, read_le16(out + frame_len))) {
            if (!inhibit_crc_warning)
                WARN("bad crc, frame dropped");
            return 0;
        }
    }
    TRACE(TR_HDLC, "hdlc rx: %s (%d bytes)",
        tr_bytes(out, frame_len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), frame_len);
    return frame_len;
}

int uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len)
{
    uint8_t frame[4096];
    size_t frame_len;

    frame_len = uart_rx_hdlc(ctxt, frame, sizeof(frame));
    if (!frame_len)
        return 0;
    frame_len = uart_decode_hdlc(buf, buf_len, frame, frame_len, ctxt->uart_inhibit_crc_warning);
    return frame_len;
}

void uart_handle_crc_error(struct os_ctxt *ctxt, uint16_t crc, uint32_t frame_len, uint8_t header, uint8_t irq_err_counter)
{
    struct retransmission_frame *buffers = ctxt->retransmission_buffers;
    int buffers_len = ARRAY_SIZE(ctxt->retransmission_buffers);
    int extra_frame;
    int i;

    for (i = 0; i < buffers_len; i++) {
        if (buffers[i].crc == crc) {
            if (buffers[i].frame_len < frame_len) {
                extra_frame = (i + buffers_len - 1) % buffers_len;
                if (buffers[extra_frame].frame[0] != header) {
                    WARN("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): 1 packet lost, %d bytes recovered",
                         irq_err_counter, frame_len, header, crc, buffers[i].frame_len);
                } else {
                    DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d + %d bytes recovered",
                          irq_err_counter, frame_len, header, crc,
                          buffers[extra_frame].frame_len, buffers[i].frame_len);
                    write(ctxt->data_fd, buffers[extra_frame].frame, buffers[extra_frame].frame_len);
                }
            } else {
                DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d bytes recovered",
                      irq_err_counter, frame_len, header, crc, buffers[i].frame_len);
            }
            write(ctxt->data_fd, buffers[i].frame, buffers[i].frame_len);
            return;
        }
    }
    for (i = 0; i < buffers_len; i++) {
        if (buffers[i].frame[0] == header) {
            write(ctxt->data_fd, buffers[i].frame, buffers[i].frame_len);
            if (buffers[i].frame_len < frame_len) {
                extra_frame = (i + 1) % buffers_len;
                DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d + %d bytes recovered (header match)",
                      irq_err_counter, frame_len, header, crc,
                      buffers[i].frame_len, buffers[extra_frame].frame_len);
                write(ctxt->data_fd, buffers[extra_frame].frame, buffers[extra_frame].frame_len);
            } else {
                DEBUG("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): %d bytes recovered (header match)",
                      irq_err_counter, frame_len, header, crc, buffers[i].frame_len);
            }
            return;
        }
    }
    WARN("crc error (%d overruns in %d bytes, hdr/crc: %02x/%04x): one or several packets lost",
         irq_err_counter, frame_len, header, crc);
}
