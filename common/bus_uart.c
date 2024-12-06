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
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <termios.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include "common/bits.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common/crc.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/bus.h"
#include "common/hif.h"

#include "bus_uart.h"

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

static void uart_read(struct bus *bus)
{
    ssize_t size;

    size = read(bus->fd,
                bus->uart.rx_buf + bus->uart.rx_buf_len,
                sizeof(bus->uart.rx_buf) - bus->uart.rx_buf_len);
    FATAL_ON(size < 0, 2, "%s: read: %m", __func__);
    FATAL_ON(!size, 2, "%s: read: Empty read", __func__);
    TRACE(TR_BUS, "bus rx: %s (%zd bytes)",
          tr_bytes(bus->uart.rx_buf + bus->uart.rx_buf_len,
                   size, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), size);
    bus->uart.rx_buf_len += size;
}

int uart_tx(struct bus *bus, const void *buf, unsigned int buf_len)
{
    uint8_t hdr[4], fcs[2];
    const struct iovec iov[] = {
        { .iov_base = hdr,         .iov_len = sizeof(hdr) },
        { .iov_base = (void *)buf, .iov_len = buf_len     },
        { .iov_base = fcs,         .iov_len = sizeof(fcs) },
    };
    ssize_t ret;

    BUG_ON(buf_len > FIELD_MAX(UART_HDR_LEN_MASK));
    write_le16(hdr,     buf_len);
    write_le16(hdr + 2, crc16(CRC_INIT_HCS, hdr, 2));
    write_le16(fcs,     crc16(CRC_INIT_FCS, buf, buf_len));

    ret = writev(bus->fd, iov, ARRAY_SIZE(iov));
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    if (ret != sizeof(hdr) + buf_len + sizeof(fcs))
        FATAL(2 ,"%s: write: Short write", __func__);

    TRACE(TR_BUS, "bus tx: %s %s %02x %02x (%zd bytes)",
          tr_bytes(hdr, sizeof(hdr), NULL, 128, DELIM_SPACE | ELLIPSIS_STAR),
          tr_bytes(buf, buf_len,     NULL, 128, DELIM_SPACE | ELLIPSIS_STAR),
          fcs[0], fcs[1], sizeof(hdr) + buf_len + sizeof(fcs));

    return ret;
}

int uart_rx(struct bus *bus, void *buf, unsigned int buf_len)
{
    struct iobuf_read iobuf = { };
    const uint8_t *hdr;
    uint16_t len, fcs;

    if (!bus->uart.data_ready)
        uart_read(bus);
    bus->uart.data_ready = false;
    iobuf.data      = bus->uart.rx_buf;
    iobuf.data_size = bus->uart.rx_buf_len;
    hdr = iobuf_pop_data_ptr(&iobuf, 4);
    if (iobuf.err)
        return 0;
    if (!crc_check(CRC_INIT_HCS, hdr, 2, read_le16(hdr + 2))) {
        memmove(bus->uart.rx_buf, bus->uart.rx_buf + 1, bus->uart.rx_buf_len - 1);
        bus->uart.rx_buf_len -= 1;
        bus->uart.data_ready = true;
        if (bus->uart.init_phase)
            TRACE(TR_DROP, "drop %-9s: bad hcs", "uart");
        else
            FATAL(3, "%s: bad hcs", __func__);
        return 0;
    }
    len = FIELD_GET(UART_HDR_LEN_MASK, read_le16(hdr));
    BUG_ON(buf_len < len);
    iobuf_pop_data(&iobuf, buf, len);
    fcs = iobuf_pop_le16(&iobuf);
    if (iobuf.err)
        return 0; // Frame not fully received
    bus->uart.data_ready = true;
    if (!crc_check(CRC_INIT_FCS, buf, len, fcs)) {
        memmove(bus->uart.rx_buf, bus->uart.rx_buf + 1, bus->uart.rx_buf_len - 1);
        bus->uart.rx_buf_len -= 1;
        if (bus->uart.init_phase)
            TRACE(TR_DROP, "drop %-9s: bad fcs", "uart");
        else
            FATAL(3, "%s: bad fcs", __func__);
        return 0;
    }
    memmove(bus->uart.rx_buf, iobuf_ptr(&iobuf), iobuf_remaining_size(&iobuf));
    bus->uart.rx_buf_len = iobuf_remaining_size(&iobuf);
    return len;
}

static int uart_legacy_tx_append(uint8_t *buf, uint8_t byte)
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

static size_t uart_legacy_encode_hdlc(uint8_t *out, const uint8_t *in, size_t in_len, uint16_t crc)
{
    uint8_t crc_bytes[2];
    int frame_len;

    frame_len = 0;
    for (int i = 0; i < in_len; i++)
        frame_len += uart_legacy_tx_append(out + frame_len, in[i]);
    write_le16(crc_bytes, crc);
    frame_len += uart_legacy_tx_append(out + frame_len, crc_bytes[0]);
    frame_len += uart_legacy_tx_append(out + frame_len, crc_bytes[1]);
    out[frame_len++] = 0x7E;
    return frame_len;
}

int uart_legacy_tx(struct bus *bus, const void *buf, unsigned int buf_len)
{
    uint16_t crc = crc16(CRC_INIT_LEGACY, buf, buf_len) ^ CRC_XOROUT_LEGACY;
    uint8_t *frame = xalloc(buf_len * 2 + 3);
    int frame_len;
    int ret;

    frame_len = uart_legacy_encode_hdlc(frame, buf, buf_len, crc);
    TRACE(TR_BUS, "bus tx: %s (%d bytes)",
          tr_bytes(frame, frame_len, NULL, 128, DELIM_SPACE | ELLIPSIS_STAR), frame_len);
    ret = write(bus->fd, frame, frame_len);
    BUG_ON(ret != frame_len, "write: %m");
    free(frame);

    return frame_len;
}

/*
 * Returns the next HDLC frame if available, terminator included.
 */
static size_t uart_legacy_rx_hdlc(struct bus *bus, uint8_t *buf, size_t buf_len)
{
    int frame_start, frame_len;
    int i;

    if (!bus->uart.data_ready)
        uart_read(bus);

    i = 0;
    while (bus->uart.rx_buf[i] == 0x7E && i < bus->uart.rx_buf_len)
        i++;
    frame_start = i;
    while (bus->uart.rx_buf[i] != 0x7E && i < bus->uart.rx_buf_len)
        i++;
    frame_len = i - frame_start + 1;
    if (bus->uart.init_phase && i >= bus->uart.rx_buf_len)
        bus->uart.data_ready = false;
    BUG_ON(bus->uart.data_ready && i >= bus->uart.rx_buf_len);
    if (i >= bus->uart.rx_buf_len)
        return 0;

    BUG_ON(buf_len < frame_len);
    memcpy(buf, bus->uart.rx_buf + frame_start, frame_len);

    while (bus->uart.rx_buf[i] == 0x7E && i < bus->uart.rx_buf_len)
        i++;
    memmove(bus->uart.rx_buf, bus->uart.rx_buf + i, bus->uart.rx_buf_len - i);
    bus->uart.rx_buf_len -= i;

    i = 0;
    bus->uart.data_ready = false;
    while (i < bus->uart.rx_buf_len) {
        if (bus->uart.rx_buf[i] == 0x7E) {
            bus->uart.data_ready = true;
            break;
        }
        i++;
    }

    return frame_len;
}

static size_t uart_legacy_decode_hdlc(uint8_t *out, size_t out_len,
                                      const uint8_t *in, size_t in_len,
                                      bool inhibit_crc_warning)
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
        if (!crc_check(CRC_INIT_LEGACY, out, frame_len,
                       read_le16(out + frame_len) ^ CRC_XOROUT_LEGACY)) {
            if (!inhibit_crc_warning)
                WARN("bad crc, frame dropped");
            return 0;
        }
    }
    return frame_len;
}

int uart_legacy_rx(struct bus *bus, void *buf, unsigned int buf_len)
{
    uint8_t frame[4096];
    size_t frame_len;

    frame_len = uart_legacy_rx_hdlc(bus, frame, sizeof(frame));
    if (!frame_len)
        return 0;
    frame_len = uart_legacy_decode_hdlc(buf, buf_len, frame, frame_len, bus->uart.init_phase);
    return frame_len;
}

bool uart_detect_v2(struct bus *bus)
{
    struct pollfd pfd = {
        .fd = bus->fd,
        .events = POLLIN,
    };
    int ret;

    ret = poll(&pfd, 1, 10000);
    if (!ret)
        FATAL_ON(!bus->uart.rx_buf_len, 2, "RCP is not responding");

    for (;;) {
        ret = poll(&pfd, 1, 1000);
        FATAL_ON(ret < 0, 2, "%s poll : %m", __func__);
        if (!ret)
            return false;
        uart_read(bus);
        bus->uart.data_ready = true;
        for (int i = 0; i < bus->uart.rx_buf_len - 4; i++)
            if (crc_check(CRC_INIT_HCS, bus->uart.rx_buf + i, 2,
                          read_le16(bus->uart.rx_buf + i + 2)))
                return true;
    }
}

static inline int uart_txqlen(struct bus *bus)
{
    int ret, cnt;

    ret = ioctl(bus->fd, TIOCOUTQ, &cnt);
    FATAL_ON(ret < 0, 2, "ioctl TIOCOUTQ: %m");
    return cnt;
}

void uart_tx_flush(struct bus *bus)
{
    while (uart_txqlen(bus))
        usleep(1000);
}
