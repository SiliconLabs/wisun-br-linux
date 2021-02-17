/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#include "log.h"
#include "utils.h"
#include "wsbr.h"
#include "bus_uart.h"

static uint16_t crc16(const uint8_t *data, int len)
{
    uint8_t x;
    uint16_t crc = 0;

    while (len--) {
        x = crc >> 8 ^ *data++;
        x ^= x >> 4;
        crc <<= 8;
        crc ^= ((uint16_t)x) << 12;
        crc ^= ((uint16_t)x) << 5;
        crc ^= x;
    }
    return crc;
}

int wsbr_uart_open(const char *device, int bitrate, bool hardflow)
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
    };
    struct termios tty;
    int sym_bitrate = -1;
    int fd, i;

    fd = open(device, O_RDWR);
    if (fd < 0)
        FATAL(1, "%s: %m", device);

    if(tcgetattr(fd, &tty) == -1)
        FATAL(1, "tcgetattr: %m");
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
        FATAL(1, "tcsetattr: %m");
    return fd;
}

int wsbr_uart_tx(struct wsbr_ctxt *ctxt, const void *buf, unsigned int len)
{
    return write(ctxt->rcp_fd, buf, len);
}

int wsbr_uart_rx(struct wsbr_ctxt *ctxt, void *buf, unsigned int len)
{
    return read(ctxt->rcp_fd, buf, len);
}
