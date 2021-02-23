/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

#include "spinel.h"
#include "log.h"
#include "utils.h"
#include "wsbr.h"
#include "bus_spi.h"

#define HDR_RST  0x01
#define HDR_CRC  0x02
#define HDR_CCF  0x04
#define HDR_PAT  0xC0

static void simple_write(const char *filename, const char *data)
{
    int fd, ret;

    fd = open(filename, O_WRONLY);
    if (fd < 0)
        FATAL(1, "%s: %m", filename);
    ret = write(fd, data, strlen(data));
    if (ret < 0)
        FATAL(1, "%s: %m", filename);
    close(fd);
}

int wsbr_gpio_open(const char *device, bool use_fall_edge)
{
    char *end_ptr;
    char buf[256];
    int fd;

    strtol(device, &end_ptr, 10);
    if (*end_ptr) {
        fd = open(device, O_RDONLY);
        if (fd < 0)
            FATAL(1, "%s: %m", buf);
    } else {
        simple_write("/sys/class/gpio/export", device);
        snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%s/direction", device);
        simple_write(buf, "in");
        snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%s/edge", device);
        simple_write(buf, use_fall_edge ? "falling" : "rising");
        snprintf(buf, sizeof(buf), "/sys/class/gpio/gpio%s/value", device);
        fd = open(buf, O_RDONLY);
        if (fd < 0)
            FATAL(1, "%s: %m", buf);
    }
    return fd;
}

int wsbr_spi_open(const char *device, uint32_t frequency, uint8_t mode)
{
    int fd, ret;

    fd = open(device, O_RDWR);
    if (fd < 0)
        FATAL(1, "%s: %m", device);
    ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
    if (ret < 0)
        FATAL(1, "SPI_IOC_WR_MODE: %m");
    ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &frequency);
    if (ret < 0)
        FATAL(1, "SPI_IOC_WR_MAX_SPEED_HZ: %m");
    return fd;
}

int wsbr_spi_tx(struct wsbr_ctxt *ctxt, const void *buf, unsigned int len)
{
    uint8_t *frame = malloc(len + 5);
    uint8_t hdr = FIELD_PREP(HDR_PAT, 0x2);
    int frame_len;

    if (ctxt->rcp_spi_recv_window < len + 5) {
        WARN("receive buffer is full");
        errno = ENOSPC;
        return -1;
    }
    frame_len = spinel_datatype_pack(frame, len + 5, "CSSD", &hdr, UINT16_MAX, len, buf, len);
    BUG_ON(frame_len != len + 5);
    if (write(ctxt->rcp_fd, buf, frame_len) != frame_len)
        BUG("write: %m");
    free(frame);
    return len;
}

int wsbr_spi_rx(struct wsbr_ctxt *ctxt, void *buf, unsigned int len)
{
    int data_len;
    uint8_t tmp[5];
    uint8_t hdr;

    lseek(ctxt->rcp_trig_fd, 0, SEEK_SET);
    if (read(ctxt->rcp_trig_fd, tmp, sizeof(tmp)) != 2)
        WARN("unexpected GPIO value");
    read(ctxt->rcp_fd, tmp, sizeof(tmp));
    spinel_datatype_unpack(tmp, sizeof(tmp), "CSS", &hdr, &ctxt->rcp_spi_recv_window, &data_len);
    if (FIELD_GET(HDR_CRC, hdr))
        data_len += 2;
    if (len < data_len)
        BUG("buffer too small");
    if (read(ctxt->rcp_fd, buf, data_len) != data_len)
        BUG("read: %m");
    if (FIELD_GET(HDR_CRC, hdr))
        data_len -= 2;
    if (FIELD_GET(HDR_RST, hdr))
        WARN("device reset");
    if (FIELD_GET(HDR_CCF, hdr))
        WARN("CRC check failure");
    if (FIELD_GET(HDR_PAT, hdr) != 0x2) {
        WARN("bad pattern, frame dropped");
        return 0;
    }
    return data_len;
}
