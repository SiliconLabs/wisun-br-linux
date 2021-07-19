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
#include "spinel_buffer.h"
#include "log.h"
#include "utils.h"
#include "os_types.h"
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

int gpio_open(const char *device, bool use_fall_edge)
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

int spi_open(const char *device, uint32_t frequency, uint8_t mode)
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

int spi_tx(struct os_ctxt *ctxt, const void *data, unsigned int len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(len + 5);

    spinel_push_u8(buf, FIELD_PREP(HDR_PAT, 0x2));
    spinel_push_u16(buf, UINT16_MAX);
    spinel_push_data(buf, data, len);
    if (write(ctxt->data_fd, buf->frame, buf->cnt) != buf->cnt)
        BUG("write: %m");
    return len;
}

int spi_rx(struct os_ctxt *ctxt, void *data, unsigned int max_len)
{
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(5);
    uint8_t tmp[2];
    int data_len;
    uint8_t hdr;

    lseek(ctxt->trig_fd, 0, SEEK_SET);
    if (read(ctxt->trig_fd, tmp, sizeof(tmp)) != 2)
        WARN("unexpected GPIO value");
    read(ctxt->data_fd, buf->frame, buf->len);
    hdr = spinel_pop_u8(buf);
    ctxt->spi_recv_window = spinel_pop_u16(buf);
    data_len = spinel_pop_u16(buf);
    if (FIELD_GET(HDR_CRC, hdr))
        data_len += 2;
    if (max_len < data_len)
        BUG("buffer too small");
    if (read(ctxt->data_fd, data, data_len) != data_len)
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
