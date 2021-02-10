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

#include "log.h"
#include "wsbr.h"
#include "bus_spi.h"

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
    return write(ctxt->rcp_fd, buf, len);
}

int wsbr_spi_rx(struct wsbr_ctxt *ctxt, void *buf, unsigned int len)
{
    char trig_val[3];

    lseek(ctxt->rcp_trig_fd, 0, SEEK_SET);
    if (read(ctxt->rcp_trig_fd, trig_val, sizeof(buf)) != 2)
        WARN("unexpected GPIO value");
    return read(ctxt->rcp_fd, buf, len);
}
