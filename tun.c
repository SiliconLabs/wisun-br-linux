/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "tun.h"
#include "log.h"

int wsbr_tun_open(char *devname)
{
    struct ifreq ifr = {
        .ifr_flags = IFF_TUN,
    };
    int fd;

    if (devname && *devname)
        strcpy(ifr.ifr_name, devname);
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        FATAL(2, "tun open: %m");
    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        FATAL(2, "tun ioctl: %m");
    if (devname)
        strcpy(devname, ifr.ifr_name);
    return fd;
}

