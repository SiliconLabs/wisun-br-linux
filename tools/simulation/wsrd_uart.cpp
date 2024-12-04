/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <sys/uio.h>
#include <stdint.h>
#include <string.h>

#include <ns3/sl-wisun-linux.hpp>

extern "C" {
#include "app_wsrd/app/wsrd.h"
#include "common/log.h"
#include "common/bus.h"
#include "common/memutils.h"
}

ns3::Callback<int, const void *, size_t> g_uart_cb = ns3::MakeNullCallback<int, const void *, size_t>();

int g_uart_fd = -1;

extern "C" int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    return g_uart_fd;
}

extern "C" ssize_t __real_writev(int fd, const struct iovec *iov, int iovcnt);
extern "C" ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
    uint8_t *buf;
    ssize_t ret;

    if (fd != g_wsrd.ws.rcp.bus.fd)
        return __real_writev(fd, iov, iovcnt);

    BUG_ON(iovcnt != 3); // hdr | cmd + body | fcs
    // TODO: change the signature of g_uart_cb to accept iovec so rebuilding
    // the packet is not needed here.
    buf = (uint8_t *)xalloc(iov[0].iov_len + iov[1].iov_len + iov[2].iov_len);
    memcpy(buf,                                   iov[0].iov_base, iov[0].iov_len);
    memcpy(buf + iov[0].iov_len,                  iov[1].iov_base, iov[1].iov_len);
    memcpy(buf + iov[0].iov_len + iov[1].iov_len, iov[2].iov_base, iov[2].iov_len);
    ret = g_uart_cb(buf, iov[0].iov_len + iov[1].iov_len + iov[2].iov_len);
    free(buf);
    return ret;
}
