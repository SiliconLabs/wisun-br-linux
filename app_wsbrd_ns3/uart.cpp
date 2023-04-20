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
#include <sys/types.h>

#include <ns3/libwsbrd-ns3.hpp>

extern "C" {
#include "app_wsbrd/wsbr.h"
#include "common/os_types.h"
}

ns3::Callback<int, const void *, size_t> g_uart_cb = ns3::MakeNullCallback<int, const void *, size_t>();

int g_uart_fd = -1;

extern "C" int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    return g_uart_fd;
}

extern "C" ssize_t __real_write(int fd, const void *buf, size_t count);
extern "C" ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (fd == g_ctxt.os_ctxt->data_fd)
        return g_uart_cb(buf, count);
    else
        return __real_write(fd, buf, count);
}
