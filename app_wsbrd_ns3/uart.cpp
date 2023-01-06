#include <sys/types.h>

extern "C" {
#include "app_wsbrd/wsbr.h"
#include "common/os_types.h"
}
#include "wsbrd_ns3.hpp"

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
