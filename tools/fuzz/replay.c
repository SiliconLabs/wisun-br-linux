#include <sys/eventfd.h>
#include <unistd.h>

#include "app_wsbrd/timers.h"
#include "app_wsbrd/wsbr.h"
#include "tools/fuzz/wsbrd_fuzz.h"
#include "common/log.h"
#include "common/os_types.h"
#include "common/spinel_buffer.h"

ssize_t __real_write(int fd, const void *buf, size_t count);

void __real_wsbr_common_timer_init(struct wsbr_ctxt *ctxt);
void __wrap_wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    if (g_fuzz_ctxt.replay_count) {
        ctxt->timerfd = eventfd(0, EFD_NONBLOCK);
        FATAL_ON(ctxt->timerfd < 0, 2, "eventfd: %m");
    } else {
        __real_wsbr_common_timer_init(ctxt);
    }
}

void fuzz_trigger_timer()
{
    uint64_t val = 1;
    int ret;

    ret = __real_write(g_ctxt.timerfd, &val, 8);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < 8, 2, "%s: write: Short write", __func__);
}

void fuzz_spinel_replay_timers(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    FATAL_ON(!fuzz_is_main_loop(&g_ctxt), 1, "timer command received during RCP init");
    FATAL_ON(!g_fuzz_ctxt.replay_count, 1, "timer command received while replay is disabled");
    g_fuzz_ctxt.timer_counter = spinel_pop_u16(buf);
    if (g_fuzz_ctxt.timer_counter)
        fuzz_trigger_timer();
}

int __real_uart_open(const char *device, int bitrate, bool hardflow);
int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    if (g_fuzz_ctxt.replay_count)
        return g_fuzz_ctxt.replay_fds[g_fuzz_ctxt.replay_i++];
    else
        return __real_uart_open(device, bitrate, hardflow);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (fd == g_ctxt.os_ctxt->data_fd && g_fuzz_ctxt.replay_count)
        return count;

    if (fd == g_ctxt.tun_fd && g_fuzz_ctxt.replay_count)
        return count;

    return __real_write(fd, buf, count);
}
