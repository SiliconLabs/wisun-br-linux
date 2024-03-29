#include <sys/eventfd.h>
#include <unistd.h>

#include "app_wsbrd/timers.h"
#include "app_wsbrd/wsbr.h"
#include "stack/source/core/timers.h"
#include "tools/fuzz/wsbrd_fuzz.h"
#include "common/log.h"
#include "common/os_types.h"
#include "common/hif.h"

ssize_t __real_write(int fd, const void *buf, size_t count);

void __real_wsbr_common_timer_init(struct wsbr_ctxt *wsbrd);
void __wrap_wsbr_common_timer_init(struct wsbr_ctxt *wsbrd)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    BUG_ON(ctxt->wsbrd != wsbrd);
    if (ctxt->replay_count) {
        wsbrd->timerfd = eventfd(0, EFD_NONBLOCK);
        FATAL_ON(wsbrd->timerfd < 0, 2, "eventfd: %m");
    } else {
        __real_wsbr_common_timer_init(wsbrd);
    }
}

int __real_clock_gettime(clockid_t clockid, struct timespec *tp);
int __wrap_clock_gettime(clockid_t clockid, struct timespec *tp)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (!ctxt->replay_count)
        return __real_clock_gettime(clockid, tp);
    if (tp) {
        tp->tv_sec  = ctxt->replay_time_ms / 1000;
        tp->tv_nsec = (ctxt->replay_time_ms % 1000) * 1000000;
    }
    return 0;
}

void fuzz_trigger_timer(struct fuzz_ctxt *ctxt)
{
    uint64_t val = 1;
    int ret;

    ctxt->replay_time_ms += WS_TIMER_GLOBAL_PERIOD_MS;
    ret = __real_write(ctxt->wsbrd->timerfd, &val, 8);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < 8, 2, "%s: write: Short write", __func__);
}

static void fuzz_replay_timers(struct fuzz_ctxt *ctxt, struct iobuf_read *buf)
{
    FATAL_ON(!fuzz_is_main_loop(ctxt->wsbrd), 1, "timer command received during RCP init");
    FATAL_ON(!ctxt->replay_count, 1, "timer command received while replay is disabled");
    ctxt->timer_counter = hif_pop_u16(buf);
    if (ctxt->timer_counter)
        fuzz_trigger_timer(ctxt);
}

void fuzz_ind_replay_timers(struct rcp *rcp, struct iobuf_read *buf)
{
    fuzz_replay_timers(&g_fuzz_ctxt, buf);
}

void fuzz_spinel_replay_timers(struct wsbr_ctxt *ctxt, uint32_t prop, struct iobuf_read *buf)
{
    fuzz_replay_timers(&g_fuzz_ctxt, buf);
}

int __real_uart_open(const char *device, int bitrate, bool hardflow);
int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count)
        return ctxt->replay_fds[ctxt->replay_i++];
    else
        return __real_uart_open(device, bitrate, hardflow);
}

ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (fd == ctxt->wsbrd->os_ctxt->data_fd && ctxt->replay_count)
        return count;

    if (fd == ctxt->wsbrd->tun_fd && ctxt->replay_count)
        return count;

    return __real_write(fd, buf, count);
}

ssize_t __real_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    BUG_ON(iovcnt != 3); // hdr | cmd + body | fcs
    if (fd == ctxt->wsbrd->os_ctxt->data_fd && ctxt->replay_count)
        return iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
    else
        return __real_writev(fd, iov, iovcnt);
}
