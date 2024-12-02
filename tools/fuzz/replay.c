/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <sys/eventfd.h>
#include <unistd.h>

#include "app_wsbrd/app/timers.h"
#include "app_wsbrd/app/wsbrd.h"
#include "app_wsbrd/net/timers.h"
#include "tools/fuzz/wsbrd_fuzz.h"
#include "common/log.h"
#include "common/bus.h"
#include "common/hif.h"

ssize_t __real_write(int fd, const void *buf, size_t count);

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

    ret = __real_write(timer_fd(), &val, 8);
    FATAL_ON(ret < 0, 2, "%s: write: %m", __func__);
    FATAL_ON(ret < 8, 2, "%s: write: Short write", __func__);
}

void fuzz_ind_replay_timers(struct rcp *rcp, struct iobuf_read *buf)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct timer_entry *timer;

    BUG_ON(rcp != &ctxt->wsbrd->rcp);
    FATAL_ON(!ctxt->replay_count, 1, "timer command received while replay is disabled");

    ctxt->target_time_ms = hif_pop_u64(buf);
    timer = timer_next();
    if (timer && timer->expire_ms < ctxt->target_time_ms)
        fuzz_trigger_timer(ctxt);
    else
        ctxt->replay_time_ms = ctxt->target_time_ms;
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

    if (fd == ctxt->wsbrd->rcp.bus.fd && ctxt->replay_count)
        return count;

    if (fd == ctxt->wsbrd->tun.fd && ctxt->replay_count)
        return count;

    return __real_write(fd, buf, count);
}

ssize_t __real_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t __wrap_writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    BUG_ON(iovcnt != 3); // hdr | cmd + body | fcs
    if (fd == ctxt->wsbrd->rcp.bus.fd && ctxt->replay_count)
        return iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
    else
        return __real_writev(fd, iov, iovcnt);
}

int __real_timerfd_create(int clockid, int flags);
int __wrap_timerfd_create(int clockid, int flags)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count)
        return eventfd(0, 0);
    else
        return __real_timerfd_create(clockid, flags);
}

int __real_timerfd_settime(int fd, int flags, const struct itimerspec *new, struct itimerspec *old);
int __wrap_timerfd_settime(int fd, int flags, const struct itimerspec *new, struct itimerspec *old)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (ctxt->replay_count)
        return 0;
    else
        return __real_timerfd_settime(fd, flags, new, old);
}

ssize_t __real_read(int fd, void *buf, size_t buf_len);
ssize_t __wrap_read(int fd, void *buf, size_t buf_len)
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    struct timer_entry *timer;
    ssize_t ret;

    ret = __real_read(fd, buf, buf_len);
    if (ret < 0 || !ctxt->replay_count)
        return ret;

    if (fd == timer_fd()) {
        timer = timer_next();
        if (timer && timer->expire_ms < ctxt->target_time_ms) {
            fuzz_trigger_timer(ctxt);
            ctxt->replay_time_ms = timer->expire_ms;
        } else {
            ctxt->replay_time_ms = ctxt->target_time_ms;
        }
    } else if (fd == ctxt->wsbrd->rcp.bus.fd && !ret && ctxt->replay_i < ctxt->replay_count) {
        // Read from the next replay file
        ctxt->wsbrd->rcp.bus.fd = ctxt->replay_fds[ctxt->replay_i++];
        ret = __real_read(ctxt->wsbrd->rcp.bus.fd, buf, buf_len);
    }
    return ret;
}
