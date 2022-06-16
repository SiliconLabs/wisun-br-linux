#include <sys/eventfd.h>
#include <unistd.h>

#include "stack-scheduler/source/timer_sys.h"
#include "app_wsbrd/libwsbrd.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/tun.h"
#include "common/bus_uart.h"
#include "common/log.h"
#include "common/os_types.h"
#include "common/spinel_buffer.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "capture.h"

struct fuzz_ctxt g_fuzz_ctxt = {
    .mbedtls_time = 1700000000, // Tue Nov 14 23:13:20 CET 2023
};

int __real_uart_open(const char *device, int bitrate, bool hardflow);
int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    if (g_fuzz_ctxt.replay_enabled)
        return g_fuzz_ctxt.uart_fd;
    else
        return __real_uart_open(device, bitrate, hardflow);
}

void __real_wsbr_tun_init(struct wsbr_ctxt *ctxt);
void __wrap_wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    if (g_fuzz_ctxt.replay_enabled) {
        ctxt->tun_fd = g_fuzz_ctxt.tun_pipe[0];
        wsbr_tun_stack_init(ctxt);
    } else {
        __real_wsbr_tun_init(ctxt);
    }
}

int __real_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len);
int __wrap_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;
    uint8_t frame[4096];
    size_t frame_len;

    if (fuzz_ctxt->replay_enabled && fuzz_ctxt->timer_counter)
        return 0;

    if (!fuzz_ctxt->capture_enabled)
        return __real_uart_rx(ctxt, buf, buf_len);

    frame_len = uart_rx_hdlc(ctxt, frame, sizeof(frame));
    if (!frame_len)
        return 0;
    if (fuzz_ctxt->capture_enabled) {
        fuzz_capture_timers(fuzz_ctxt);
        fuzz_capture(fuzz_ctxt, frame, frame_len);
    }
    frame_len = uart_decode_hdlc(buf, buf_len, frame, frame_len);
    return frame_len;
}

void __real_wsbr_common_timer_init(struct wsbr_ctxt *ctxt);
void __wrap_wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    if (g_fuzz_ctxt.replay_enabled) {
        timer_sys_init();
        g_ctxt.timerfd = eventfd(0, EFD_NONBLOCK);
        FATAL_ON(g_ctxt.timerfd < 0, 2, "eventfd: %m");
    } else {
        __real_wsbr_common_timer_init(ctxt);
    }
}

static void fuzz_trigger_timer()
{
    uint64_t val = 1;
    int ret;

    ret = write(g_ctxt.timerfd, &val, 8);
    FATAL_ON(ret < 0, 2, "write: %m");
}

void __wrap_wsbr_spinel_replay_timers(struct spinel_buffer *buf)
{
    FATAL_ON(!g_fuzz_ctxt.replay_enabled, 1, "timer command received while replay is disabled");
    g_fuzz_ctxt.timer_counter = spinel_pop_u16(buf);
    if (g_fuzz_ctxt.timer_counter)
        fuzz_trigger_timer();
}

void __wrap_wsbr_spinel_replay_tun(struct spinel_buffer *buf)
{
    uint8_t *data;
    size_t size;
    int ret;

    FATAL_ON(!g_fuzz_ctxt.replay_enabled, 1, "TUN command received while replay is disabled");
    size = spinel_pop_data_ptr(buf, &data);
    ret = write(g_fuzz_ctxt.tun_pipe[1], data, size);
    FATAL_ON(ret < 0, 2, "write: %m");
    FATAL_ON(ret < size, 2, "write: Short write");
}

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    ssize_t ret = __real_read(fd, buf, count);
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (fd == g_ctxt.timerfd) {
        if (g_fuzz_ctxt.capture_enabled) {
            g_fuzz_ctxt.timer_counter++;
        } else if (g_fuzz_ctxt.replay_enabled) {
            g_fuzz_ctxt.timer_counter--;
            if (g_fuzz_ctxt.timer_counter)
                fuzz_trigger_timer();
        }
    } else if (fd == g_ctxt.tun_fd && ctxt->capture_enabled) {
        fuzz_capture_timers(ctxt);
        fuzz_capture_tun(ctxt, buf, count);
    }

    return ret;
}

ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (fd == g_ctxt.os_ctxt->data_fd && g_fuzz_ctxt.replay_enabled)
        return count;

    if (fd == g_ctxt.tun_fd && g_fuzz_ctxt.replay_enabled)
        return count;

    return __real_write(fd, buf, count);
}

int main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
