#include "app_wsbrd/libwsbrd.h"
#include "app_wsbrd/wsbr.h"
#include "common/bus_uart.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "capture.h"

struct fuzz_ctxt g_fuzz_ctxt = {
    .mbedtls_time = 1700000000, // Tue Nov 14 23:13:20 CET 2023
};

int __real_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len);
int __wrap_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;
    uint8_t frame[4096];
    size_t frame_len;

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

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if (fd == g_ctxt.timerfd && g_fuzz_ctxt.capture_enabled)
        g_fuzz_ctxt.timer_counter++;

    return __real_read(fd, buf, count);
}

int main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
