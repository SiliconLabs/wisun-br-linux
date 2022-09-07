#include <sys/eventfd.h>
#include <unistd.h>

#include "stack-scheduler/source/timer_sys.h"
#include "stack/source/service_libs/utils/ns_file_system.h"
#include "app_wsbrd/libwsbrd.h"
#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/tun.h"
#include "common/bus_uart.h"
#include "common/log.h"
#include "common/os_types.h"
#include "common/spinel_buffer.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "capture.h"
#include "interfaces.h"

struct fuzz_ctxt g_fuzz_ctxt = {
    .mbedtls_time = 1700000000, // Tue Nov 14 23:13:20 CET 2023
};

int __real_uart_open(const char *device, int bitrate, bool hardflow);
int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    // This function is the first being executed ater parse_commandline in
    // wsbr_main. Thus some checks can be put here.
    if (ns_file_system_get_root_path()) {
        if (g_fuzz_ctxt.fuzzing_enabled)
            ns_file_system_set_root_path(NULL);
        else if (g_fuzz_ctxt.capture_enabled || g_fuzz_ctxt.replay_count)
            WARN("using storage while in cature/replay mode");
    }

    if (g_fuzz_ctxt.replay_count)
        return g_fuzz_ctxt.replay_fds[g_fuzz_ctxt.replay_i++];
    else
        return __real_uart_open(device, bitrate, hardflow);
}

void __real_wsbr_tun_init(struct wsbr_ctxt *ctxt);
void __wrap_wsbr_tun_init(struct wsbr_ctxt *ctxt)
{
    if (g_fuzz_ctxt.replay_count)
        ctxt->tun_fd = g_fuzz_ctxt.tun_pipe[0];
    else
        __real_wsbr_tun_init(ctxt);
}

int __real_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len);
int __wrap_uart_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;
    uint8_t frame[4096];
    size_t frame_len;

    if (fuzz_ctxt->replay_count && fuzz_ctxt->timer_counter)
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

bool __real_crc_check(const uint8_t *data, int len, uint16_t expected_crc);
bool __wrap_crc_check(const uint8_t *data, int len, uint16_t expected_crc)
{
    if (g_fuzz_ctxt.fuzzing_enabled)
        return true;
    else
        return __real_crc_check(data, len, expected_crc);
}

bool __real_spinel_prop_is_valid(struct spinel_buffer *buf, int prop);
bool __wrap_spinel_prop_is_valid(struct spinel_buffer *buf, int prop)
{
    if (!g_fuzz_ctxt.fuzzing_enabled)
        return __real_spinel_prop_is_valid(buf, prop);
    if (buf->err) {
        ERROR("spinel error (offset %d): %s", buf->cnt, spinel_prop_str(prop));
        return false;
    }
    return true;
}

void __real_wsbr_common_timer_init(struct wsbr_ctxt *ctxt);
void __wrap_wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    if (g_fuzz_ctxt.replay_count) {
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
    FATAL_ON(!(g_ctxt.rcp_init_state & RCP_INIT_DONE), 1, "timer command received during RCP init");
    FATAL_ON(!g_fuzz_ctxt.replay_count, 1, "timer command received while replay is disabled");
    g_fuzz_ctxt.timer_counter = spinel_pop_u16(buf);
    if (g_fuzz_ctxt.timer_counter)
        fuzz_trigger_timer();
}

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    ssize_t size = __real_read(fd, buf, count);
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (fd == g_ctxt.timerfd) {
        if (g_fuzz_ctxt.capture_enabled) {
            g_fuzz_ctxt.timer_counter++;
        } else if (g_fuzz_ctxt.replay_count) {
            g_fuzz_ctxt.timer_counter--;
            if (g_fuzz_ctxt.timer_counter)
                fuzz_trigger_timer();
        }
    } else if (fd == g_ctxt.tun_fd && ctxt->capture_enabled) {
        fuzz_capture_timers(ctxt);
        fuzz_capture_interface(ctxt, IF_TUN, buf, count);
    } else if (fd == g_ctxt.os_ctxt->data_fd && !size && ctxt->replay_i < ctxt->replay_count) {
        // Read from the next replay file
        g_ctxt.os_ctxt->data_fd = ctxt->replay_fds[ctxt->replay_i++];
        return __real_read(g_ctxt.os_ctxt->data_fd, buf, count);
    }

    return size;
}

ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    // os_ctxt is set right at the beginning of main, but AFL calls
    // write before main so the pointer needs to be checked
    if (g_ctxt.os_ctxt && fd == g_ctxt.os_ctxt->data_fd && g_fuzz_ctxt.replay_count)
        return count;

    if (fd == g_ctxt.tun_fd && g_fuzz_ctxt.replay_count)
        return count;

    return __real_write(fd, buf, count);
}

int main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
