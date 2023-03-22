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
#include <sys/eventfd.h>
#include <unistd.h>

#include "stack/source/core/ns_address_internal.h"
#include "stack/timers.h"
#include "app_wsbrd/libwsbrd.h"
#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/tun.h"
#include "common/bus_uart.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/os_types.h"
#include "common/iobuf.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "common/version.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "capture.h"
#include "interfaces.h"

struct fuzz_ctxt g_fuzz_ctxt = {
    .mbedtls_time = 1700000000, // Tue Nov 14 23:13:20 CET 2023
    .socket_pipes = {
        { -1, -1 },
        { -1, -1 },
        { -1, -1 },
        { -1, -1 },
    },
};

// Fuzzing command can only be processed from the main loop.
bool fuzz_is_main_loop(struct wsbr_ctxt *ctxt)
{
    if (!(ctxt->rcp.init_state & RCP_HAS_RESET))
        return false;
    if (!(ctxt->rcp.init_state & RCP_HAS_HWADDR))
        return false;
    if (!version_older_than(ctxt->rcp.version_api, 0, 11, 0) && !(ctxt->rcp.init_state & RCP_HAS_RF_CONFIG_LIST))
        return false;
    return true;
}

int __real_uart_open(const char *device, int bitrate, bool hardflow);
int __wrap_uart_open(const char *device, int bitrate, bool hardflow)
{
    // This function is the first being executed after parse_commandline in
    // wsbr_main. Thus some checks can be put here.
    if (g_fuzz_ctxt.fuzzing_enabled)
        g_ctxt.config.storage_delete = true;
    if (g_fuzz_ctxt.capture_enabled || g_fuzz_ctxt.replay_count) {
        WARN_ON(!g_ctxt.config.storage_delete, "storage_delete set to false while using capture/replay");
        WARN_ON(!g_ctxt.config.tun_autoconf, "tun_autoconf set to false while using capture/replay");
    }

    if (g_fuzz_ctxt.replay_count)
        return g_fuzz_ctxt.replay_fds[g_fuzz_ctxt.replay_i++];
    else
        return __real_uart_open(device, bitrate, hardflow);
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
    frame_len = uart_decode_hdlc(buf, buf_len, frame, frame_len, ctxt->uart_inhibit_crc_warning);
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

bool __real_spinel_prop_is_valid(struct iobuf_read *buf, int prop);
bool __wrap_spinel_prop_is_valid(struct iobuf_read *buf, int prop)
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
        fuzz_capture_interface(ctxt, IF_TUN, ADDR_UNSPECIFIED, 0, buf, count);
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
    int i;

    for (i = 0; rx_cmds->cmd != (uint32_t)-1; i++) {
        if (rx_cmds->cmd == SPINEL_CMD_REPLAY_TIMERS)
            rx_cmds->fn = fuzz_spinel_replay_timers;
        if (rx_cmds->cmd == SPINEL_CMD_REPLAY_INTERFACE)
            rx_cmds->fn = fuzz_spinel_replay_interface;
    }
    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
