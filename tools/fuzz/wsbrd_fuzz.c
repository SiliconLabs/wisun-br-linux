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
#include <netinet/in.h>
#include "stack/source/core/netaddr_types.h"
#include "stack/source/core/timers.h"
#include "app_wsbrd/libwsbrd.h"
#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/tun.h"
#include "tools/fuzz/capture.h"
#include "tools/fuzz/commandline.h"
#include "tools/fuzz/interfaces.h"
#include "tools/fuzz/replay.h"
#include "common/bus_uart.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/os_types.h"
#include "common/iobuf.h"
#include "common/spinel.h"
#include "common/hif.h"
#include "common/version.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "capture.h"
#include "interfaces.h"

struct fuzz_ctxt g_fuzz_ctxt = {
    .wsbrd = &g_ctxt,
    .mbedtls_time = 1700000000, // Tue Nov 14 23:13:20 CET 2023
    .socket_pipes = {
        { -1, -1 },
        { -1, -1 },
        { -1, -1 },
        { -1, -1 },
        { -1, -1 },
        { -1, -1 },
    },
    .capture_fd      = -1,
    .capture_init_fd = -1,
};

// Fuzzing command can only be processed from the main loop.
bool fuzz_is_main_loop(struct wsbr_ctxt *ctxt)
{
    if (!(ctxt->rcp.init_state & RCP_HAS_RESET))
        return false;
    if (!(ctxt->rcp.init_state & RCP_HAS_HWADDR))
        return false;
    if (!version_older_than(ctxt->rcp.version_api, 0, 16, 0) && !(ctxt->rcp.init_state & RCP_HAS_RF_CONFIG_LIST))
        return false;
    return true;
}

void __real_parse_commandline(struct wsbrd_conf *config, int argc, char *argv[], void (*print_help)(FILE *stream));
void __wrap_parse_commandline(struct wsbrd_conf *config, int argc, char *argv[], void (*print_help)(FILE *stream))
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    __real_parse_commandline(config, argc, argv, print_help);

    if (ctxt->fuzzing_enabled)
        ctxt->wsbrd->config.storage_delete = true;
    if (ctxt->capture_fd >= 0 || ctxt->replay_count) {
        WARN_ON(!ctxt->wsbrd->config.storage_delete, "storage_delete set to false while using capture/replay");
        WARN_ON(!ctxt->wsbrd->config.tun_autoconf, "tun_autoconf set to false while using capture/replay");
    }
}

int __real_uart_legacy_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len);
int __wrap_uart_legacy_rx(struct os_ctxt *ctxt, void *buf, unsigned int buf_len)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;
    uint8_t frame[4096];
    size_t frame_len;

    if (fuzz_ctxt->replay_count && fuzz_ctxt->timer_counter)
        return 0;

    if (fuzz_ctxt->capture_fd < 0)
        return __real_uart_legacy_rx(ctxt, buf, buf_len);

    frame_len = uart_legacy_rx_hdlc(ctxt, frame, sizeof(frame));
    if (!frame_len)
        return 0;
    fuzz_capture_timers(fuzz_ctxt);
    fuzz_capture(fuzz_ctxt, frame, frame_len);
    frame_len = uart_legacy_decode_hdlc(buf, buf_len, frame, frame_len, ctxt->uart_init_phase);
    return frame_len;
}

bool __real_crc_check(uint16_t init, const uint8_t *data, int len, uint16_t expected_crc);
bool __wrap_crc_check(uint16_t init, const uint8_t *data, int len, uint16_t expected_crc)
{
    if (g_fuzz_ctxt.fuzzing_enabled)
        return true;
    else
        return __real_crc_check(init, data, len, expected_crc);
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

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    ssize_t size = __real_read(fd, buf, count);
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    if (fd == ctxt->wsbrd->timerfd) {
        if (ctxt->capture_fd >= 0) {
            ctxt->timer_counter++;
        } else if (ctxt->replay_count) {
            ctxt->timer_counter--;
            if (ctxt->timer_counter)
                fuzz_trigger_timer(ctxt);
        }
    } else if (fd == ctxt->wsbrd->tun_fd && ctxt->capture_fd >= 0) {
        fuzz_capture_timers(ctxt);
        fuzz_capture_interface(ctxt, IF_TUN, in6addr_any.s6_addr, in6addr_any.s6_addr, 0, buf, size);
    } else if (fd == ctxt->wsbrd->os_ctxt->data_fd && !size && ctxt->replay_i < ctxt->replay_count) {
        // Read from the next replay file
        ctxt->wsbrd->os_ctxt->data_fd = ctxt->replay_fds[ctxt->replay_i++];
        return __real_read(ctxt->wsbrd->os_ctxt->data_fd, buf, count);
    }

    return size;
}

int wsbr_fuzz_main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;
    int i;

    for (i = 0; rcp_legacy_rx_cmds[i].cmd != (uint32_t)-1; i++) {
        if (rcp_legacy_rx_cmds[i].cmd == SPINEL_CMD_REPLAY_TIMERS)
            rcp_legacy_rx_cmds[i].fn = fuzz_spinel_replay_timers;
        if (rcp_legacy_rx_cmds[i].cmd == SPINEL_CMD_REPLAY_INTERFACE)
            rcp_legacy_rx_cmds[i].fn = fuzz_spinel_replay_interface;
    }
    argc = fuzz_parse_commandline(ctxt, argv);
    return wsbr_main(argc, argv);
}
