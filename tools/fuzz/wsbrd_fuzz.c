/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include "app_wsbrd/net/netaddr_types.h"
#include "app_wsbrd/net/timers.h"
#include "app_wsbrd/app/rcp_api_legacy.h"
#include "app_wsbrd/app/libwsbrd.h"
#include "app_wsbrd/app/wsbr_mac.h"
#include "app_wsbrd/app/wsbrd.h"
#include "app_wsbrd/app/tun.h"
#include "tools/fuzz/commandline.h"
#include "tools/fuzz/interfaces.h"
#include "tools/fuzz/replay.h"
#include "common/bus_uart.h"
#include "common/capture.h"
#include "common/key_value_storage.h"
#include "common/log.h"
#include "common/bus.h"
#include "common/iobuf.h"
#include "common/spinel.h"
#include "common/hif.h"
#include "common/version.h"
#include "wsbrd_fuzz.h"
#include "commandline.h"
#include "interfaces.h"

struct fuzz_ctxt g_fuzz_ctxt = {
    .wsbrd = &g_ctxt,
    .mbedtls_time = 1700000000, // Tue Nov 14 23:13:20 CET 2023
};

void __real_parse_commandline(struct wsbrd_conf *config, int argc, char *argv[], void (*print_help)(FILE *stream));
void __wrap_parse_commandline(struct wsbrd_conf *config, int argc, char *argv[], void (*print_help)(FILE *stream))
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    __real_parse_commandline(config, argc, argv, print_help);

    if (ctxt->fuzzing_enabled)
        ctxt->wsbrd->config.storage_delete = true;
    if (ctxt->replay_count) {
        WARN_ON(!ctxt->wsbrd->config.storage_delete, "storage_delete set to false while using replay");
        WARN_ON(!ctxt->wsbrd->config.tun_autoconf, "tun_autoconf set to false while using replay");
    }
}

int __real_uart_rx(struct bus *bus, void *buf, unsigned int buf_len);
int __wrap_uart_rx(struct bus *bus, void *buf, unsigned int buf_len)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;

    if (fuzz_ctxt->replay_count && fuzz_ctxt->replay_time_ms < fuzz_ctxt->target_time_ms)
        return 0;
    else
        return __real_uart_rx(bus, buf, buf_len);
}

bool __real_crc_check(uint16_t init, const uint8_t *data, int len, uint16_t expected_crc);
bool __wrap_crc_check(uint16_t init, const uint8_t *data, int len, uint16_t expected_crc)
{
    struct fuzz_ctxt *fuzz_ctxt = &g_fuzz_ctxt;

    if (fuzz_ctxt->fuzzing_enabled && fuzz_ctxt->replay_count)
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
    struct timer_entry *timer;

    if (fd == timer_fd() && ctxt->replay_count) {
        timer = timer_next();
        if (timer && timer->expire_ms < ctxt->target_time_ms) {
            fuzz_trigger_timer(ctxt);
            ctxt->replay_time_ms = timer->expire_ms;
        } else {
            ctxt->replay_time_ms = ctxt->target_time_ms;
        }
    } else if (fd == ctxt->wsbrd->rcp.bus.fd && !size && ctxt->replay_i < ctxt->replay_count) {
        // Read from the next replay file
        ctxt->wsbrd->rcp.bus.fd = ctxt->replay_fds[ctxt->replay_i++];
        return __real_read(ctxt->wsbrd->rcp.bus.fd, buf, count);
    }

    return size;
}

int wsbr_fuzz_main(int argc, char *argv[])
{
    struct fuzz_ctxt *ctxt = &g_fuzz_ctxt;

    for (struct rcp_cmd *cmd = rcp_cmd_table; cmd->fn; cmd++) {
        if (cmd->cmd == HIF_CMD_IND_REPLAY_TIMER)
            cmd->fn = fuzz_ind_replay_timers;
        if (cmd->cmd == HIF_CMD_IND_REPLAY_SOCKET)
            cmd->fn = fuzz_ind_replay_socket;
    }
    argc = fuzz_parse_commandline(ctxt, argv);

    if (ctxt->replay_count || ctxt->fuzzing_enabled)
        capture_start("/dev/null"); // HACK: enable predictable RNG

    return wsbr_main(argc, argv);
}
