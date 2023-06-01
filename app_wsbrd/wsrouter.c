/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include "common/bus_uart.h"
#include "common/events_scheduler.h"
#include "common/os_types.h"
#include "common/key_value_storage.h"
#include "common/utils.h"
#include "common/log.h"
#include "common/log_legacy.h"
#include "common/version.h"
#include "stack/mac/fhss_api.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/sw_mac.h"
#include "stack/ws_test_api.h"
#include "stack/ws_management_api.h"

#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/6lowpan/ws/ws_llc.h"
#include "stack/source/core/ns_address_internal.h"

#include "commandline.h"
#include "version.h"
#include "rcp_api.h"
#include "wsbr.h"
#include "wsbr_mac.h"
#include "timers.h"

static void wsbr_handle_reset(struct wsbr_ctxt *ctxt);
static void wsbr_handle_rx_err(uint8_t src[8], uint8_t status);

enum {
    POLLFD_RCP,
    POLLFD_EVENT,
    POLLFD_TIMER,
    POLLFD_COUNT,
};

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = {
    .rcp.on_reset = wsbr_handle_reset,
    .rcp.on_rx_err = wsbr_handle_rx_err,
    .rcp.on_tx_cnf = ws_llc_mac_confirm_cb,
    .rcp.on_rx_ind = ws_llc_mac_indication_cb,

    // avoid initializating to 0 = STDIN_FILENO
    .pcapng_fd = -1,
};

// See warning in common/os_types.h
struct os_ctxt g_os_ctxt = { };

static int get_fixed_channel(uint8_t bitmask[static 32])
{
    int val = -1;

    for (int i = 0; i < 256; i++) {
        if (bittest(bitmask, i)) {
            if (val >= 0)
                return 0xFFFF;
            val = i;
        }
    }
    return val;
}

static void wsbr_configure_ws(struct wsbr_ctxt *ctxt)
{
    int ret, i;
    int fixed_channel = get_fixed_channel(ctxt->config.ws_allowed_channels);
    uint8_t channel_function = (fixed_channel == 0xFFFF) ? WS_DH1CF : WS_FIXED_CHANNEL;
    uint8_t *gtks[4] = { };
    bool gtk_force = false;

    ret = ws_management_node_init(ctxt->rcp_if_id, ctxt->config.ws_domain,
                                  ctxt->config.ws_name);
    WARN_ON(ret);

    WARN_ON(ctxt->config.ws_domain == 0xFE, "Not supported");
    ret = ws_management_regulatory_domain_set(ctxt->rcp_if_id, ctxt->config.ws_domain,
                                              ctxt->config.ws_class, ctxt->config.ws_mode,
                                              ctxt->config.ws_phy_mode_id, ctxt->config.ws_chan_plan_id);
    WARN_ON(ret);

    // Note that calling ws_management_fhss_timing_configure() is redundant
    // with the two function calls bellow.
    ret = ws_management_fhss_unicast_channel_function_configure(ctxt->rcp_if_id, channel_function, fixed_channel,
                                                                WS_FHSS_UC_DWELL_INTERVAL);
    WARN_ON(ret);
    ret = ws_management_fhss_broadcast_channel_function_configure(ctxt->rcp_if_id, channel_function, fixed_channel,
                                                                  WS_FHSS_BC_DWELL_INTERVAL, WS_FHSS_BC_INTERVAL);
    WARN_ON(ret);
    if (fixed_channel == 0xFFFF) {
        ret = ws_management_channel_mask_set(ctxt->rcp_if_id, ctxt->config.ws_allowed_channels);
        WARN_ON(ret);
    }


    // Note that calls to ws_management_timing_parameters_set() and
    // ws_bbr_rpl_parameters_set() are done by the function below.
    ret = ws_management_network_size_set(ctxt->rcp_if_id, ctxt->config.ws_size);
    WARN_ON(ret);

    ret = ws_test_version_set(ctxt->rcp_if_id, ctxt->config.ws_fan_version);
    WARN_ON(ret);

    ret = arm_network_own_certificate_add(&ctxt->config.tls_own);
    WARN_ON(ret);

    ret = arm_network_trusted_certificate_add(&ctxt->config.tls_ca);
    WARN_ON(ret);


    for (i = 0; i < ARRAY_SIZE(ctxt->config.ws_gtk_force); i++) {
        if (ctxt->config.ws_gtk_force[i]) {
            gtk_force = true;
            gtks[i] = ctxt->config.ws_gtk[i];
        }
    }
    if (gtk_force) {
        ret = ws_test_gtk_set(ctxt->rcp_if_id, gtks);
        WARN_ON(ret);
    }
}

static void wsbr_tasklet(struct event_payload *event)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    switch (event->event_type) {
        case ARM_LIB_TASKLET_INIT_EVENT:
            // The tasklet that call arm_nwk_interface_configure_*_bootstrap_set()
            // will be used to receive ARM_LIB_NWK_INTERFACE_EVENT.
            if (arm_nwk_interface_configure_6lowpan_bootstrap_set(ctxt->rcp_if_id,
                                                                  NET_6LOWPAN_ROUTER,
                                                                  NET_6LOWPAN_WS))
                WARN("arm_nwk_interface_configure_6lowpan_bootstrap_set");
            wsbr_configure_ws(ctxt);
            if (arm_nwk_interface_up(ctxt->rcp_if_id, NULL))
                 WARN("arm_nwk_interface_up RCP");
            break;
        default:
            WARN("received unknown event: %d", event->event_type);
            break;
    }
}

static void wsbr_handle_rx_err(uint8_t src[8], uint8_t status)
{
    TRACE(TR_DROP, "drop %-9s: from %s: %02x", "15.4", tr_ipv6(src), status);
}

static void wsbr_handle_reset(struct wsbr_ctxt *ctxt)
{
    if (ctxt->rcp.init_state & RCP_HAS_HWADDR) {
        if (!(ctxt->rcp.init_state & RCP_HAS_RF_CONFIG))
            FATAL(3, "unsupported radio configuration (check --list-rf-config)");
        else
            FATAL(3, "MAC layer has been reset. Operation not supported");
    }
    INFO("Connected to RCP \"%s\" (%d.%d.%d), API %d.%d.%d", ctxt->rcp.version_label,
          FIELD_GET(0xFF000000, ctxt->rcp.version_fw),
          FIELD_GET(0x00FFFF00, ctxt->rcp.version_fw),
          FIELD_GET(0x000000FF, ctxt->rcp.version_fw),
          FIELD_GET(0xFF000000, ctxt->rcp.version_api),
          FIELD_GET(0x00FFFF00, ctxt->rcp.version_api),
          FIELD_GET(0x000000FF, ctxt->rcp.version_api));
    if (version_older_than(ctxt->rcp.version_api, 0, 2, 0))
        FATAL(3, "RCP API is too old");
    rcp_get_hw_addr();
}

void kill_handler(int signal)
{
    exit(0);
}

static void wsbr_rcp_init(struct wsbr_ctxt *ctxt)
{
    static const int timeout_values[] = { 2, 15, 60, 300, 900, 3600 }; // seconds
    struct pollfd fds = { .fd = ctxt->os_ctxt->data_fd, .events = POLLIN };
    int ret, i;

    i = 0;
    do {
        ret = poll(&fds, 1, timeout_values[i] * 1000);
        if (ret < 0)
            FATAL(2, "poll: %m");
        if (ret == 0)
            WARN("still waiting for RCP");
        if (i + 1 < ARRAY_SIZE(timeout_values))
            i++;
    } while (ret < 1);

    while (!(ctxt->rcp.init_state & RCP_HAS_RESET))
        rcp_rx(ctxt);

    if (version_older_than(ctxt->rcp.version_api, 0, 15, 0) && ctxt->config.ws_fan_version == WS_FAN_VERSION_1_1)
        FATAL(1, "RCP does not support FAN 1.1");
    if (version_older_than(ctxt->rcp.version_api, 0, 16, 0) && ctxt->config.pcap_file[0])
        FATAL(1, "pcap_file requires RCP >= 0.16.0");

    while (!(ctxt->rcp.init_state & RCP_HAS_HWADDR))
        rcp_rx(ctxt);

    if (ctxt->config.list_rf_configs) {
        if (version_older_than(ctxt->rcp.version_api, 0, 11, 0))
            FATAL(1, "--list-rf-configs needs RCP API >= 0.10.0");
    }

    if (!version_older_than(ctxt->rcp.version_api, 0, 11, 0)) {
        rcp_get_rf_config_list();
        while (!(ctxt->rcp.init_state & RCP_HAS_RF_CONFIG_LIST))
            rcp_rx(ctxt);
        if (ctxt->config.list_rf_configs)
            exit(0);
    }
}

static void wsbr_fds_init(struct wsbr_ctxt *ctxt, struct pollfd *fds)
{
    fds[POLLFD_RCP].fd = ctxt->os_ctxt->trig_fd;
    fds[POLLFD_RCP].events = POLLIN;
    fds[POLLFD_EVENT].fd = ctxt->scheduler.event_fd[0];
    fds[POLLFD_EVENT].events = POLLIN;
    fds[POLLFD_TIMER].fd = ctxt->timerfd;
    fds[POLLFD_TIMER].events = POLLIN;
}

static void wsbr_poll(struct wsbr_ctxt *ctxt, struct pollfd *fds)
{
    uint64_t val;
    int ret;

    if (ctxt->os_ctxt->uart_next_frame_ready)
        ret = poll(fds, POLLFD_COUNT, 0);
    else
        ret = poll(fds, POLLFD_COUNT, -1);
    if (ret < 0)
        FATAL(2, "poll: %m");

    if (fds[POLLFD_EVENT].revents & POLLIN) {
        read(ctxt->scheduler.event_fd[0], &val, sizeof(val));
        WARN_ON(val != 'W');
        event_scheduler_run_until_idle();
    }
    if (fds[POLLFD_RCP].revents & POLLIN ||
        fds[POLLFD_RCP].revents & POLLERR ||
        ctxt->os_ctxt->uart_next_frame_ready)
        rcp_rx(ctxt);
    if (fds[POLLFD_TIMER].revents & POLLIN)
        wsbr_common_timer_process(ctxt);
}

int main(int argc, char *argv[])
{
    static const char *files[] = {
        "pairwise-keys",
        "network-keys",
        "counters",
        NULL,
    };
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct pollfd fds[POLLFD_COUNT];

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);
    signal(SIGINT, kill_handler);
    signal(SIGHUP, kill_handler);
    signal(SIGTERM, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    ctxt->rcp.device_tx = uart_tx;
    ctxt->rcp.device_rx = uart_rx;
    ctxt->rcp.on_crc_error = uart_handle_crc_error;
    parse_commandline(&ctxt->config, argc, argv, print_help_node);
    if (ctxt->config.color_output != -1)
        g_enable_color_traces = ctxt->config.color_output;
    event_scheduler_init(&ctxt->scheduler);
    g_storage_prefix = ctxt->config.storage_prefix[0] ? ctxt->config.storage_prefix : NULL;
    if (ctxt->config.storage_delete)
        storage_delete(files);
    ctxt->os_ctxt->data_fd = uart_open(ctxt->config.uart_dev, ctxt->config.uart_baudrate, ctxt->config.uart_rtscts);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;

    rcp_reset();
    wsbr_rcp_init(ctxt);

    wsbr_common_timer_init(ctxt);
    if (net_init_core())
        BUG("net_init_core");

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&ctxt->rcp, ctxt->config.lowpan_mtu, "ws0");
    if (ctxt->rcp_if_id < 0)
        BUG("arm_nwk_interface_lowpan_init: %d", ctxt->rcp_if_id);

    if (event_handler_create(&wsbr_tasklet, ARM_LIB_TASKLET_INIT_EVENT) < 0)
        BUG("event_handler_create");

    wsbr_fds_init(ctxt, fds);

    while (true)
        wsbr_poll(ctxt, fds);

    return 0;
}

