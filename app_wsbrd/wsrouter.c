/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#include "common/hal_interrupt.h"
#include "common/bus_uart.h"
#include "common/os_scheduler.h"
#include "common/os_types.h"
#include "common/log.h"
#include "stack-services/ns_trace.h"
#include "stack-scheduler/eventOS_event.h"
#include "stack-scheduler/eventOS_scheduler.h"
#include "service_libs/utils/ns_file_system.h"
#include "stack/mac/fhss_api.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/sw_mac.h"
#include "stack/ws_test_api.h"
#include "stack/ws_management_api.h"

#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/core/ns_address_internal.h"

#include "commandline.h"
#include "version.h"
#include "wsbr.h"
#include "wsbr_mac.h"
#include "timers.h"

enum {
    POLLFD_RCP,
    POLLFD_EVENT,
    POLLFD_TIMER,
    POLLFD_COUNT,
};

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = {
    .mac_api.mac_initialize = wsbr_mac_init,
    .mac_api.mac_mcps_edfe_enable = wsbr_mac_edfe_ext_init,
    .mac_api.mac_mcps_extension_enable = wsbr_mac_mcps_ext_init,

    .mac_api.mac_storage_sizes_get = wsbr_mac_storage_sizes_get,
    .mac_api.mac64_set = wsbr_mac_addr_set,
    .mac_api.mac64_get = wsbr_mac_addr_get,

    .mac_api.mlme_req = wsbr_mlme,
    .mac_api.mcps_data_req = wsbr_mcps_req,
    .mac_api.mcps_data_req_ext = wsbr_mcps_req_ext,
    .mac_api.mcps_purge_req = wsbr_mcps_purge,

    .mac_api.mtu = 2043,
};

// See warning in common/os_types.h
struct os_ctxt g_os_ctxt = { };

static int get_fixed_channel(uint32_t bitmask[static 8])
{
    int i, j, val = -1;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 32; j++) {
            if (bitmask[i] & (1u << j)) {
                if (val >= 0)
                    return 0xFFFF;
                val = i * 32 + j;
            }
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
                                  ctxt->config.ws_name, (struct fhss_timer *)-1);
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

    ret = ws_device_min_sens_set(ctxt->rcp_if_id, 174 - 93);
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

static void wsbr_tasklet(struct arm_event_s *event)
{
    const char *const nwk_events[] = {
        "ARM_NWK_BOOTSTRAP_READY",
        "ARM_NWK_RPL_INSTANCE_FLOODING_READY",
        "ARM_NWK_SET_DOWN_COMPLETE",
        "ARM_NWK_NWK_SCAN_FAIL",
        "ARM_NWK_IP_ADDRESS_ALLOCATION_FAIL",
        "ARM_NWK_DUPLICATE_ADDRESS_DETECTED",
        "ARM_NWK_AUHTENTICATION_START_FAIL",
        "ARM_NWK_AUHTENTICATION_FAIL",
        "ARM_NWK_NWK_CONNECTION_DOWN",
        "ARM_NWK_NWK_PARENT_POLL_FAIL",
        "ARM_NWK_PHY_CONNECTION_DOWN"
    };
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
        case ARM_LIB_NWK_INTERFACE_EVENT:
            if (event->event_id == ctxt->rcp_if_id) {
                DEBUG("get event for ws interface: %s", nwk_events[event->event_data]);
            } else {
                WARN("received unknown network event: %d", event->event_id);
            }
            break;
        default:
            WARN("received unknown event: %d", event->event_type);
            break;
    }
}

void wsbr_handle_reset(struct wsbr_ctxt *ctxt, const char *version_fw_str)
{
    if (ctxt->rcp_init_state & RCP_INIT_DONE)
        FATAL(3, "MAC layer has been reset. Operation not supported");
    INFO("Connected to RCP \"%s\" (%d.%d.%d), API %d.%d.%d", version_fw_str,
          FIELD_GET(0xFF000000, ctxt->rcp_version_fw),
          FIELD_GET(0x00FFFF00, ctxt->rcp_version_fw),
          FIELD_GET(0x000000FF, ctxt->rcp_version_fw),
          FIELD_GET(0xFF000000, ctxt->rcp_version_api),
          FIELD_GET(0x00FFFF00, ctxt->rcp_version_api),
          FIELD_GET(0x000000FF, ctxt->rcp_version_api));
    if (fw_api_older_than(ctxt, 0, 2, 0))
        FATAL(3, "RCP API is too old");
    ctxt->rcp_init_state |= RCP_HAS_RESET;
    wsbr_rcp_get_hw_addr(ctxt);
}

static void mbed_trace_print_function(const char *str)
{
    INFO("%s", str);
}

void wsbr_spinel_replay_interface(struct spinel_buffer *buf)
{
    WARN("%s: not implemented", __func__);
}

void kill_handler(int signal)
{
    exit(0);
}

static void wsbr_fds_init(struct wsbr_ctxt *ctxt, struct pollfd *fds)
{
    fds[POLLFD_RCP].fd = ctxt->os_ctxt->trig_fd;
    fds[POLLFD_RCP].events = POLLIN;
    fds[POLLFD_EVENT].fd = ctxt->os_ctxt->event_fd[0];
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
        read(ctxt->os_ctxt->event_fd[0], &val, sizeof(val));
        WARN_ON(val != 'W');
        eventOS_scheduler_run_until_idle();
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
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct pollfd fds[POLLFD_COUNT];

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);
    signal(SIGINT, kill_handler);
    signal(SIGHUP, kill_handler);
    signal(SIGTERM, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    ctxt->rcp_tx = uart_tx;
    ctxt->rcp_rx = uart_rx;
    parse_commandline(&ctxt->config, argc, argv, print_help_node);
    if (ctxt->config.color_output != -1)
        g_enable_color_traces = ctxt->config.color_output;
    mbed_trace_init();
    mbed_trace_config_set(TRACE_ACTIVE_LEVEL_ALL | (g_enable_color_traces ? TRACE_MODE_COLOR : 0));
    mbed_trace_print_function_set(mbed_trace_print_function);
    platform_critical_init();
    eventOS_scheduler_os_init(ctxt->os_ctxt);
    eventOS_scheduler_init();
    ns_file_system_set_root_path(ctxt->config.storage_prefix);
    ctxt->os_ctxt->data_fd = uart_open(ctxt->config.uart_dev, ctxt->config.uart_baudrate, ctxt->config.uart_rtscts);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;

    wsbr_rcp_reset(ctxt);
    while (!(ctxt->rcp_init_state & RCP_HAS_HWADDR))
        rcp_rx(ctxt);
    memcpy(ctxt->dynamic_mac, ctxt->hw_mac, sizeof(ctxt->dynamic_mac));
    ctxt->rcp_init_state |= RCP_INIT_DONE;

    wsbr_common_timer_init(ctxt);
    if (net_init_core())
        BUG("net_init_core");

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&ctxt->mac_api, "ws0");
    if (ctxt->rcp_if_id < 0)
        BUG("arm_nwk_interface_lowpan_init: %d", ctxt->rcp_if_id);

    if (eventOS_event_handler_create(&wsbr_tasklet, ARM_LIB_TASKLET_INIT_EVENT) < 0)
        BUG("eventOS_event_handler_create");

    wsbr_fds_init(ctxt, fds);

    while (true)
        wsbr_poll(ctxt, fds);

    return 0;
}

