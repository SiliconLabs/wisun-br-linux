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
#include <unistd.h>
#include <signal.h>
#include <sys/timerfd.h>
#include "common/hal_interrupt.h"
#include "common/bus_uart.h"
#include "common/os_scheduler.h"
#include "common/os_types.h"
#include "common/ws_regdb.h"
#include "common/slist.h"
#include "common/log.h"
#include "common/ws_regdb.h"
#include "stack-services/ns_trace.h"
#include "stack-scheduler/eventOS_event.h"
#include "stack-scheduler/eventOS_scheduler.h"
#include "stack-scheduler/source/timer_sys.h"
#include "stack/mac/fhss_api.h"
#include "stack/mac/mac_filter_api.h"
#include "stack/ns_file_system.h"
#include "stack/ws_bbr_api.h"
#include "stack/ws_management_api.h"
#include "stack/net_ws_test.h"
#include "stack/multicast_api.h"

#include "stack/source/6lowpan/mac/mac_helper.h"
#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/6lowpan/ws/ws_regulation.h"
#include "stack/source/core/ns_address_internal.h"
#include "stack/source/security/kmp/kmp_socket_if.h"
#include "stack/source/nwk_interface/protocol_timer.h"
#include "stack/source/dhcpv6_client/dhcpv6_client_api.h"
#include "stack/source/libdhcpv6/libdhcpv6.h"

#include "mbedtls_config_check.h"
#include "commandline.h"
#include "version.h"
#include "wsbr_mac.h"
#include "wsbr.h"
#include "dbus.h"
#include "tun.h"

enum {
    POLLFD_TUN,
    POLLFD_KMP,
    POLLFD_RCP,
    POLLFD_DBUS,
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

    // FIXME: retrieve from RCP. Normally, MAC layer set this value when it
    // receive the mac802_15_4Mode request.
    // .mac_api.phyMTU = MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE,
    .mac_api.phyMTU = 2043,
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

static int8_t ws_enable_mac_filtering(struct wsbr_ctxt *ctxt)
{
    int ret;
    int i;

    if (ctxt->ws_allowed_mac_address_count > 0 || ctxt->ws_denied_mac_address_count > 0) {
        if (fw_api_older_than(ctxt, 0, 3, 0))
            FATAL(1, "RCP API is too old to enable MAC address filtering");
    }

    if (ctxt->ws_allowed_mac_address_count > 0)
        ret = mac_helper_mac_mlme_filter_start(ctxt->rcp_if_id, MAC_FILTER_BLOCKED);
    else if (ctxt->ws_denied_mac_address_count > 0)
        ret = mac_helper_mac_mlme_filter_start(ctxt->rcp_if_id, MAC_FILTER_ALLOWED);
    else
        return 0;
    if (ret)
        return -1;

    ret = mac_helper_mac_mlme_filter_clear(ctxt->rcp_if_id);
    if (ret)
        return -2;

    for (i = 0; i < ctxt->ws_allowed_mac_address_count; i++) {
        ret = mac_helper_mac_mlme_filter_add_long(ctxt->rcp_if_id, ctxt->ws_allowed_mac_addresses[i], MAC_FILTER_ALLOWED);
        if (ret)
            return -3;
    }

    for (i = 0; i < ctxt->ws_denied_mac_address_count; i++) {
        ret = mac_helper_mac_mlme_filter_add_long(ctxt->rcp_if_id, ctxt->ws_denied_mac_addresses[i], MAC_FILTER_BLOCKED);
        if (ret)
            return -4;
    }

    return 0;
}

static void wsbr_configure_ws(struct wsbr_ctxt *ctxt)
{
    int ret, i;
    int fixed_channel = get_fixed_channel(ctxt->ws_allowed_channels);
    uint8_t channel_function = (fixed_channel == 0xFFFF) ? WS_DH1CF : WS_FIXED_CHANNEL;
    uint8_t *gtks[4] = { };
    bool gtk_force = false;

    ret = ws_management_node_init(ctxt->rcp_if_id, ctxt->ws_domain,
                                  ctxt->ws_name, (struct fhss_timer *)-1);
    WARN_ON(ret);

    ret = ws_management_regulatory_domain_set(ctxt->rcp_if_id, ctxt->ws_domain,
                                              ctxt->ws_class, ctxt->ws_mode,
                                              ctxt->ws_phy_mode_id, ctxt->ws_chan_plan_id);
    WARN_ON(ret);
    if (ctxt->ws_domain == REG_DOMAIN_UNDEF) {
        ret = ws_management_channel_plan_set(ctxt->rcp_if_id,
                                             CHANNEL_FUNCTION_DH1CF,
                                             CHANNEL_FUNCTION_DH1CF,
                                             ctxt->ws_chan0_freq,
                                             ws_regdb_chan_spacing_id(ctxt->ws_chan_spacing),
                                             ctxt->ws_chan_count);
    }
    WARN_ON(ret);


    // Note that calling ws_management_fhss_timing_configure() is redundant
    // with the two function calls bellow.
    ret = ws_management_fhss_unicast_channel_function_configure(ctxt->rcp_if_id, channel_function, fixed_channel,
                                                                ctxt->uc_dwell_interval);
    WARN_ON(ret);
    ret = ws_management_fhss_broadcast_channel_function_configure(ctxt->rcp_if_id, channel_function, fixed_channel,
                                                                  ctxt->bc_dwell_interval, ctxt->bc_interval);
    WARN_ON(ret);
    if (fixed_channel == 0xFFFF) {
        ret = ws_management_channel_mask_set(ctxt->rcp_if_id, ctxt->ws_allowed_channels);
        WARN_ON(ret);
    }

    if (ctxt->ws_pan_id >= 0)
        ws_bbr_pan_configuration_set(ctxt->rcp_if_id, ctxt->ws_pan_id);

    // Note that calls to ws_management_timing_parameters_set() and
    // ws_bbr_rpl_parameters_set() are done by the function below.
    ret = ws_management_network_size_set(ctxt->rcp_if_id, ctxt->ws_size);
    WARN_ON(ret);

    ret = arm_nwk_set_tx_output_power(ctxt->rcp_if_id, ctxt->tx_power);
    WARN_ON(ret);

    ret = ws_device_min_sens_set(ctxt->rcp_if_id, 174 - 93);
    WARN_ON(ret);

    ret = ws_test_key_lifetime_set(ctxt->rcp_if_id, ctxt->ws_gtk_expire_offset, ctxt->ws_pmk_lifetime, ctxt->ws_ptk_lifetime);
    WARN_ON(ret);

    ret = ws_test_gtk_time_settings_set(ctxt->rcp_if_id, ctxt->ws_revocation_lifetime_reduction, ctxt->ws_gtk_new_activation_time, ctxt->ws_gtk_new_install_required, ctxt->ws_gtk_max_mismatch);
    WARN_ON(ret);

    ret = arm_network_own_certificate_add(&ctxt->tls_own);
    WARN_ON(ret);

    ret = arm_network_trusted_certificate_add(&ctxt->tls_ca);
    WARN_ON(ret);

    for (i = 0; i < ARRAY_SIZE(ctxt->ws_gtk_force); i++) {
        if (ctxt->ws_gtk_force[i]) {
            gtk_force = true;
            gtks[i] = ctxt->ws_gtk[i];
        }
    }
    if (gtk_force) {
        ret = ws_test_gtk_set(ctxt->rcp_if_id, gtks);
        WARN_ON(ret);
    }

    ret = ws_enable_mac_filtering(ctxt);
    WARN_ON(ret);

    if (ctxt->ws_regional_regulation) {
        FATAL_ON(fw_api_older_than(ctxt, 0, 6, 0), 2,
                 "this device does not support regional regulation");
        ret = ws_regulation_set(ctxt->rcp_if_id, ctxt->ws_regional_regulation);
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
    uint8_t ipv6[16];
    int ret;

    switch (event->event_type) {
        case ARM_LIB_TASKLET_INIT_EVENT:
            // The tasklet that call arm_nwk_interface_configure_*_bootstrap_set()
            // will be used to receive ARM_LIB_NWK_INTERFACE_EVENT.
            ret = arm_nwk_interface_configure_6lowpan_bootstrap_set(ctxt->rcp_if_id,
                                                                  NET_6LOWPAN_BORDER_ROUTER,
                                                                  NET_6LOWPAN_WS);
            WARN_ON(ret, "arm_nwk_interface_configure_6lowpan_bootstrap_set: %d", ret);
            ret = arm_nwk_interface_configure_ipv6_bootstrap_set(ctxt->tun_if_id,
                                                                 NET_IPV6_BOOTSTRAP_STATIC,
                                                                 (ctxt->dhcpv6_server.sin6_family == AF_INET6) ?
                                                                 (uint8_t *)&ctxt->dhcpv6_server.sin6_addr :
                                                                 ctxt->ipv6_prefix);
            WARN_ON(ret, "arm_nwk_interface_configure_ipv6_bootstrap_set: %d", ret);
            get_link_local_addr(ctxt->tun_dev, ipv6);
            arm_net_route_add(NULL, 0, ipv6, 0xFFFFFFFF, 0, ctxt->tun_if_id);
            multicast_fwd_full_for_scope(ctxt->tun_if_id, 3);
            multicast_fwd_full_for_scope(ctxt->rcp_if_id, 3);
            wsbr_configure_ws(ctxt);
            if (arm_nwk_interface_up(ctxt->tun_if_id))
                 WARN("arm_nwk_interface_up TUN");
            if (arm_nwk_interface_up(ctxt->rcp_if_id))
                 WARN("arm_nwk_interface_up RCP");
            if (ws_bbr_start(ctxt->rcp_if_id, ctxt->tun_if_id))
                 WARN("ws_bbr_start");
            if (strlen(ctxt->radius_secret) != 0)
                if (ws_bbr_radius_shared_secret_set(ctxt->rcp_if_id, strlen(ctxt->radius_secret), (uint8_t *)ctxt->radius_secret))
                    WARN("ws_bbr_radius_shared_secret_set");
            if (ctxt->radius_server.ss_family != AF_UNSPEC)
                if (ws_bbr_radius_address_set(ctxt->rcp_if_id, &ctxt->radius_server))
                    WARN("ws_bbr_radius_address_set");
            if (ctxt->dhcpv6_server.sin6_family == AF_INET6) {
                // dhcp relay agent needs a client instance (no other use)
                dhcp_client_init(ctxt->tun_if_id, DHCPV6_DUID_HARDWARE_EUI48_TYPE);
                dhcp_client_configure(ctxt->tun_if_id, true, true, true);
                // for nodes of rank 2 or more
                dhcp_relay_agent_enable(ctxt->tun_if_id, (uint8_t *)&ctxt->dhcpv6_server.sin6_addr);
                // for rank 1 nodes
                dhcp_relay_agent_enable(ctxt->rcp_if_id, (uint8_t *)&ctxt->dhcpv6_server.sin6_addr);
            }
            break;
        case ARM_LIB_NWK_INTERFACE_EVENT:
            if (event->event_id == ctxt->tun_if_id) {
                DEBUG("get event for tun interface: %s", nwk_events[event->event_data]);
            } else if (event->event_id == ctxt->rcp_if_id) {
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

static int wsbr_uart_tx(struct os_ctxt *os_ctxt, const void *buf, unsigned int buf_len)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    int ret;

    ret = uart_tx(os_ctxt, buf, buf_len);
    // Old firmware may merge close Rx events
    if (fw_api_older_than(ctxt, 0, 4, 0))
        usleep(20000);
    return ret;
}

void wsbr_handle_reset(struct wsbr_ctxt *ctxt, const char *version_fw_str)
{
    if (ctxt->reset_done && ctxt->hw_addr_done)
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
    ctxt->reset_done = true;
    wsbr_rcp_get_hw_addr(ctxt);
}

static void wsbr_common_timer_init(struct wsbr_ctxt *ctxt)
{
    int ret;
    struct itimerspec parms = {
        .it_value.tv_nsec = 50 * 1000 * 1000,
        .it_interval.tv_nsec = 50 * 1000 * 1000,
    };

    timer_sys_init();
    ctxt->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    FATAL_ON(ctxt->timerfd < 0, 2, "timerfd_create: %m");
    ret = timerfd_settime(ctxt->timerfd, 0, &parms, NULL);
    FATAL_ON(ret < 0, 2, "timerfd_settime: %m");
}

void kill_handler(int signal)
{
    exit(3);
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

    while (!ctxt->hw_addr_done)
        rcp_rx(ctxt);
    memcpy(ctxt->dynamic_mac, ctxt->hw_mac, sizeof(ctxt->dynamic_mac));

    if (ctxt->list_rf_configs) {
        if (fw_api_older_than(ctxt, 0, 11, 0))
            FATAL(1, "--list-rf-configs needs RCP API >= 0.10.0");
    }

    if (!fw_api_older_than(ctxt, 0, 11, 0)) {
        wsbr_rcp_get_rf_config_list(ctxt);
        while (!ctxt->list_rf_configs_done)
            rcp_rx(ctxt);
        if (ctxt->list_rf_configs)
            exit(0);
    }
}

static void wsbr_fds_init(struct wsbr_ctxt *ctxt, struct pollfd *fds)
{
    fds[POLLFD_DBUS].fd = dbus_get_fd(ctxt);
    fds[POLLFD_DBUS].events = POLLIN;
    fds[POLLFD_KMP].fd = kmp_socket_if_get_native_sockfd();
    fds[POLLFD_KMP].events = POLLIN;
    fds[POLLFD_RCP].fd = ctxt->os_ctxt->trig_fd;
    fds[POLLFD_RCP].events = POLLIN;
    fds[POLLFD_TUN].fd = ctxt->tun_fd;
    fds[POLLFD_TUN].events = POLLIN;
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

    if (fds[POLLFD_DBUS].revents & POLLIN)
        dbus_process(ctxt);
    if (fds[POLLFD_KMP].revents & POLLIN)
        kmp_socket_if_data_from_ext_radius();
    if (fds[POLLFD_TUN].revents & POLLIN)
        wsbr_tun_read(ctxt);
    if (fds[POLLFD_EVENT].revents & POLLIN) {
        read(ctxt->os_ctxt->event_fd[0], &val, sizeof(val));
        WARN_ON(val != 'W');
        eventOS_scheduler_run_until_idle();
    }
    if (fds[POLLFD_RCP].revents & POLLIN ||
        fds[POLLFD_RCP].revents & POLLERR ||
        ctxt->os_ctxt->uart_next_frame_ready)
        rcp_rx(ctxt);
    if (fds[POLLFD_TIMER].revents & POLLIN) {
        ret = read(ctxt->timerfd, &val, sizeof(val));
        WARN_ON(ret < sizeof(val), "cancelled timer?");
        WARN_ON(val != 1, "missing timers: %u", (unsigned int)val - 1);
        system_timer_tick_update(1);
        protocol_timer_cb(1);
    }
}

int main(int argc, char *argv[])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct pollfd fds[POLLFD_COUNT];

    INFO("Silicon Labs Wi-SUN border router %s", version_daemon);
    signal(SIGINT, kill_handler);
    signal(SIGHUP, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    ctxt->ping_socket_fd = -1;
    ctxt->rcp_tx = wsbr_uart_tx;
    ctxt->rcp_rx = uart_rx;
    wsbr_check_mbedtls_features();
    mbed_trace_init();
    mbed_trace_config_set(TRACE_ACTIVE_LEVEL_ALL | TRACE_MODE_COLOR);
    platform_critical_init();
    eventOS_scheduler_os_init(ctxt->os_ctxt);
    eventOS_scheduler_init();
    parse_commandline(ctxt, argc, argv, print_help_br);
    ctxt->os_ctxt->data_fd = uart_open(ctxt->uart_dev, ctxt->uart_baudrate, ctxt->uart_rtscts);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
    wsbr_tun_init(ctxt);

    wsbr_rcp_reset(ctxt);
    wsbr_rcp_init(ctxt);

    wsbr_common_timer_init(ctxt);

    if (net_init_core())
        BUG("net_init_core");

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&ctxt->mac_api, "ws0");
    if (ctxt->rcp_if_id < 0)
        BUG("arm_nwk_interface_lowpan_init: %d", ctxt->rcp_if_id);

    if (eventOS_event_handler_create(&wsbr_tasklet, ARM_LIB_TASKLET_INIT_EVENT) < 0)
        BUG("eventOS_event_handler_create");
    eventOS_scheduler_run_until_idle();

    dbus_register(ctxt);

    wsbr_fds_init(ctxt, fds);

    while (true)
        wsbr_poll(ctxt, fds);

    return 0;
}
