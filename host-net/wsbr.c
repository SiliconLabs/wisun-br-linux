/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>

#include "mbed-trace/mbed_trace.h"
#include "nanostack-event-loop/eventOS_event.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack/fhss_api.h"
#include "nanostack/mac_filter_api.h"
#include "nanostack/ns_file_system.h"
#include "nanostack/ws_bbr_api.h"
#include "nanostack/net_ws_test.h"
#include "nanostack/ws_management_api.h"
#include "nanostack/source/6LoWPAN/MAC/mac_helper.h"
#include "nanostack/source/6LoWPAN/ws/ws_common_defines.h"
#include "nanostack/source/Core/include/ns_address_internal.h"

#include "host-common/hal_interrupt.h"
#include "host-common/bus_uart.h"
#include "host-common/os_scheduler.h"
#include "host-common/os_types.h"
#include "host-common/os_timer.h"
#include "host-common/slist.h"
#include "host-common/log.h"
#include "version.h"
#include "wsbr_mac.h"
#include "wsbr.h"
#include "commandline.h"
#include "dbus.h"
#include "tun.h"

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = {
    .mac_api.mac_initialize = wsbr_mac_init,
    .mac_api.mac_mode_switch_resolver_set = wsbr_mac_mode_switch_resolver_set,
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

// See warning in host-common/os_types.h
struct os_ctxt g_os_ctxt = { };

static int get_fixed_channel(uint32_t bitmask[static 8])
{
    int i, j, val = -1;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 32; j++) {
            if (bitmask[i] & (1 << j)) {
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

    WARN_ON(ctxt->ws_domain == 0xFE, "Not supported");
    ret = ws_management_regulatory_domain_set(ctxt->rcp_if_id, ctxt->ws_domain,
                                              ctxt->ws_class, ctxt->ws_mode);
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

    switch (event->event_type) {
        case ARM_LIB_TASKLET_INIT_EVENT:
            // The tasklet that call arm_nwk_interface_configure_*_bootstrap_set()
            // will be used to receive ARM_LIB_NWK_INTERFACE_EVENT.
            if (arm_nwk_interface_configure_6lowpan_bootstrap_set(ctxt->rcp_if_id,
                                                                  NET_6LOWPAN_BORDER_ROUTER,
                                                                  NET_6LOWPAN_WS))
                WARN("arm_nwk_interface_configure_6lowpan_bootstrap_set");
            if (arm_nwk_interface_configure_ipv6_bootstrap_set(ctxt->tun_if_id,
                                                               NET_IPV6_BOOTSTRAP_STATIC,
                                                               ctxt->ipv6_prefix))
                WARN("arm_nwk_interface_configure_ipv6_bootstrap_set");
            get_link_local_addr(ctxt->tun_dev, ipv6);
            arm_net_route_add(NULL, 0, ipv6, 0xFFFFFFFF, 0, ctxt->tun_if_id);
            wsbr_configure_ws(ctxt);
            if (arm_nwk_interface_up(ctxt->tun_if_id))
                 WARN("arm_nwk_interface_up TUN");
            if (arm_nwk_interface_up(ctxt->rcp_if_id))
                 WARN("arm_nwk_interface_up RCP");
            if (ws_bbr_start(ctxt->rcp_if_id, ctxt->tun_if_id))
                 WARN("ws_bbr_start");
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

void kill_handler(int signal)
{
    exit(3);
}

int main(int argc, char *argv[])
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct callback_timer *timer;
    fd_set rfds, efds;
    int maxfd, ret;
    uint64_t val;
    struct timespec ts = { };

    INFO("Silicon Labs Wi-SUN border router %s", version_daemon);
    signal(SIGINT, kill_handler);
    signal(SIGHUP, kill_handler);
    ctxt->os_ctxt = &g_os_ctxt;
    ctxt->ping_socket_fd = -1;
    ctxt->rcp_tx = wsbr_uart_tx;
    ctxt->rcp_rx = uart_rx;
    mbed_trace_init();
    mbed_trace_config_set(TRACE_ACTIVE_LEVEL_ALL | TRACE_MODE_COLOR);
    platform_critical_init();
    eventOS_scheduler_os_init(ctxt->os_ctxt);
    eventOS_scheduler_init();
    parse_commandline(ctxt, argc, argv, print_help_br);
    if (!memcmp(ctxt->ipv6_prefix, ADDR_UNSPECIFIED, 16))
        FATAL(1, "You must specify a ipv6_prefix");
    ctxt->os_ctxt->data_fd = uart_open(ctxt->uart_dev, ctxt->uart_baudrate, ctxt->uart_rtscts);
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;
    wsbr_tun_init(ctxt);

    wsbr_rcp_reset(ctxt);
    while (!ctxt->hw_addr_done)
        rcp_rx(ctxt);
    memcpy(ctxt->dynamic_mac, ctxt->hw_mac, sizeof(ctxt->dynamic_mac));

    if (net_init_core())
        BUG("net_init_core");

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&ctxt->mac_api, "ws0");
    if (ctxt->rcp_if_id < 0)
        BUG("arm_nwk_interface_lowpan_init: %d", ctxt->rcp_if_id);

    if (eventOS_event_handler_create(&wsbr_tasklet, ARM_LIB_TASKLET_INIT_EVENT) < 0)
        BUG("eventOS_event_handler_create");

    dbus_register(ctxt);

    for (;;) {
        maxfd = 0;
        FD_ZERO(&rfds);
        FD_ZERO(&efds);
        if (dbus_get_fd(ctxt) >= 0) {
            FD_SET(dbus_get_fd(ctxt), &rfds);
            maxfd = max(maxfd, dbus_get_fd(ctxt));
        }
        if (ctxt->os_ctxt->trig_fd == ctxt->os_ctxt->data_fd)
            FD_SET(ctxt->os_ctxt->trig_fd, &rfds); // UART
        else
            FD_SET(ctxt->os_ctxt->trig_fd, &efds); // SPI + GPIO
        maxfd = max(maxfd, ctxt->os_ctxt->trig_fd);
        FD_SET(ctxt->tun_fd, &rfds);
        maxfd = max(maxfd, ctxt->tun_fd);
        FD_SET(ctxt->os_ctxt->event_fd[0], &rfds);
        maxfd = max(maxfd, ctxt->os_ctxt->event_fd[0]);
        SLIST_FOR_EACH_ENTRY(ctxt->os_ctxt->timers, timer, node) {
            FD_SET(timer->fd, &rfds);
            maxfd = max(maxfd, timer->fd);
        }
        // FIXME: consider poll() usage
        if (ctxt->os_ctxt->uart_next_frame_ready)
            ret = pselect(maxfd + 1, &rfds, NULL, &efds, &ts, NULL);
        else
            ret = pselect(maxfd + 1, &rfds, NULL, &efds, NULL, NULL);
        if (ret < 0)
            FATAL(2, "pselect: %m");
        if (FD_ISSET(dbus_get_fd(ctxt), &rfds))
            dbus_process(ctxt);
        if (FD_ISSET(ctxt->tun_fd, &rfds))
            wsbr_tun_read(ctxt);
        if (FD_ISSET(ctxt->os_ctxt->event_fd[0], &rfds)) {
            read(ctxt->os_ctxt->event_fd[0], &val, sizeof(val));
            WARN_ON(val != 'W');
            eventOS_scheduler_run_until_idle();
        }
        if (FD_ISSET(ctxt->os_ctxt->trig_fd, &rfds) ||
            FD_ISSET(ctxt->os_ctxt->trig_fd, &efds) ||
            ctxt->os_ctxt->uart_next_frame_ready)
            rcp_rx(ctxt);
        SLIST_FOR_EACH_ENTRY(ctxt->os_ctxt->timers, timer, node) {
            if (FD_ISSET(timer->fd, &rfds)) {
                ret = read(timer->fd, &val, sizeof(val));
                WARN_ON(ret < sizeof(val) || val != 1, "cancelled timer?");
                timer->fn(timer->fd, 0);
            }
        }
    }

    return 0;
}

