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
#include <unistd.h>
#include <signal.h>
#include "common/bus_uart.h"
#include "common/bus_cpc.h"
#include "common/dhcp_server.h"
#include "common/events_scheduler.h"
#include "common/os_types.h"
#include "common/ws_regdb.h"
#include "common/log.h"
#include "common/utils.h"
#include "common/version.h"
#include "common/ws_regdb.h"
#include "common/key_value_storage.h"
#include "common/log_legacy.h"
#include "stack/net_multicast.h"
#include "stack/mac/fhss_api.h"
#include "stack/mac/mac_filter_api.h"
#include "stack/ws_bbr_api.h"
#include "stack/ws_management_api.h"
#include "stack/ws_test_api.h"
#include "stack/timers.h"

#include "stack/source/6lowpan/mac/mac_helper.h"
#include "stack/source/6lowpan/ws/ws_bbr_api_internal.h"
#include "stack/source/6lowpan/ws/ws_common_defines.h"
#include "stack/source/6lowpan/ws/ws_common.h"
#include "stack/source/6lowpan/ws/ws_cfg_settings.h"
#include "stack/source/6lowpan/ws/ws_regulation.h"
#include "stack/source/6lowpan/ws/ws_llc.h"
#include "stack/source/core/ns_address_internal.h"
#include "stack/source/nwk_interface/protocol.h"
#include "stack/source/security/kmp/kmp_socket_if.h"

#include "mbedtls_config_check.h"
#include "commandline_values.h"
#include "drop_privileges.h"
#include "commandline.h"
#include "version.h"
#include "wsbr_mac.h"
#include "wsbr_pcapng.h"
#include "libwsbrd.h"
#include "wsbr.h"
#include "timers.h"
#include "rcp_api.h"
#include "rail_config.h"
#include "dbus.h"
#include "tun.h"

static void wsbr_handle_reset(struct wsbr_ctxt *ctxt);
static void wsbr_handle_rx_err(uint8_t src[8], uint8_t status);

enum {
    POLLFD_TUN,
    POLLFD_RCP,
    POLLFD_DBUS,
    POLLFD_EVENT,
    POLLFD_TIMER,
    POLLFD_DHCP_SERVER,
    POLLFD_BR_EAPOL_RELAY,
    POLLFD_EAPOL_RELAY,
    POLLFD_PAE_AUTH,
    POLLFD_RADIUS,
    POLLFD_COUNT,
};

// See warning in wsbr.h
struct wsbr_ctxt g_ctxt = {
    .scheduler.event_fd = { -1, -1 },

    .rcp.on_reset = wsbr_handle_reset,
    .rcp.on_rx_err = wsbr_handle_rx_err,
    .rcp.on_tx_cnf = ws_llc_mac_confirm_cb,
    .rcp.on_rx_ind = ws_llc_mac_indication_cb,

    // avoid initializating to 0 = STDIN_FILENO
    .timerfd = -1,
    .tun_fd = -1,
    .pcapng_fd = -1,
    .dhcp_server.fd = -1,

    .os_ctxt = &g_os_ctxt,
};

// See warning in common/os_types.h
struct os_ctxt g_os_ctxt = {
    // avoid initializating to 0 = STDIN_FILENO
    .trig_fd = -1,
    .data_fd = -1,
};

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

static void ws_enable_mac_filtering(struct wsbr_ctxt *ctxt)
{
    int i;

    BUG_ON(ctxt->config.ws_allowed_mac_address_count && ctxt->config.ws_denied_mac_address_count);
    if (!ctxt->config.ws_allowed_mac_address_count && !ctxt->config.ws_denied_mac_address_count)
        return;
    if (version_older_than(ctxt->rcp.version_api, 0, 3, 0))
        FATAL(1, "RCP API is too old to enable MAC address filtering");
    if (ctxt->config.ws_allowed_mac_address_count)
        rcp_enable_mac_filter(false);
    if (ctxt->config.ws_denied_mac_address_count)
        rcp_enable_mac_filter(true);
    rcp_clear_mac_filters();
    for (i = 0; i < ctxt->config.ws_allowed_mac_address_count; i++)
        rcp_add_mac_filter_entry(ctxt->config.ws_allowed_mac_addresses[i], true);
    for (i = 0; i < ctxt->config.ws_denied_mac_address_count; i++)
        rcp_add_mac_filter_entry(ctxt->config.ws_allowed_mac_addresses[i], false);
}

static int wsbr_configure_ws_sect_time(struct wsbr_ctxt *ctxt)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    ws_sec_timer_cfg_t cfg;
    int ret;

    ws_cfg_sec_timer_get(&cfg);
    cfg.pmk_lifetime = ctxt->config.ws_pmk_lifetime;
    cfg.ptk_lifetime = ctxt->config.ws_ptk_lifetime;
    cfg.gtk_expire_offset = ctxt->config.ws_gtk_expire_offset;
    cfg.gtk_new_act_time = ctxt->config.ws_gtk_new_activation_time;
    cfg.gtk_new_install_req = ctxt->config.ws_gtk_new_install_required;
    cfg.ffn_revocat_lifetime_reduct = ctxt->config.ws_ffn_revocation_lifetime_reduction;
    cfg.lgtk_expire_offset = ctxt->config.ws_lgtk_expire_offset;
    cfg.lgtk_new_act_time = ctxt->config.ws_lgtk_new_activation_time;
    cfg.lgtk_new_install_req = ctxt->config.ws_lgtk_new_install_required;
    cfg.lfn_revocat_lifetime_reduct = ctxt->config.ws_lfn_revocation_lifetime_reduction;
    ret = ws_cfg_sec_timer_set(cur, &cfg, 0x00);
    return ret;
}

static void wsbr_configure_ws(struct wsbr_ctxt *ctxt)
{
    int ret, i;
    int fixed_channel = get_fixed_channel(ctxt->config.ws_allowed_channels);
    uint8_t channel_function = (fixed_channel == 0xFFFF) ? WS_DH1CF : WS_FIXED_CHANNEL;
    uint8_t *gtks[4] = { };
    bool gtk_force = false;
    uint8_t *lgtks[3] = { };
    bool lgtk_force = false;

    ret = ws_management_node_init(ctxt->rcp_if_id, ctxt->config.ws_domain,
                                  ctxt->config.ws_name);
    WARN_ON(ret);

    ret = ws_management_regulatory_domain_set(ctxt->rcp_if_id, ctxt->config.ws_domain,
                                              ctxt->config.ws_class, ctxt->config.ws_mode,
                                              ctxt->config.ws_phy_mode_id, ctxt->config.ws_chan_plan_id);
    WARN_ON(ret);
    if (ctxt->config.ws_domain == REG_DOMAIN_UNDEF) {
        ret = ws_management_channel_plan_set(ctxt->rcp_if_id,
                                             CHANNEL_FUNCTION_DH1CF,
                                             CHANNEL_FUNCTION_DH1CF,
                                             ctxt->config.ws_chan0_freq,
                                             ws_regdb_chan_spacing_id(ctxt->config.ws_chan_spacing),
                                             ctxt->config.ws_chan_count);
    }
    WARN_ON(ret);

    rail_fill_pom(ctxt);

    // Note that calling ws_management_fhss_timing_configure() is redundant
    // with the two function calls bellow.
    ret = ws_management_fhss_unicast_channel_function_configure(ctxt->rcp_if_id, channel_function, fixed_channel,
                                                                ctxt->config.uc_dwell_interval);
    WARN_ON(ret);
    ret = ws_management_fhss_broadcast_channel_function_configure(ctxt->rcp_if_id, channel_function, fixed_channel,
                                                                  ctxt->config.bc_dwell_interval, ctxt->config.bc_interval);
    WARN_ON(ret);
    ret = ws_management_fhss_lfn_configure(ctxt->rcp_if_id, ctxt->config.lfn_bc_interval, ctxt->config.lfn_bc_sync_period);
    g_timers[WS_TIMER_LTS].period_ms =
        rounddown(ctxt->config.lfn_bc_interval * ctxt->config.lfn_bc_sync_period, WS_TIMER_GLOBAL_PERIOD_MS);
    WARN_ON(ret);
    if (fixed_channel == 0xFFFF) {
        ret = ws_management_channel_mask_set(ctxt->rcp_if_id, ctxt->config.ws_allowed_channels);
        WARN_ON(ret);
    }

    if (ctxt->config.ws_pan_id >= 0)
        ws_bbr_pan_configuration_set(ctxt->rcp_if_id, ctxt->config.ws_pan_id);

    // Note that calls to ws_management_timing_parameters_set() and
    // ws_bbr_rpl_parameters_set() are done by the function below.
    ret = ws_management_network_size_set(ctxt->rcp_if_id, ctxt->config.ws_size);
    WARN_ON(ret);

    ret = ws_test_version_set(ctxt->rcp_if_id, ctxt->config.ws_fan_version);
    WARN_ON(ret);

    rcp_set_tx_power(ctxt->config.tx_power);

    ret = wsbr_configure_ws_sect_time(ctxt);
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

    for (i = 0; i < ARRAY_SIZE(ctxt->config.ws_lgtk_force); i++) {
        if (ctxt->config.ws_lgtk_force[i]) {
            lgtk_force = true;
            lgtks[i] = ctxt->config.ws_lgtk[i];
        }
    }
    if (lgtk_force) {
        ret = ws_test_lgtk_set(ctxt->rcp_if_id, lgtks);
        WARN_ON(ret);
    }

    ws_enable_mac_filtering(ctxt);

    if (ctxt->config.ws_regional_regulation) {
        FATAL_ON(version_older_than(ctxt->rcp.version_api, 0, 6, 0), 2,
                 "this device does not support regional regulation");
        ret = ws_regulation_set(ctxt->rcp_if_id, ctxt->config.ws_regional_regulation);
        WARN_ON(ret);
    }

    if (!version_older_than(ctxt->rcp.version_api, 0, 17, 0))
        rcp_set_max_async_duration(ctxt->config.ws_async_frag_duration);
}

static void wsbr_check_link_local_addr(struct wsbr_ctxt *ctxt)
{
    struct net_if *interface;
    uint8_t addr_ws0[16];
    uint8_t addr_tun[16];
    bool cmp;

    tun_addr_get_link_local(ctxt->config.tun_dev, addr_tun);
    if (!memcmp(addr_tun, ADDR_UNSPECIFIED, 16))
        FATAL(1, "no link-local address found on %s", ctxt->config.tun_dev);

    interface = protocol_stack_interface_info_get_by_id(ctxt->rcp_if_id);
    addr_interface_get_ll_address(interface, addr_ws0, 0);

    cmp = memcmp(addr_ws0, addr_tun, 16);
    FATAL_ON(cmp, 1, "address mismatch: expected %s but found %s on %s",
        tr_ipv6(addr_ws0), tr_ipv6(addr_tun), ctxt->config.tun_dev);
}

static void wsbr_network_init(struct wsbr_ctxt *ctxt)
{
    uint8_t ipv6[16];
    int ret;

    ret = arm_nwk_interface_configure_6lowpan_bootstrap_set(ctxt->rcp_if_id,
                                                          NET_6LOWPAN_BORDER_ROUTER,
                                                          NET_6LOWPAN_WS);
    WARN_ON(ret, "arm_nwk_interface_configure_6lowpan_bootstrap_set: %d", ret);
    wsbr_configure_ws(ctxt);
    tun_addr_get_global_unicast(ctxt->config.tun_dev, ipv6);
    if (!memcmp(ipv6, ADDR_UNSPECIFIED, 16))
        FATAL(1, "no gua found on %s", ctxt->config.tun_dev);
    if (arm_nwk_interface_up(ctxt->rcp_if_id, ipv6))
        WARN("arm_nwk_interface_up RCP");
    wsbr_check_link_local_addr(ctxt);
    if (ws_bbr_start(ctxt->rcp_if_id, ctxt->rcp_if_id))
        WARN("ws_bbr_start");
    if (ctxt->config.internal_dhcp)
        dhcp_start(&ctxt->dhcp_server, ctxt->config.tun_dev, ctxt->rcp.eui64, ipv6);
    if (strlen(ctxt->config.radius_secret) != 0)
        if (ws_bbr_radius_shared_secret_set(ctxt->rcp_if_id, strlen(ctxt->config.radius_secret), (uint8_t *)ctxt->config.radius_secret))
            WARN("ws_bbr_radius_shared_secret_set");
    if (ctxt->config.radius_server.ss_family != AF_UNSPEC)
        if (ws_bbr_radius_address_set(ctxt->rcp_if_id, &ctxt->config.radius_server))
            WARN("ws_bbr_radius_address_set");
    // Artificially add wsbrd to the DHCP lease list
    wsbr_dhcp_lease_update(ctxt, ctxt->rcp.eui64, ipv6);
}

static int wsbr_uart_tx(struct os_ctxt *os_ctxt, const void *buf, unsigned int buf_len)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;
    int ret;

    ret = uart_tx(os_ctxt, buf, buf_len);
    // Old firmware may merge close Rx events
    if (version_older_than(ctxt->rcp.version_api, 0, 4, 0))
        usleep(20000);
    return ret;
}

static void wsbr_handle_rx_err(uint8_t src[8], uint8_t status)
{
    TRACE(TR_DROP, "drop %-9s: from %s: status 0x%02x", "15.4", tr_eui64(src), status);
}

static void wsbr_handle_reset(struct wsbr_ctxt *ctxt)
{
    int min_device_description_table_size = MAX_NEIGH_TEMPORARY_EAPOL_SIZE + WS_SMALL_TEMPORARY_NEIGHBOUR_ENTRIES;

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
    if (ctxt->rcp.neighbors_table_size <= min_device_description_table_size)
        FATAL(1, "RCP size of \"neighbor_timings\" table is too small (should be > %d)",
              min_device_description_table_size);
    rcp_get_hw_addr();
}

void kill_handler(int signal)
{
    exit(0);
}

void wsbr_dhcp_lease_update(struct wsbr_ctxt *ctxt, const uint8_t eui64[8], const uint8_t ipv6[16])
{
    int i;

    // delete entries that already use this IPv6 address
    for (i = 0; i < ctxt->dhcp_leases_len; i++) {
        if (!memcmp(ctxt->dhcp_leases[i].ipv6, ipv6, 16)) {
            memmove(ctxt->dhcp_leases + i, ctxt->dhcp_leases + i + 1,
                    (ctxt->dhcp_leases_len - i - 1) * sizeof(*ctxt->dhcp_leases));
            ctxt->dhcp_leases_len--;
            i--;
        }
    }

    for (i = 0; i < ctxt->dhcp_leases_len; i++)
        if (!memcmp(ctxt->dhcp_leases[i].eui64, eui64, 8))
            break;
    if (i == ctxt->dhcp_leases_len) {
        ctxt->dhcp_leases_len++;
        ctxt->dhcp_leases = realloc(ctxt->dhcp_leases, ctxt->dhcp_leases_len * sizeof(*ctxt->dhcp_leases));
        BUG_ON(!ctxt->dhcp_leases);
    }
    memcpy(ctxt->dhcp_leases[i].eui64, eui64, 8);
    memcpy(ctxt->dhcp_leases[i].ipv6, ipv6, 16);
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

    ctxt->os_ctxt->uart_inhibit_crc_warning = true;
    while (!(ctxt->rcp.init_state & RCP_HAS_RESET))
        rcp_rx(ctxt);
    ctxt->os_ctxt->uart_inhibit_crc_warning = false;

    if (version_older_than(ctxt->rcp.version_api, 0, 15, 0) && ctxt->config.ws_fan_version == WS_FAN_VERSION_1_1)
        FATAL(1, "fan_version = 1.1 requires RCP API >= 0.15.0");
    if (version_older_than(ctxt->rcp.version_api, 0, 16, 0) && ctxt->config.pcap_file[0])
        FATAL(1, "pcap_file requires RCP API >= 0.16.0");
    if (version_older_than(ctxt->rcp.version_api, 0, 16, 0) && ctxt->config.list_rf_configs)
        FATAL(1, "--list-rf-configs requires RCP API >= 0.16.0");
    if (version_older_than(ctxt->rcp.version_api, 0, 16, 0)) {
        while (!(ctxt->rcp.init_state & RCP_HAS_HWADDR))
            rcp_rx(ctxt);
    } else {
        rcp_get_rf_config_list();
        while (!(ctxt->rcp.init_state & RCP_HAS_RF_CONFIG_LIST))
            rcp_rx(ctxt);
    }
    if (ctxt->config.list_rf_configs) {
        rail_print_config_list(ctxt);
        exit(0);
    }
}

static void wsbr_fds_init(struct wsbr_ctxt *ctxt, struct pollfd *fds)
{
    fds[POLLFD_DBUS].fd = dbus_get_fd(ctxt);
    fds[POLLFD_DBUS].events = POLLIN;
    fds[POLLFD_RCP].fd = ctxt->os_ctxt->trig_fd;
    fds[POLLFD_RCP].events = POLLIN;
    fds[POLLFD_TUN].fd = ctxt->tun_fd;
    fds[POLLFD_TUN].events = POLLIN;
    fds[POLLFD_EVENT].fd = ctxt->scheduler.event_fd[0];
    fds[POLLFD_EVENT].events = POLLIN;
    fds[POLLFD_TIMER].fd = ctxt->timerfd;
    fds[POLLFD_TIMER].events = POLLIN;
    fds[POLLFD_DHCP_SERVER].fd = ctxt->dhcp_server.fd;
    fds[POLLFD_DHCP_SERVER].events = POLLIN;
    fds[POLLFD_BR_EAPOL_RELAY].fd = ws_bbr_eapol_relay_get_socket_fd();
    fds[POLLFD_BR_EAPOL_RELAY].events = POLLIN;
    fds[POLLFD_EAPOL_RELAY].fd = ws_bbr_eapol_auth_relay_get_socket_fd();
    fds[POLLFD_EAPOL_RELAY].events = POLLIN;
    fds[POLLFD_PAE_AUTH].fd = kmp_socket_if_get_pae_socket_fd();
    fds[POLLFD_PAE_AUTH].events = POLLIN;
    fds[POLLFD_RADIUS].fd = kmp_socket_if_get_radius_sockfd();
    fds[POLLFD_RADIUS].events = POLLIN;
}

static void wsbr_poll(struct wsbr_ctxt *ctxt, struct pollfd *fds)
{
    uint64_t val;
    int ret;

    if (ctxt->os_ctxt->uart_next_frame_ready)
        ret = poll(fds, POLLFD_COUNT, 0);
    else
        ret = poll(fds, POLLFD_COUNT, -1);
    FATAL_ON(ret < 0, 2, "poll: %m");

    if (fds[POLLFD_DBUS].revents & POLLIN)
        dbus_process(ctxt);
    if (fds[POLLFD_DHCP_SERVER].revents & POLLIN)
        dhcp_recv(&ctxt->dhcp_server);
    if (fds[POLLFD_BR_EAPOL_RELAY].revents & POLLIN)
        ws_bbr_eapol_relay_socket_cb(fds[POLLFD_BR_EAPOL_RELAY].fd);
    if (fds[POLLFD_EAPOL_RELAY].revents & POLLIN)
        ws_bbr_eapol_auth_relay_socket_cb(fds[POLLFD_EAPOL_RELAY].fd);
    if (fds[POLLFD_PAE_AUTH].revents & POLLIN)
        kmp_socket_if_pae_socket_cb(fds[POLLFD_PAE_AUTH].fd);
    if (fds[POLLFD_RADIUS].revents & POLLIN)
        kmp_socket_if_radius_socket_cb(fds[POLLFD_RADIUS].fd);
    if (fds[POLLFD_TUN].revents & POLLIN)
        wsbr_tun_read(ctxt);
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

int wsbr_main(int argc, char *argv[])
{
    static const char *files[] = {
        "keys-*:*:*:*:*:*:*:*",
        "network-keys",
        "counters",
        "br-info",
        NULL,
    };
    struct wsbr_ctxt *ctxt = &g_ctxt;
    struct pollfd fds[POLLFD_COUNT];

    INFO("Silicon Labs Wi-SUN border router %s", version_daemon_str);
    signal(SIGINT, kill_handler);
    signal(SIGHUP, kill_handler);
    signal(SIGTERM, kill_handler);
    signal(SIGPIPE, SIG_IGN); // Handle writing to unread FIFO for pcapng capture
    parse_commandline(&ctxt->config, argc, argv, print_help_br);
    if (ctxt->config.color_output != -1)
        g_enable_color_traces = ctxt->config.color_output;
    wsbr_check_mbedtls_features();
    event_scheduler_init(&ctxt->scheduler);
    g_storage_prefix = ctxt->config.storage_prefix;
    if (ctxt->config.storage_delete)
        storage_delete(files);
    if (ctxt->config.pan_size >= 0)
        test_pan_size_override = ctxt->config.pan_size;
    if (ctxt->config.pcap_file[0])
        wsbr_pcapng_init(ctxt);
    if (ctxt->config.uart_dev[0]) {
        ctxt->rcp.device_tx = wsbr_uart_tx;
        ctxt->rcp.device_rx = uart_rx;
        ctxt->rcp.on_crc_error = uart_handle_crc_error;
        ctxt->os_ctxt->data_fd = uart_open(ctxt->config.uart_dev, ctxt->config.uart_baudrate, ctxt->config.uart_rtscts);
    } else if (ctxt->config.cpc_instance[0]) {
        ctxt->rcp.device_tx = cpc_tx;
        ctxt->rcp.device_rx = cpc_rx;
        ctxt->os_ctxt->data_fd = cpc_open(ctxt->os_ctxt, ctxt->config.cpc_instance, g_enabled_traces & TR_CPC);
    } else {
        BUG();
    }
    ctxt->os_ctxt->trig_fd = ctxt->os_ctxt->data_fd;

    rcp_noop();
    rcp_reset();
    wsbr_rcp_init(ctxt);
    wsbr_tun_init(ctxt);

    wsbr_common_timer_init(ctxt);

    if (net_init_core())
        BUG("net_init_core");

    ctxt->rcp_if_id = arm_nwk_interface_lowpan_init(&ctxt->rcp, ctxt->config.lowpan_mtu, "ws0");
    if (ctxt->rcp_if_id < 0)
        BUG("arm_nwk_interface_lowpan_init: %d", ctxt->rcp_if_id);

    wsbr_network_init(ctxt);
    event_scheduler_run_until_idle();

    dbus_register(ctxt);
    if (ctxt->config.user[0] && ctxt->config.group[0])
        drop_privileges(&ctxt->config);

    wsbr_fds_init(ctxt, fds);

    while (true)
        wsbr_poll(ctxt, fds);

    return 0;
}
