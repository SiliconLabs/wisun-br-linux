/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#define _GNU_SOURCE
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "common/mbedtls_config_check.h"
#include "common/bus_uart.h"
#include "common/bus_cpc.h"
#include "common/capture.h"
#include "common/dbus.h"
#include "common/dhcp_server.h"
#include "common/events_scheduler.h"
#include "common/bus.h"
#include "common/ws_regdb.h"
#include "common/log.h"
#include "common/bits.h"
#include "common/mathutils.h"
#include "common/version.h"
#include "common/ws_regdb.h"
#include "common/ieee802154_frame.h"
#include "common/key_value_storage.h"
#include "common/drop_privileges.h"
#include "common/string_extra.h"
#include "common/specs/ws.h"
#include "common/rand.h"
#include "common/rcp_api.h"

#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "ws/ws_pan_info_storage.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_bootstrap_6lbr.h"
#include "ws/ws_common.h"
#include "ws/ws_llc.h"
#include "ws/ws_pae_controller.h"
#include "ws/ws_eapol_relay.h"
#include "ws/ws_config.h"
#include "ws/ws_eapol_auth_relay.h"
#include "net/timers.h"
#include "net/ns_address_internal.h"
#include "net/netaddr_types.h"
#include "net/protocol.h"
#include "rpl/rpl_glue.h"
#include "rpl/rpl_storage.h"
#include "rpl/rpl.h"
#include "rpl/rpl_lollipop.h"
#include "security/kmp/kmp_socket_if.h"
#include "app_wsbrd/mpl/mpl.h"

#include "commandline_values.h"
#include "commandline.h"
#include "wsbr_cfg.h"
#include "wsbr_mac.h"
#include "wsbr_pcapng.h"
#include "libwsbrd.h"
#include "wsbrd.h"
#include "rail_config.h"
#include "dbus.h"
#include "tun.h"

static void wsbr_handle_reset(struct rcp *rcp);
static void wsbr_rpl_target_add(struct rpl_root *root, struct rpl_target *target);
static void wsbr_rpl_target_del(struct rpl_root *root, struct rpl_target *target);
static void wsbr_rpl_target_update(struct rpl_root *root, struct rpl_target *target, bool updated_transit);

// See warning in wsbrd.h
struct wsbr_ctxt g_ctxt = {
    .scheduler.event_fd = { -1, -1 },

    .rcp.on_reset = wsbr_handle_reset,
    .rcp.on_tx_cnf = wsbr_tx_cnf,
    .rcp.on_rx_ind = wsbr_rx_ind,

    // avoid initializating to 0 = STDIN_FILENO
    .tun.fd = -1,
    .pcapng_fd = -1,
    .rcp.bus.fd = -1,
    .dhcp_server.fd = -1,
    .net_if.rpl_root.sockfd = -1,

    // Defined by Wi-SUN FAN 1.1v06 - 6.2.1.1 Configuration Parameters
    .net_if.rpl_root.dio_i_min        = 19,
    .net_if.rpl_root.dio_i_doublings  = 1,
    .net_if.rpl_root.dio_redundancy   = 0,
    .net_if.rpl_root.lifetime_unit_s  = 1200,
    .net_if.rpl_root.lifetime_s = 1200 * 6,
    .net_if.rpl_root.min_hop_rank_inc = 128,
    // Defined by Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    .net_if.rpl_root.pcs              = 7,

    .net_if.rpl_root.dodag_version_number = RPL_LOLLIPOP_INIT,
    .net_if.rpl_root.instance_id      = 0,
    .net_if.rpl_root.on_target_add    = wsbr_rpl_target_add,
    .net_if.rpl_root.on_target_del    = wsbr_rpl_target_del,
    .net_if.rpl_root.on_target_update = wsbr_rpl_target_update,

    .net_if.llc_random_early_detection.weight = RED_AVERAGE_WEIGHT_EIGHTH,
    .net_if.llc_random_early_detection.threshold_min = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN,
    .net_if.llc_random_early_detection.threshold_max = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX,
    .net_if.llc_random_early_detection.drop_max_probability = 100,

    .net_if.llc_eapol_random_early_detection.weight = RED_AVERAGE_WEIGHT_EIGHTH,
    .net_if.llc_eapol_random_early_detection.threshold_min = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN,
    .net_if.llc_eapol_random_early_detection.threshold_max = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX,
    .net_if.llc_eapol_random_early_detection.drop_max_probability = 100,

    .net_if.pae_random_early_detection.weight = RED_AVERAGE_WEIGHT_DISABLED,
    .net_if.pae_random_early_detection.threshold_min = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN,
    .net_if.pae_random_early_detection.threshold_max = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX,
    .net_if.pae_random_early_detection.drop_max_probability = 100,

    .net_if.ws_info.neighbor_storage.on_add = ws_bootstrap_neighbor_add_cb,
    .net_if.ws_info.neighbor_storage.on_del = ws_bootstrap_neighbor_del_cb,
    .net_if.ws_info.pan_information.pan_id = -1,
    .net_if.ws_info.fhss_config.bsi = -1,
};

static void wsbr_rpl_target_add(struct rpl_root *root, struct rpl_target *target)
{
    struct wsbr_ctxt *ctxt = container_of(root, struct wsbr_ctxt, net_if.rpl_root);

    ipv6_route_add_with_info(target->prefix,      // prefix
                             128,                 // prefix length
                             ctxt->net_if.id,     // interface id
                             in6addr_any.s6_addr, // next hop
                             ROUTE_RPL_DAO_SR,    // source
                             (void *)root,        // info
                             0,                   // source id
                             0xffffffff,          // lifetime
                             0);                  // pref
    tun_add_node_to_proxy_neightbl(&ctxt->net_if, target->prefix);
    tun_add_ipv6_direct_route(&ctxt->net_if, target->prefix);
}

static void wsbr_rpl_target_del(struct rpl_root *root, struct rpl_target *target)
{
    struct wsbr_ctxt *ctxt = container_of(root, struct wsbr_ctxt, net_if.rpl_root);

    ipv6_route_delete_with_info(target->prefix,      // prefix
                                128,                 // prefix length
                                ctxt->net_if.id,     // interface id
                                in6addr_any.s6_addr, // next hop
                                ROUTE_RPL_DAO_SR,    // source
                                (void *)root,        // info
                                0);                  // source id
    rpl_storage_del_target(root, target);
    dbus_emit_change("Nodes");
    dbus_emit_change("RoutingGraph");
}

static void wsbr_rpl_target_update(struct rpl_root *root, struct rpl_target *target, bool updated_transit)
{
    struct wsbr_ctxt *ctxt = container_of(root, struct wsbr_ctxt, net_if.rpl_root);
    struct ipv6_neighbour *neigh;
    bool is_neigh = false;

    rpl_storage_store_target(root, target);

    if (!updated_transit)
        return;

    dbus_emit_change("Nodes");
    dbus_emit_change("RoutingGraph");

    /*
     * HACK: Delete the neighbor cache entry in case the node did not
     * remove itself. Otherwise routing will choose an "ARO route" instead
     * of a "DAO route", which will fail until ARO expiration.
     */
    for (uint8_t i = 0; i < root->pcs + 1; i++)
        if (IN6_ARE_ADDR_EQUAL(target->transits[i].parent, root->dodag_id))
            is_neigh = true;
    if (!is_neigh) {
        neigh = ipv6_neighbour_lookup(&ctxt->net_if.ipv6_neighbour_cache, target->prefix);
        if (neigh)
            ipv6_neighbour_entry_remove(&ctxt->net_if.ipv6_neighbour_cache, neigh);
    }
}

static void ws_enable_mac_filtering(struct wsbr_ctxt *ctxt)
{
    BUG_ON(ctxt->config.ws_allowed_mac_address_count && ctxt->config.ws_denied_mac_address_count);
    if (!ctxt->config.ws_allowed_mac_address_count && !ctxt->config.ws_denied_mac_address_count)
        return;
    if (ctxt->config.ws_allowed_mac_address_count)
        rcp_set_filter_src64(&ctxt->rcp,
                             ctxt->config.ws_allowed_mac_addresses,
                             ctxt->config.ws_allowed_mac_address_count,
                             true);
    else
        rcp_set_filter_src64(&ctxt->rcp,
                             ctxt->config.ws_denied_mac_addresses,
                             ctxt->config.ws_denied_mac_address_count,
                             false);
}

static uint16_t wsbr_get_max_pan_size(uint8_t network_size)
{
    switch (network_size) {
    case WS_NETWORK_SIZE_CERTIFICATION:
    case WS_NETWORK_SIZE_SMALL:
        return 100;
    case WS_NETWORK_SIZE_MEDIUM:
        return 1000;
    case WS_NETWORK_SIZE_LARGE:
        return 10000;
    case WS_NETWORK_SIZE_XLARGE:
        return UINT16_MAX;
    default:
        BUG();
    }
}

static void wsbr_pae_controller_configure(struct wsbr_ctxt *ctxt)
{
    struct sec_timing timing_ffn = {
        .pmk_lifetime_s          = ctxt->config.ws_pmk_lifetime_s,
        .ptk_lifetime_s          = ctxt->config.ws_ptk_lifetime_s,
        .expire_offset           = ctxt->config.ws_gtk_expire_offset_s,
        .new_act_time            = ctxt->config.ws_gtk_new_activation_time,
        .new_install_req         = ctxt->config.ws_gtk_new_install_required,
        .revocat_lifetime_reduct = ctxt->config.ws_ffn_revocation_lifetime_reduction,
    };
    struct sec_timing timing_lfn = {
        .pmk_lifetime_s          = ctxt->config.ws_lpmk_lifetime_s,
        .ptk_lifetime_s          = ctxt->config.ws_lptk_lifetime_s,
        .expire_offset           = ctxt->config.ws_lgtk_expire_offset_s,
        .new_act_time            = ctxt->config.ws_lgtk_new_activation_time,
        .new_install_req         = ctxt->config.ws_lgtk_new_install_required,
        .revocat_lifetime_reduct = ctxt->config.ws_lfn_revocation_lifetime_reduction,
    };
    struct arm_certificate_entry tls_br = {
        .cert     = ctxt->config.br_cert.iov_base,
        .cert_len = ctxt->config.br_cert.iov_len,
        .key      = ctxt->config.br_key.iov_base,
        .key_len  = ctxt->config.br_key.iov_len,
    };
    struct arm_certificate_entry tls_ca = {
        .cert     = ctxt->config.ca_cert.iov_base,
        .cert_len = ctxt->config.ca_cert.iov_len,
    };
    uint8_t *lgtks[3] = { };
    bool lgtk_force = false;
    uint8_t *gtks[4] = { };
    bool gtk_force = false;
    int ret;

    ws_pae_controller_configure(&ctxt->net_if,
                                &timing_ffn, &timing_lfn,
                                &size_params[ctxt->config.ws_size].security_protocol_config);

    if (strlen(ctxt->config.radius_secret) != 0)
        if (ws_pae_controller_radius_shared_secret_set(ctxt->net_if.id, strlen(ctxt->config.radius_secret),
                                                       (uint8_t *)ctxt->config.radius_secret))
            WARN("ws_pae_controller_radius_shared_secret_set");
    if (ctxt->config.radius_server.ss_family != AF_UNSPEC)
        if (ws_pae_controller_radius_address_set(ctxt->net_if.id, &ctxt->config.radius_server))
            WARN("ws_pae_controller_radius_address_set");

    for (int i = 0; i < ARRAY_SIZE(ctxt->config.ws_gtk_force); i++) {
        if (ctxt->config.ws_gtk_force[i]) {
            gtk_force = true;
            gtks[i] = ctxt->config.ws_gtk[i];
        }
    }
    if (gtk_force) {
        ret = ws_pae_controller_gtk_update(ctxt->net_if.id, gtks);
        WARN_ON(ret);
    }
    for (int i = 0; i < ARRAY_SIZE(ctxt->config.ws_lgtk_force); i++) {
        if (ctxt->config.ws_lgtk_force[i]) {
            lgtk_force = true;
            lgtks[i] = ctxt->config.ws_lgtk[i];
        }
    }
    if (lgtk_force) {
        ret = ws_pae_controller_lgtk_update(ctxt->net_if.id, lgtks);
        WARN_ON(ret);
    }

    ret = ws_pae_controller_own_certificate_add(&tls_br);
    WARN_ON(ret);
    ret = ws_pae_controller_trusted_certificate_add(&tls_ca);
    WARN_ON(ret);
}

static void wsbr_configure_ws(struct wsbr_ctxt *ctxt)
{
    struct ws_info *ws_info = &ctxt->net_if.ws_info;
    struct ws_fhss_config *fhss = &ws_info->fhss_config;
    struct chan_params *chan_params;

    ws_info->phy_config.params = ws_regdb_phy_params(ctxt->config.ws_phy_mode_id,
                                                     ctxt->config.ws_mode);
    BUG_ON(!ws_info->phy_config.params);

    ws_info->pan_information.jm.mask = ctxt->config.ws_join_metrics;

    fhss->chan_params = ws_regdb_chan_params(ctxt->config.ws_domain,
                                             ctxt->config.ws_chan_plan_id,
                                             ctxt->config.ws_class);
    if (!fhss->chan_params) {
        chan_params = zalloc(sizeof(*fhss->chan_params));
        chan_params->reg_domain   = ctxt->config.ws_domain;
        chan_params->chan0_freq   = ctxt->config.ws_chan0_freq;
        chan_params->chan_spacing = ctxt->config.ws_chan_spacing;
        chan_params->chan_count   = ctxt->config.ws_chan_count;
        fhss->chan_params = chan_params;
        fhss->chan_plan = 1;
    } else if (ctxt->config.ws_chan_plan_id) {
        fhss->chan_plan = 2;
    } else {
        fhss->chan_plan = 0;
    }

    fhss->uc_dwell_interval  = ctxt->config.uc_dwell_interval;
    fhss->bc_dwell_interval  = ctxt->config.bc_dwell_interval;
    fhss->bc_interval        = ctxt->config.bc_interval;
    fhss->lfn_bc_interval    = ctxt->config.lfn_bc_interval;
    fhss->lfn_bc_sync_period = ctxt->config.lfn_bc_sync_period;

    if (ctxt->config.ws_regional_regulation) {
        fhss->regional_regulation = ctxt->config.ws_regional_regulation;
        rcp_set_radio_regulation(&ctxt->rcp, ctxt->config.ws_regional_regulation);
    }

    ws_chan_mask_calc_reg(fhss->uc_chan_mask, fhss->chan_params, fhss->regional_regulation);
    ws_chan_mask_calc_reg(fhss->bc_chan_mask, fhss->chan_params, fhss->regional_regulation);
    bitand(fhss->uc_chan_mask, ctxt->config.ws_allowed_channels, 256);
    bitand(fhss->bc_chan_mask, ctxt->config.ws_allowed_channels, 256);
    if (!memzcmp(fhss->uc_chan_mask, sizeof(fhss->uc_chan_mask)))
        FATAL(1, "combination of allowed_channels and regulatory constraints results in no valid channel (see --list-rf-configs)");

    rail_fill_pom(ctxt);

    g_timers[WS_TIMER_LTS].period_ms =
        rounddown(ctxt->config.lfn_bc_interval * ctxt->config.lfn_bc_sync_period, WS_TIMER_GLOBAL_PERIOD_MS);
    fhss->async_frag_duration_ms = ctxt->config.ws_async_frag_duration;

    ws_pan_info_storage_read(&fhss->bsi, &ws_info->pan_information.pan_id,
                             &ws_info->pan_information.pan_version,
                             &ws_info->pan_information.lfn_version,
                             ws_info->network_name);

    if (memzcmp(ws_info->network_name, sizeof(ws_info->network_name)) &&
        strcmp(ws_info->network_name, ctxt->config.ws_name))
        FATAL(1, "Network Name out-of-date in storage (see -D)");
    strncpy(ws_info->network_name, ctxt->config.ws_name, sizeof(ws_info->network_name));

    if (ctxt->config.ws_pan_id != -1 && ws_info->pan_information.pan_id != -1 &&
        ws_info->pan_information.pan_id != ctxt->config.ws_pan_id)
        FATAL(1, "PAN_ID out-of-date in storage (see -D)");
    if (ws_info->pan_information.pan_id == -1)
        ws_info->pan_information.pan_id = ctxt->config.ws_pan_id;
    if (ws_info->pan_information.pan_id == -1)
        ws_info->pan_information.pan_id = rand_get_random_in_range(0, 0xfffe);
    if (fhss->bsi == -1)
        fhss->bsi = rand_get_random_in_range(0, 0xffff);

    BUG_ON(ctxt->config.ws_size >= ARRAY_SIZE(size_params));
    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.8 Multicast Forwarding
     * For networks operating only with FAN 1.1 nodes, it is RECOMMENDED to set
     * the S field to 0 and elide the seed-id field (source address is the FFN
     * seed address). Otherwise by default, the S field value MUST be set to 3
     * with the seed-id field set to the GUA\ULA of the FFN seed (this for
     * backwards compatibility with FAN 1.0).
     */
    ctxt->net_if.mpl_domain = mpl_domain_create(&ctxt->net_if, ADDR_ALL_MPL_FORWARDERS,
                                                size_params[ctxt->config.ws_size].mpl_seed_set_entry_lifetime,
                                                ctxt->config.enable_ffn10 ? MPL_SEED_128_BIT : MPL_SEED_IPV6_SRC,
                                                &size_params[ctxt->config.ws_size].trickle_mpl);
    ws_info->mngt.trickle_params = size_params[ctxt->config.ws_size].trickle_discovery;

    ws_info->pan_information.version = ctxt->config.ws_fan_version;
    ws_info->pan_information.max_pan_size = wsbr_get_max_pan_size(ctxt->config.ws_size);
    ws_info->pan_information.test_pan_size = ctxt->config.pan_size;
    ws_info->enable_lfn   = ctxt->config.enable_lfn;
    ws_info->enable_ffn10 = ctxt->config.enable_ffn10;

    rcp_set_radio_tx_power(&ctxt->rcp, ctxt->config.tx_power);
    ws_info->tx_power_dbm = ctxt->config.tx_power;

    wsbr_pae_controller_configure(ctxt);

    ws_enable_mac_filtering(ctxt);

    timer_group_init(&ws_info->neighbor_storage.timer_group);
}

static void wsbr_check_link_local_addr(struct wsbr_ctxt *ctxt)
{
    struct in6_addr addr_tun;
    uint8_t addr_ws0[16];
    int ret;
    bool cmp;

    ret = tun_addr_get_linklocal(&ctxt->tun, &addr_tun);
    FATAL_ON(ret < 0, 1, "no link-local address found on %s", ctxt->tun.ifname);

    addr_interface_get_ll_address(&ctxt->net_if, addr_ws0, 0);

    cmp = memcmp(addr_ws0, addr_tun.s6_addr, 16);
    FATAL_ON(cmp, 1, "address mismatch: expected %s but found %s on %s",
             tr_ipv6(addr_ws0), tr_ipv6(addr_tun.s6_addr), ctxt->tun.ifname);
}

static void wsbr_network_init(struct wsbr_ctxt *ctxt)
{
    struct in6_addr gua;
    int ret;

    protocol_core_init();
    address_module_init();
    protocol_init(&ctxt->net_if, &ctxt->rcp, ctxt->config.lowpan_mtu);
    ws_bootstrap_init(ctxt->net_if.id);

    wsbr_configure_ws(ctxt);
    ret = tun_addr_get_uc_global(&ctxt->tun, &gua);
    FATAL_ON(ret < 0, 1, "no GUA found on %s", ctxt->tun.ifname);

    ws_bootstrap_up(&ctxt->net_if, gua.s6_addr);
    wsbr_check_link_local_addr(ctxt);
    if (ctxt->config.internal_dhcp)
        dhcp_start(&ctxt->dhcp_server, ctxt->tun.ifname, ctxt->rcp.eui64.u8, gua.s6_addr);

    memcpy(ctxt->net_if.rpl_root.dodag_id, gua.s6_addr, 16);
    rpl_storage_load(&ctxt->net_if.rpl_root);
    ctxt->net_if.rpl_root.compat = ctxt->config.rpl_compat;
    ctxt->net_if.rpl_root.rpi_ignorable = ctxt->config.rpl_rpi_ignorable;
    if (ctxt->net_if.rpl_root.instance_id || memcmp(ctxt->net_if.rpl_root.dodag_id, gua.s6_addr, 16))
        FATAL(1, "RPL storage out-of-date (see -D)");
    if (ctxt->config.ws_size == WS_NETWORK_SIZE_SMALL ||
        ctxt->config.ws_size == WS_NETWORK_SIZE_CERTIFICATION) {
        ctxt->net_if.rpl_root.dio_i_min       = 15; // min interval 32s
        ctxt->net_if.rpl_root.dio_i_doublings = 2;  // max interval 131s with default large Imin
    }
    rpl_glue_init(&ctxt->net_if);
    rpl_start(&ctxt->net_if.rpl_root, ctxt->tun.ifname);
    rpl_storage_store_config(&ctxt->net_if.rpl_root);
}

static void wsbr_handle_reset(struct rcp *rcp)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);

    if (ctxt->rcp.has_rf_list)
        FATAL(3, "unsupported RCP reset");
    INFO("Connected to RCP \"%s\" (%d.%d.%d), API %d.%d.%d", ctxt->rcp.version_label,
          FIELD_GET(0xFF000000, ctxt->rcp.version_fw),
          FIELD_GET(0x00FFFF00, ctxt->rcp.version_fw),
          FIELD_GET(0x000000FF, ctxt->rcp.version_fw),
          FIELD_GET(0xFF000000, ctxt->rcp.version_api),
          FIELD_GET(0x00FFFF00, ctxt->rcp.version_api),
          FIELD_GET(0x000000FF, ctxt->rcp.version_api));
    if (version_older_than(ctxt->rcp.version_api, 2, 0, 0))
        FATAL(3, "RCP API < 2.0.0 (too old)");
}

void kill_handler(int signal)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    if (ctxt->config.rcp_cfg.uart_dev[0])
        uart_tx_flush(&ctxt->rcp.bus);
    exit(0);
}

void sig_error_handler(int signal)
{
     __PRINT(91, "bug: %s", strsignal(signal));
    backtrace_show();
    raise(signal);
}

static void wsbr_fds_init(struct wsbr_ctxt *ctxt)
{
    ctxt->fds[POLLFD_DBUS].fd = dbus_get_fd();
    ctxt->fds[POLLFD_DBUS].events = POLLIN;
    ctxt->fds[POLLFD_RCP].fd = ctxt->rcp.bus.fd;
    ctxt->fds[POLLFD_RCP].events = POLLIN;
    ctxt->fds[POLLFD_TUN].fd = ctxt->tun.fd;
    ctxt->fds[POLLFD_TUN].events = 0;
    ctxt->fds[POLLFD_EVENT].fd = ctxt->scheduler.event_fd[0];
    ctxt->fds[POLLFD_EVENT].events = POLLIN;
    ctxt->fds[POLLFD_TIMER].fd = timer_fd();
    ctxt->fds[POLLFD_TIMER].events = POLLIN;
    ctxt->fds[POLLFD_DHCP_SERVER].fd = ctxt->dhcp_server.fd;
    ctxt->fds[POLLFD_DHCP_SERVER].events = POLLIN;
    ctxt->fds[POLLFD_RPL].fd = ctxt->net_if.rpl_root.sockfd;
    ctxt->fds[POLLFD_RPL].events = POLLIN;
    ctxt->fds[POLLFD_BR_EAPOL_RELAY].fd = ws_eapol_relay_get_socket_fd();
    ctxt->fds[POLLFD_BR_EAPOL_RELAY].events = POLLIN;
    ctxt->fds[POLLFD_EAPOL_RELAY].fd = ws_eapol_auth_relay_get_socket_fd();
    ctxt->fds[POLLFD_EAPOL_RELAY].events = POLLIN;
    ctxt->fds[POLLFD_PAE_AUTH].fd = kmp_socket_if_get_pae_socket_fd();
    ctxt->fds[POLLFD_PAE_AUTH].events = POLLIN;
    ctxt->fds[POLLFD_RADIUS].fd = kmp_socket_if_get_radius_sockfd();
    ctxt->fds[POLLFD_RADIUS].events = POLLIN;
}

static void wsbr_poll(struct wsbr_ctxt *ctxt)
{
    uint64_t val;
    int ret;

    if (lowpan_adaptation_queue_size(ctxt->net_if.id) > 2)
        ctxt->fds[POLLFD_TUN].events = 0;
    else
        ctxt->fds[POLLFD_TUN].events = POLLIN;

    if (ctxt->rcp.bus.uart.data_ready)
        ret = poll(ctxt->fds, POLLFD_COUNT, 0);
    else
        ret = poll(ctxt->fds, POLLFD_COUNT, -1);
    FATAL_ON(ret < 0, 2, "poll: %m");

    if (ctxt->fds[POLLFD_DBUS].revents & POLLIN)
        dbus_process();
    if (ctxt->fds[POLLFD_DHCP_SERVER].revents & POLLIN)
        dhcp_recv(&ctxt->dhcp_server);
    if (ctxt->fds[POLLFD_RPL].revents & POLLIN)
        rpl_recv(&ctxt->net_if.rpl_root);
    if (ctxt->fds[POLLFD_BR_EAPOL_RELAY].revents & POLLIN)
        ws_eapol_relay_socket_cb(ctxt->fds[POLLFD_BR_EAPOL_RELAY].fd);
    if (ctxt->fds[POLLFD_EAPOL_RELAY].revents & POLLIN)
        ws_eapol_auth_relay_socket_cb(ctxt->fds[POLLFD_EAPOL_RELAY].fd);
    if (ctxt->fds[POLLFD_PAE_AUTH].revents & POLLIN)
        kmp_socket_if_pae_socket_cb(ctxt->fds[POLLFD_PAE_AUTH].fd);
    if (ctxt->fds[POLLFD_RADIUS].revents & POLLIN)
        kmp_socket_if_radius_socket_cb(ctxt->fds[POLLFD_RADIUS].fd);
    if (ctxt->fds[POLLFD_TUN].revents & POLLIN)
        wsbr_tun_read(ctxt);
    if (ctxt->fds[POLLFD_EVENT].revents & POLLIN) {
        read(ctxt->scheduler.event_fd[0], &val, sizeof(val));
        WARN_ON(val != 'W');
        event_scheduler_run_until_idle();
    }
    if (ctxt->fds[POLLFD_RCP].revents & POLLIN ||
        ctxt->fds[POLLFD_RCP].revents & POLLERR ||
        ctxt->rcp.bus.uart.data_ready)
        rcp_rx(&ctxt->rcp);
    if (ctxt->fds[POLLFD_TIMER].revents & POLLIN)
        timer_process();
    if (ctxt->fds[POLLFD_PCAP].revents & POLLERR)
        wsbr_pcapng_closed(ctxt);
}

int wsbr_main(int argc, char *argv[])
{
    struct sigaction sigact = { };
    static const char *files[] = {
        "neighbor-*:*:*:*:*:*:*:*",
        "keys-*:*:*:*:*:*:*:*",
        "network-keys",
        "br-info",
        "rpl-*",
        NULL,
    };
    struct wsbr_ctxt *ctxt = &g_ctxt;

    INFO("Silicon Labs Wi-SUN border router %s", version_daemon_str);
    sigact.sa_flags = SA_RESETHAND;
    sigact.sa_handler = kill_handler;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigact.sa_handler = sig_error_handler;
    sigaction(SIGILL, &sigact, NULL);
    sigaction(SIGSEGV, &sigact, NULL);
    sigaction(SIGBUS, &sigact, NULL);
    sigaction(SIGFPE, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);
    sigact.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sigact, NULL); // Handle writing to unread FIFO for pcapng capture
    parse_commandline(&ctxt->config, argc, argv, print_help_br);
    if (ctxt->config.color_output != -1)
        g_enable_color_traces = ctxt->config.color_output;
    check_mbedtls_features();
    event_scheduler_init(&ctxt->scheduler);
    g_storage_prefix = ctxt->config.storage_prefix;
    if (ctxt->config.storage_delete) {
        INFO("deleting storage");
        storage_delete(files);
    }
    if (ctxt->config.storage_exit)
        exit(0);
    if (ctxt->config.pcap_file[0])
        wsbr_pcapng_init(ctxt);
    if (ctxt->config.capture[0])
        capture_start(ctxt->config.capture);

    rcp_init(&ctxt->rcp, &ctxt->config.rcp_cfg);
    if (ctxt->config.list_rf_configs) {
        rail_print_config_list(&ctxt->rcp);
        exit(0);
    }
    // NOTE: destination address filtering is enabled by default with the
    // native EUI-64.
    if (memcmp(ctxt->config.ws_mac_address, &ieee802154_addr_bc, 8))
        rcp_set_filter_dst64(&ctxt->rcp, ctxt->config.ws_mac_address);

    wsbr_tun_init(ctxt);
    ctxt->timer_legacy.period_ms = WS_TIMER_GLOBAL_PERIOD_MS;
    ctxt->timer_legacy.callback  = ws_timer_cb;
    timer_start_rel(NULL, &ctxt->timer_legacy, WS_TIMER_GLOBAL_PERIOD_MS);
    wsbr_network_init(ctxt);
    dbus_register("com.silabs.Wisun.BorderRouter",
                  "/com/silabs/Wisun/BorderRouter",
                  "com.silabs.Wisun.BorderRouter",
                  wsbrd_dbus_vtable, ctxt);
    if (ctxt->config.user[0] && ctxt->config.group[0])
        drop_privileges(ctxt->config.user, ctxt->config.group, ctxt->config.neighbor_proxy[0]);
    // FIXME: This call should be made in wsbr_configure_ws() but we cannot do
    // so because of privileges
    ws_pan_info_storage_write(ctxt->net_if.ws_info.fhss_config.bsi, ctxt->net_if.ws_info.pan_information.pan_id,
                              ctxt->net_if.ws_info.pan_information.pan_version,
                              ctxt->net_if.ws_info.pan_information.lfn_version, ctxt->net_if.ws_info.network_name);
    ws_bootstrap_6lbr_init(&ctxt->net_if);
    wsbr_fds_init(ctxt);

    INFO("Wi-SUN Border Router is ready");

    while (true)
        wsbr_poll(ctxt);

    return 0;
}
