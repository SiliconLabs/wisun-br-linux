/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app_wsrd/app/commandline.h"
#include "app_wsrd/ipv6/ipv6_addr_mc.h"
#include "app_wsrd/app/join_state.h"
#include "app_wsrd/app/dbus.h"
#include "app_wsrd/app/ws.h"
#include "app_wsrd/ipv6/rpl.h"
#include "common/ws/eapol_relay.h"
#include "common/ws/ws_regdb.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/crypto/ws_keys.h"
#include "common/mbedtls_config_check.h"
#include "common/drop_privileges.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/ieee802154_frame.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/version.h"
#include "common/dbus.h"
#include "wsrd.h"

enum {
    POLLFD_RCP,
    POLLFD_TIMER,
    POLLFD_TUN,
    POLLFD_RPL,
    POLLFD_DHCP,
    POLLFD_EAPOL_RELAY,
    POLLFD_DBUS,
    POLLFD_COUNT,
};

static void wsrd_on_rcp_reset(struct rcp *rcp);
static void wsrd_on_etx_outdated(struct ws_neigh_table *table, struct ws_neigh *neigh);
static void wsrd_on_etx_update(struct ws_neigh_table *table, struct ws_neigh *neigh);
static int wsrd_ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const uint8_t dst[8]);
static void wsrd_eapol_sendto_mac(struct supp_ctx *supp, uint8_t kmp_id, const void *pkt,
                                  size_t pkt_len, const uint8_t dst[8]);
static uint8_t *wsrd_eapol_get_target(struct supp_ctx *supp);
static void wsrd_eapol_on_gtk_change(struct supp_ctx *supp, const uint8_t gtk[16], uint8_t index);
static void wsrd_eapol_on_failure(struct supp_ctx *supp);
static void wsrd_on_pref_parent_change(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh);
static void wsrd_on_dhcp_addr_add(struct dhcp_client *client);
static void wsrd_on_dhcp_addr_del(struct dhcp_client *client);
static struct in6_addr wsrd_dhcp_get_dst(struct dhcp_client *client);

static void wsrd_on_dao_ack(struct ipv6_ctx *ipv6)
{
    struct wsrd *wsrd = container_of(ipv6, struct wsrd, ipv6);

    join_state_transition(wsrd, WSRD_EVENT_ROUTING_SUCCESS);
}

struct wsrd g_wsrd = {
    .ws.rcp.bus.fd = -1,
    .ws.rcp.on_reset  = wsrd_on_rcp_reset,
    .ws.rcp.on_rx_ind = ws_if_recv_ind,
    .ws.rcp.on_tx_cnf = ws_if_recv_cnf,

    .ws.pan_id = 0xffff,
    .ws.pan_version = -1,
    .ws.neigh_table.on_etx_outdated = wsrd_on_etx_outdated,
    .ws.neigh_table.on_etx_update   = wsrd_on_etx_update,
    .ws.on_recv_ind                 = ws_on_recv_ind,
    .ws.on_recv_cnf                 = ws_on_recv_cnf,
    .ws.eapol_relay_fd = -1,
    .ipv6.sendto_mac = wsrd_ipv6_sendto_mac,
    .eapol_target_eui64 = IEEE802154_ADDR_BC_INIT,

    // Wi-SUN FAN 1.1v08 - 6.5.2.1.1 SUP Operation
    .supp.key_request_txalg.irt_s       =  300, //  5 * 60
    .supp.key_request_txalg.mrt_s       = 3600, // 60 * 60
    .supp.key_request_txalg.max_delay_s = 60, // Unspecified
    .supp.key_request_txalg.mrc         =  3, // Unspecified
    // RFC 8415 15. Reliability of Client-Initiated Message Exchanges
    .supp.key_request_txalg.rand_min    = -0.1,
    .supp.key_request_txalg.rand_max    = +0.1,
    .supp.on_gtk_change = wsrd_eapol_on_gtk_change,
    .supp.on_failure  = wsrd_eapol_on_failure,
    .supp.sendto_mac  = wsrd_eapol_sendto_mac,
    .supp.get_target  = wsrd_eapol_get_target,
    .supp.timeout_ms = 60 * 1000, // Arbitrary

    // Arbitrary default values
    .config.rcp_cfg.uart_baudrate = 115200,
    .config.tun_autoconf = true,
    .config.ws_domain = REG_DOMAIN_UNDEF,
    .config.ws_uc_dwell_interval_ms = 255,
    .config.ws_allowed_channels = { [0 ... sizeof(g_wsrd.config.ws_allowed_channels) - 1] = 0xff },
    .config.tx_power = 14,
    .config.color_output = -1,
    .config.ws_mac_address = IEEE802154_ADDR_BC_INIT,

    // Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
    .config.disc_cfg.Imin_ms = 15 * 1000,
    .config.disc_cfg.Imax_ms = TRICKLE_DOUBLINGS(15, 2) * 1000,
    .config.disc_cfg.k = 1,
    .pas_tkl.cfg = &g_wsrd.config.disc_cfg,
    .pas_tkl.debug_name  = "pas",
    .pas_tkl.on_transmit = ws_on_send_pas,
    .pas_tkl.on_interval_done = ws_on_pas_interval_done,
    .pcs_tkl.cfg         = &g_wsrd.config.disc_cfg,
    .pcs_tkl.debug_name  = "pcs",
    .pcs_tkl.on_transmit = ws_on_send_pcs,
    .pan_selection_timer.callback = ws_on_pan_selection_timer_timeout,

    // Arbitrary parameters
    .ipv6.rpl.dis_txalg.irt_s = 5,
    .ipv6.rpl.dis_txalg.mrt_s = 180,
    .ipv6.rpl.dis_txalg.rand_min = -0.1,
    .ipv6.rpl.dis_txalg.rand_max = +0.1,
    .ipv6.rpl.on_dao_ack = wsrd_on_dao_ack,
    // Wi-SUN FAN 1.1v09 6.2.1.1 Configuration Parameters
    .ipv6.rpl.dao_txalg.irt_s = 3,
    .ipv6.rpl.dao_txalg.mrc   = 3,
    .ipv6.rpl.dao_txalg.mrt_s = 0,
    .ipv6.rpl.dao_txalg.mrd_s = 0,
    .ipv6.rpl.dao_txalg.rand_min = -0.1,
    .ipv6.rpl.dao_txalg.rand_max = +0.1,
    // RFC 6719 5. MRHOF Variables and Parameters
    .ipv6.rpl.mrhof.max_link_metric         =   512, // 128 * 4
    .ipv6.rpl.mrhof.max_path_cost           = 32768, // 128 * 256
    .ipv6.rpl.mrhof.parent_switch_threshold =   192, // 128 * 1.5
    .ipv6.rpl.mrhof.ws_neigh_table = &g_wsrd.ws.neigh_table,
    .ipv6.rpl.mrhof.on_pref_parent_change = wsrd_on_pref_parent_change,

    // Wi-SUN FAN 1.1v08 - 6.2.3.1.2.1.2 Global and Unique Local Addresses
    .ipv6.dhcp.solicit_txalg.max_delay_s = 60,
    .ipv6.dhcp.solicit_txalg.irt_s       = 60,
    .ipv6.dhcp.solicit_txalg.mrt_s       = 3600,
    // RFC 8415 18.2.1. Creation and Transmission of Solicit Messages
    .ipv6.dhcp.solicit_txalg.mrc         = 0,
    .ipv6.dhcp.solicit_txalg.mrd_s       = 0,
    // RFC 8415 15. Reliability of Client-Initiated Message Exchanges
    .ipv6.dhcp.solicit_txalg.rand_min    = -0.1,
    .ipv6.dhcp.solicit_txalg.rand_max    = +0.1,
    .ipv6.dhcp.fd    = -1,
    .ipv6.dhcp.get_dst     = wsrd_dhcp_get_dst,
    .ipv6.dhcp.on_addr_add = wsrd_on_dhcp_addr_add,
    .ipv6.dhcp.on_addr_del = wsrd_on_dhcp_addr_del,

    // Arbitrary, same lifetime as MAC neighbors
    .ipv6.aro_lifetime_ms = WS_NEIGHBOR_LINK_TIMEOUT * 1000,
    // Arbitrary (default RETRANS_TIMER of 1s is not suited for Wi-SUN)
    .ipv6.probe_delay_ms =  5000,
    /*
     * RFC 4861 10. Protocol Constants
     * FIXME: BaseReachableTime and RetransTimer can be overritten by Router
     * Advertisements in normal NDP, but Wi-SUN disables RAs without providing
     * any sensible default values.
     */
    .ipv6.reach_base_ms  = 30000, // REACHABLE_TIME  30,000 milliseconds
};

static void wsrd_on_rcp_reset(struct rcp *rcp)
{
    if (rcp->has_rf_list)
        FATAL(3, "unsupported RCP reset");
    INFO("Connected to RCP \"%s\" (%d.%d.%d), API %d.%d.%d", rcp->version_label,
         FIELD_GET(0xFF000000, rcp->version_fw),
         FIELD_GET(0x00FFFF00, rcp->version_fw),
         FIELD_GET(0x000000FF, rcp->version_fw),
         FIELD_GET(0xFF000000, rcp->version_api),
         FIELD_GET(0x00FFFF00, rcp->version_api),
         FIELD_GET(0x000000FF, rcp->version_api));
    if (version_older_than(rcp->version_api, 2, 4, 0))
        FATAL(3, "RCP API < 2.4.0 (too old)");
}

static void wsrd_on_etx_outdated(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct wsrd *wsrd = container_of(table, struct wsrd, ws.neigh_table);
    struct ipv6_neigh *nce;

    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.6.1 Link Metrics
     * In the absence of other messaging, a Router SHOULD initiate NUD
     * messaging to refresh the ETX value for that neighbor.
     */
    nce = ipv6_neigh_get_from_eui64(&wsrd->ipv6, neigh->mac64);
    if (!nce)
        return;
    ipv6_nud_set_state(&wsrd->ipv6, nce, IPV6_NUD_PROBE);
}

static void wsrd_on_etx_update(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct wsrd *wsrd = container_of(table, struct wsrd, ws.neigh_table);
    struct ipv6_neigh *nce;

    nce = ipv6_neigh_get_from_eui64(&wsrd->ipv6, neigh->mac64);
    if (!nce || !nce->rpl)
        return;
    rpl_mrhof_select_parent(&wsrd->ipv6);
}

static int wsrd_ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const uint8_t dst[8])
{
    struct wsrd *wsrd = container_of(ipv6, struct wsrd, ipv6);

    return ws_if_send_data(&wsrd->ws, pktbuf_head(pktbuf), pktbuf_len(pktbuf), (struct eui64 *)dst);
}

static void wsrd_eapol_on_gtk_change(struct supp_ctx *supp, const uint8_t gtk[16], uint8_t index)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);
    uint8_t gak[16];

    // TODO: handle LGTK
    if (index > 4)
        return;
    if (gtk) {
        ws_generate_gak(wsrd->ws.netname, gtk, gak);
        rcp_set_sec_key(&wsrd->ws.rcp, index, gak, 0);
        join_state_transition(wsrd, WSRD_EVENT_AUTH_SUCCESS);
    } else {
        rcp_set_sec_key(&wsrd->ws.rcp, index, NULL, 0);
    }
    dbus_emit_change("Gaks");
}

static void wsrd_eapol_on_failure(struct supp_ctx *supp)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);

    join_state_transition(wsrd, WSRD_EVENT_AUTH_FAIL);
}

static void wsrd_eapol_sendto_mac(struct supp_ctx *supp, uint8_t kmp_id, const void *pkt,
                                  size_t pkt_len, const uint8_t dst[8])
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);

    ws_if_send_eapol(&wsrd->ws, kmp_id, pkt, pkt_len, (const struct eui64 *)dst, NULL);
}

static uint8_t *wsrd_eapol_get_target(struct supp_ctx *supp)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);

    return wsrd->eapol_target_eui64.u8;
}

static void wsrd_on_pref_parent_change(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh)
{
    struct wsrd *wsrd = container_of(mrhof, struct wsrd, ipv6.rpl.mrhof);

    if (neigh) {
        join_state_transition(wsrd, WSRD_EVENT_RPL_NEW_PREF_PARENT);
        /*
         *   Wi-SUN FAN 1.1v08 - 6.5.2.1.1 SUP Operation
         * A Router operating as a SUP MUST direct EAPOL frames to a node designated
         * as its EAPOL target. When a Router has determined a RPL parent, it shall
         * use that parent as the EAPOL target.
         */
        memcpy(&wsrd->eapol_target_eui64, neigh->eui64, 8);
    } else {
        wsrd->eapol_target_eui64 = ieee802154_addr_bc;
        // TODO: handle parent loss
        join_state_transition(wsrd, WSRD_EVENT_RPL_NO_CANDIDATE);
    }
}

static void wsrd_on_dhcp_addr_add(struct dhcp_client *client)
{
    struct wsrd *wsrd = container_of(client, struct wsrd, ipv6.dhcp);
    struct ipv6_neigh *parent = rpl_neigh_pref_parent(&wsrd->ipv6);

    BUG_ON(!parent);

    // TODO: set prefix len to 128, and add default route instead
    tun_addr_add(&wsrd->ipv6.tun, &client->iaaddr.ipv6, 64);
    ipv6_nud_set_state(&wsrd->ipv6, parent, IPV6_NUD_PROBE);
    // TODO: NS(ARO) error handling
}

static void wsrd_on_dhcp_addr_del(struct dhcp_client *client)
{
    struct ipv6_ctx *ipv6 = container_of(client, struct ipv6_ctx, dhcp);

    tun_addr_del(&ipv6->tun, &client->iaaddr.ipv6, 64);
    // TODO: send NS(ARO) with 0 lifetime
}

static struct in6_addr wsrd_dhcp_get_dst(struct dhcp_client *client)
{
    struct ipv6_ctx *ipv6 = container_of(client, struct ipv6_ctx, dhcp);
    struct ipv6_neigh *pref_parent = rpl_neigh_pref_parent(ipv6);
    struct in6_addr parent_ll = ipv6_prefix_linklocal;

    BUG_ON(!pref_parent);
    ipv6_addr_conv_iid_eui64(parent_ll.s6_addr + 8, pref_parent->eui64);
    return parent_ll;
}

void kill_handler(int signal)
{
    // Exit cleanly to dump coverage.
    exit(EXIT_SUCCESS);
}

void sig_error_handler(int signal)
{
    __PRINT(91, "bug: %s", strsignal(signal));
    backtrace_show();
    raise(signal);
}

static void wsrd_init_radio(struct wsrd *wsrd)
{
    const struct rcp_rail_config *rail_config;
    uint8_t chan_mask[WS_CHAN_MASK_LEN];
    struct chan_params *chan_params;

    wsrd->ws.phy.params = ws_regdb_phy_params(wsrd->config.ws_phy_mode_id,
                                              wsrd->config.ws_mode);
    BUG_ON(!wsrd->ws.phy.params);
    wsrd->ws.fhss.chan_params = ws_regdb_chan_params(wsrd->config.ws_domain,
                                                     wsrd->config.ws_chan_plan_id,
                                                     wsrd->config.ws_class);
    if (!wsrd->ws.fhss.chan_params) {
        chan_params = zalloc(sizeof(*chan_params));
        chan_params->reg_domain   = wsrd->config.ws_domain;
        chan_params->chan0_freq   = wsrd->config.ws_chan0_freq;
        chan_params->chan_spacing = wsrd->config.ws_chan_spacing;
        chan_params->chan_count   = wsrd->config.ws_chan_count;
        wsrd->ws.fhss.chan_params = chan_params;
        wsrd->ws.fhss.chan_plan = 1;
    } else {
        wsrd->ws.fhss.chan_plan = wsrd->config.ws_chan_plan_id ? 2 : 0;
    }
    wsrd->ws.fhss.uc_dwell_interval = wsrd->config.ws_uc_dwell_interval_ms;
    memcpy(wsrd->ws.fhss.uc_chan_mask, wsrd->config.ws_allowed_channels, sizeof(wsrd->ws.fhss.uc_chan_mask));

    for (rail_config = wsrd->ws.rcp.rail_config_list; rail_config->chan0_freq; rail_config++)
        if (rail_config->rail_phy_mode_id == wsrd->ws.phy.params->rail_phy_mode_id   &&
            rail_config->chan0_freq       == wsrd->ws.fhss.chan_params->chan0_freq   &&
            rail_config->chan_spacing     == wsrd->ws.fhss.chan_params->chan_spacing &&
            rail_config->chan_count       == wsrd->ws.fhss.chan_params->chan_count)
            break;
    if (!rail_config->chan0_freq)
        FATAL(2, "unsupported radio configuration (check --list-rf-configs)");
    rcp_set_radio_tx_power(&wsrd->ws.rcp, wsrd->config.tx_power);
    rcp_set_radio(&wsrd->ws.rcp, rail_config->index, wsrd->ws.phy.params->ofdm_mcs, false);
    wsrd->ws.phy.rcp_rail_config_index = rail_config->index;

    ws_chan_mask_calc_reg(chan_mask, wsrd->ws.fhss.chan_params, HIF_REG_NONE);
    bitand(chan_mask, wsrd->config.ws_allowed_channels, 256);
    if (!memzcmp(chan_mask, sizeof(chan_mask)))
        FATAL(1, "combination of allowed_channels and regulatory constraints results in no valid channel (see --list-rf-configs)");
    rcp_set_fhss_uc(&wsrd->ws.rcp, wsrd->config.ws_uc_dwell_interval_ms, chan_mask, NULL);
    rcp_set_fhss_async(&wsrd->ws.rcp, 500, chan_mask);

    rcp_req_radio_enable(&wsrd->ws.rcp);
}

static void wsrd_init_ipv6(struct wsrd *wsrd)
{
    struct in6_addr addr_linklocal = ipv6_prefix_linklocal;
    BUG_ON(!wsrd->ipv6.sendto_mac);

    strcpy(wsrd->ipv6.tun.ifname, wsrd->config.tun_dev);
    tun_init(&wsrd->ipv6.tun, wsrd->config.tun_autoconf);
    tun_sysctl_set("/proc/sys/net/ipv6/conf", wsrd->ipv6.tun.ifname, "accept_ra", '0');

    ipv6_addr_conv_iid_eui64(addr_linklocal.s6_addr + 8, wsrd->ws.rcp.eui64.u8);
    tun_addr_add(&wsrd->ipv6.tun, &addr_linklocal, 64);

    timer_group_init(&wsrd->ipv6.timer_group);

    rpl_start(&wsrd->ipv6);
    dhcp_client_init(&wsrd->ipv6.dhcp, &wsrd->ipv6.tun, wsrd->ws.rcp.eui64.u8);
    ipv6_addr_add_mc(&wsrd->ipv6, &ipv6_addr_all_nodes_link);     // ff02::1
    ipv6_addr_add_mc(&wsrd->ipv6, &ipv6_addr_all_routers_link);   // ff02::2
    ipv6_addr_add_mc(&wsrd->ipv6, &ipv6_addr_all_rpl_nodes_link); // ff02::1a
    ipv6_addr_add_mc(&wsrd->ipv6, &ipv6_addr_all_nodes_realm);    // ff03::1
    ipv6_addr_add_mc(&wsrd->ipv6, &ipv6_addr_all_routers_realm);  // ff03::2
    ipv6_addr_add_mc(&wsrd->ipv6, &ipv6_addr_all_mpl_fwd_realm);  // ff03::fc
}

static void wsrd_init_ws(struct wsrd *wsrd)
{
    strcpy(wsrd->ws.netname, wsrd->config.ws_netname);

    timer_group_init(&wsrd->ws.neigh_table.timer_group);
    trickle_init(&wsrd->pas_tkl);
    trickle_init(&wsrd->pcs_tkl);
    supp_init(&wsrd->supp, &wsrd->config.ca_cert, &wsrd->config.cert, &wsrd->config.key, wsrd->ws.rcp.eui64.u8);
    supp_reset(&wsrd->supp);
    join_state_1_enter(wsrd);
}

static void wsrd_eapol_relay_recv(struct wsrd *wsrd)
{
    struct eui64 supp_eui64;
    uint8_t buf[1500];
    ssize_t buf_len;
    uint8_t kmp_id;

    buf_len = eapol_relay_recv(wsrd->ws.eapol_relay_fd, buf, sizeof(buf),
                               NULL, &supp_eui64, &kmp_id);
    if (buf_len < 0)
        return;
    ws_if_send_eapol(&wsrd->ws, kmp_id, buf, buf_len, &supp_eui64,
                     (struct eui64 *)wsrd->supp.authenticator_eui64);
}

int wsrd_main(int argc, char *argv[])
{
    struct pollfd pfd[POLLFD_COUNT] = { };
    struct sigaction sigact = { };
    struct wsrd *wsrd = &g_wsrd;
    int ret;

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);
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

    parse_commandline(&wsrd->config, argc, argv);
    if (wsrd->config.color_output != -1)
        g_enable_color_traces = wsrd->config.color_output;

    check_mbedtls_features();

    rcp_init(&wsrd->ws.rcp, &wsrd->config.rcp_cfg);
    if (wsrd->config.list_rf_configs) {
        rail_print_config_list(&wsrd->ws.rcp);
        exit(0);
    }
    // NOTE: destination address filtering is enabled by default with the
    // native EUI-64.
    if (memcmp(&wsrd->config.ws_mac_address, &ieee802154_addr_bc, 8))
        rcp_set_filter_dst64(&wsrd->ws.rcp, wsrd->config.ws_mac_address.u8);
    memcpy(wsrd->ipv6.eui64, &wsrd->ws.rcp.eui64, 8);

    wsrd_init_radio(wsrd);
    wsrd_init_ws(wsrd);
    wsrd_init_ipv6(wsrd);
    dbus_register("com.silabs.Wisun.Router",
                  "/com/silabs/Wisun/Router",
                  "com.silabs.Wisun.Router",
                  wsrd_dbus_vtable, wsrd);

    if (wsrd->config.user[0] && wsrd->config.group[0])
        drop_privileges(wsrd->config.user, wsrd->config.group, true); // keep privileges to manage interface later

    INFO("Wi-SUN Router successfully started");

    pfd[POLLFD_RCP].fd = wsrd->ws.rcp.bus.fd;
    pfd[POLLFD_RCP].events = POLLIN;
    pfd[POLLFD_TIMER].fd = timer_fd();
    pfd[POLLFD_TIMER].events = POLLIN;
    pfd[POLLFD_TUN].fd = wsrd->ipv6.tun.fd;
    pfd[POLLFD_TUN].events = POLLIN;
    pfd[POLLFD_RPL].fd = wsrd->ipv6.rpl.fd;
    pfd[POLLFD_RPL].events = POLLIN;
    pfd[POLLFD_DHCP].fd = wsrd->ipv6.dhcp.fd;
    pfd[POLLFD_DHCP].events = POLLIN;
    pfd[POLLFD_DBUS].fd = dbus_get_fd();
    pfd[POLLFD_DBUS].events = POLLIN;
    pfd[POLLFD_EAPOL_RELAY].events = POLLIN;
    while (true) {
        pfd[POLLFD_EAPOL_RELAY].fd = wsrd->ws.eapol_relay_fd;
        ret = poll(pfd, POLLFD_COUNT, wsrd->ws.rcp.bus.uart.data_ready ? 0 : -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (wsrd->ws.rcp.bus.uart.data_ready ||
            pfd[POLLFD_RCP].revents & POLLIN)
            rcp_rx(&wsrd->ws.rcp);
        if (pfd[POLLFD_TIMER].revents & POLLIN)
            timer_process();
        if (pfd[POLLFD_TUN].revents & POLLIN)
            ipv6_recvfrom_tun(&wsrd->ipv6);
        if (pfd[POLLFD_RPL].revents & POLLIN)
            rpl_recv(&wsrd->ipv6);
        if (pfd[POLLFD_DHCP].revents & POLLIN)
            dhcp_client_recv(&wsrd->ipv6.dhcp);
        if (pfd[POLLFD_EAPOL_RELAY].revents & POLLIN)
            wsrd_eapol_relay_recv(wsrd);
        if (pfd[POLLFD_DBUS].revents & POLLIN)
            dbus_process();
    }
}
