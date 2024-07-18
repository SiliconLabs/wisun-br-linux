/*
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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app_wsrd/app/commandline.h"
#include "app_wsrd/ipv6/ipv6_addr.h"
#include "app_wsrd/app/dbus.h"
#include "app_wsrd/ipv6/rpl.h"
#include "app_wsrd/ws/ws.h"
#include "common/crypto/ws_keys.h"
#include "common/mbedtls_config_check.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/ieee802154_frame.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/version.h"
#include "common/ws_regdb.h"
#include "common/dbus.h"
#include "wsrd.h"

enum {
    POLLFD_RCP,
    POLLFD_TIMER,
    POLLFD_TUN,
    POLLFD_RPL,
    POLLFD_DHCP,
    POLLFD_DBUS,
    POLLFD_COUNT,
};

static void wsrd_on_rcp_reset(struct rcp *rcp);
static void wsrd_on_rcp_rx_ind(struct rcp *rcp, const struct rcp_rx_ind *ind);
static void wsrd_on_rcp_tx_cnf(struct rcp *rcp, const struct rcp_tx_cnf *cnf);
static void wsrd_on_etx_outdated(struct ws_neigh_table *table, struct ws_neigh *neigh);
static void wsrd_on_etx_update(struct ws_neigh_table *table, struct ws_neigh *neigh);
static int wsrd_ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const uint8_t dst[8]);
static void wsrd_eapol_sendto_mac(struct supplicant_ctx *supp, uint8_t kmp_id, const void *pkt,
                                  size_t pkt_len, const uint8_t dst[8]);
static uint8_t *wsrd_eapol_get_target(struct supplicant_ctx *supp);
static void wsrd_eapol_on_gtk_success(struct supplicant_ctx *supp, const uint8_t gtk[16], uint8_t index);
static void wsrd_eapol_on_failure(struct supplicant_ctx *supp);
static void wsrd_on_pref_parent_change(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh);
static void wsrd_on_dhcp_addr_add(struct dhcp_client *client, const struct in6_addr *addr,
                                  uint32_t valid_lifetime_s, uint32_t preferred_lifetime_s);
static void wsrd_on_dhcp_addr_del(struct dhcp_client *client, const struct in6_addr *addr);
static struct in6_addr wsrd_dhcp_get_dst(struct dhcp_client *client);

struct wsrd g_wsrd = {
    .rcp.bus.fd = -1,
    .rcp.on_reset  = wsrd_on_rcp_reset,
    .rcp.on_rx_ind = wsrd_on_rcp_rx_ind,
    .rcp.on_tx_cnf = wsrd_on_rcp_tx_cnf,

    .ws.pan_id = 0xffff,
    .ws.pan_version = -1,
    .ws.neigh_table.on_etx_outdated = wsrd_on_etx_outdated,
    .ws.neigh_table.on_etx_update   = wsrd_on_etx_update,
    .ws.ipv6.sendto_mac = wsrd_ipv6_sendto_mac,
    .ws.eapol_target_eui64[0 ... 7] = 0xff,

    // Wi-SUN FAN 1.1v08 - 6.5.2.1.1 SUP Operation
    .ws.supp.key_request_txalg.irt_s       =  300, //  5 * 60
    .ws.supp.key_request_txalg.mrt_s       = 3600, // 60 * 60
    .ws.supp.key_request_txalg.max_delay_s = 60, // Unspecified
    .ws.supp.key_request_txalg.mrc         =  3, // Unspecified
    // RFC 8415 15. Reliability of Client-Initiated Message Exchanges
    .ws.supp.key_request_txalg.rand_min    = -0.1,
    .ws.supp.key_request_txalg.rand_max    = +0.1,
    .ws.supp.on_gtk_success = wsrd_eapol_on_gtk_success,
    .ws.supp.on_failure  = wsrd_eapol_on_failure,
    .ws.supp.sendto_mac  = wsrd_eapol_sendto_mac,
    .ws.supp.get_target  = wsrd_eapol_get_target,

    // Wi-SUN FAN 1.1v08 6.2.1.1 Configuration Parameters
    .ws.ipv6.rpl.dao_txalg.irt_s = 3,
    .ws.ipv6.rpl.dao_txalg.mrc   = 3,
    .ws.ipv6.rpl.dao_txalg.mrt_s = 0,
    .ws.ipv6.rpl.dao_txalg.mrd_s = 0,
    .ws.ipv6.rpl.dao_txalg.rand_min = -0.5,
    .ws.ipv6.rpl.dao_txalg.rand_max =  0.0,
    // RFC 6719 5. MRHOF Variables and Parameters
    .ws.ipv6.rpl.mrhof.max_link_metric         =   512, // 128 * 4
    .ws.ipv6.rpl.mrhof.max_path_cost           = 32768, // 128 * 256
    .ws.ipv6.rpl.mrhof.parent_switch_threshold =   192, // 128 * 1.5
    .ws.ipv6.rpl.mrhof.ws_neigh_table = &g_wsrd.ws.neigh_table,
    .ws.ipv6.rpl.mrhof.on_pref_parent_change = wsrd_on_pref_parent_change,

    // Wi-SUN FAN 1.1v08 - 6.2.3.1.2.1.2 Global and Unique Local Addresses
    .dhcp.solicit_txalg.max_delay_s = 60,
    .dhcp.solicit_txalg.irt_s       = 60,
    .dhcp.solicit_txalg.mrt_s       = 3600,
    // RFC 8415 18.2.1. Creation and Transmission of Solicit Messages
    .dhcp.solicit_txalg.mrc         = 0,
    .dhcp.solicit_txalg.mrd_s       = 0,
    // RFC 8415 15. Reliability of Client-Initiated Message Exchanges
    .dhcp.solicit_txalg.rand_min    = -0.1,
    .dhcp.solicit_txalg.rand_max    = +0.1,
    .dhcp.fd    = -1,
    .dhcp.get_dst     = wsrd_dhcp_get_dst,
    .dhcp.on_addr_add = wsrd_on_dhcp_addr_add,
    .dhcp.on_addr_del = wsrd_on_dhcp_addr_del,
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
    if (version_older_than(rcp->version_api, 2, 3, 0))
        FATAL(3, "RCP API < 2.3.0 (too old)");
}

static void wsrd_on_rcp_rx_ind(struct rcp *rcp, const struct rcp_rx_ind *ind)
{
    struct wsrd *wsrd = container_of(rcp, struct wsrd, rcp);

    ws_recv_ind(&wsrd->ws, ind);
}

static void wsrd_on_rcp_tx_cnf(struct rcp *rcp, const struct rcp_tx_cnf *cnf)
{
    struct wsrd *wsrd = container_of(rcp, struct wsrd, rcp);

    ws_recv_cnf(&wsrd->ws, cnf);
}

static void wsrd_on_etx_outdated(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct ws_ctx *ws = container_of(table, struct ws_ctx, neigh_table);
    struct ipv6_neigh *nce;

    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.6.1 Link Metrics
     * In the absence of other messaging, a Router SHOULD initiate NUD
     * messaging to refresh the ETX value for that neighbor.
     */
    nce = ipv6_neigh_get_from_eui64(&ws->ipv6, neigh->mac64);
    if (!nce)
        return;
    ipv6_nud_set_state(&ws->ipv6, nce, IPV6_NUD_PROBE);
}

static void wsrd_on_etx_update(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct ws_ctx *ws = container_of(table, struct ws_ctx, neigh_table);
    struct ipv6_neigh *nce;

    nce = ipv6_neigh_get_from_eui64(&ws->ipv6, neigh->mac64);
    if (!nce || !nce->rpl)
        return;
    rpl_mrhof_select_parent(&ws->ipv6);
}

static int wsrd_ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const uint8_t dst[8])
{
    struct ws_ctx *ws = container_of(ipv6, struct ws_ctx, ipv6);

    return ws_send_data(ws, pktbuf_head(pktbuf), pktbuf_len(pktbuf), dst);
}

static void wsrd_eapol_on_gtk_success(struct supplicant_ctx *supp, const uint8_t gtk[16], uint8_t index)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, ws.supp);
    uint8_t gak[16];

    // TODO: handle LGTK
    if (index > 4)
        return;
    ws_generate_gak(wsrd->config.ws_netname, gtk, gak);
    wsrd->ws.gak_index = index;
    DEBUG("install key=%s key-idx=%u", tr_key(gak, 16), wsrd->ws.gak_index);
    rcp_set_sec_key(&wsrd->rcp, wsrd->ws.gak_index, gak, 0);
}

static void wsrd_eapol_on_failure(struct supplicant_ctx *supp)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, ws.supp);

    supp_stop(supp);
    memset(wsrd->ws.eapol_target_eui64, 0xff, sizeof(wsrd->ws.eapol_target_eui64));
}

static void wsrd_eapol_sendto_mac(struct supplicant_ctx *supp, uint8_t kmp_id, const void *pkt,
                                  size_t pkt_len, const uint8_t dst[8])
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, ws.supp);

    ws_send_eapol(&wsrd->ws, kmp_id, pkt, pkt_len, dst);
}

static uint8_t *wsrd_eapol_get_target(struct supplicant_ctx *supp)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, ws.supp);

    return wsrd->ws.eapol_target_eui64;
}

static void wsrd_on_pref_parent_change(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh)
{
    struct wsrd *wsrd = container_of(mrhof, struct wsrd, ws.ipv6.rpl.mrhof);

    if (IN6_IS_ADDR_UNSPECIFIED(&wsrd->ws.ipv6.addr_uc_global) && !wsrd->dhcp.running) {
        dhcp_client_start(&wsrd->dhcp);
    } else if (neigh) {
        rpl_start_dao(&wsrd->ws.ipv6);
        /*
         *   Wi-SUN FAN 1.1v08 - 6.5.2.1.1 SUP Operation
         * A Router operating as a SUP MUST direct EAPOL frames to a node designated
         * as its EAPOL target. When a Router has determined a RPL parent, it shall
         * use that parent as the EAPOL target.
         */
        memcpy(wsrd->ws.eapol_target_eui64, neigh->eui64, sizeof(wsrd->ws.eapol_target_eui64));
    } else {
        memset(wsrd->ws.eapol_target_eui64, 0xff, sizeof(wsrd->ws.eapol_target_eui64));
        // TODO: handle parent loss
    }
}

static void wsrd_on_dhcp_addr_add(struct dhcp_client *client, const struct in6_addr *addr, uint32_t valid_lifetime_s, uint32_t preferred_lifetime_s)
{
    struct wsrd *wsrd = container_of(client, struct wsrd, dhcp);
    struct ipv6_neigh *pref_parent = rpl_neigh_pref_parent(&wsrd->ws.ipv6);

    BUG_ON(!pref_parent);
    if (!IN6_IS_ADDR_UNSPECIFIED(&wsrd->ws.ipv6.addr_uc_global))
        return;

    // TODO: set prefix len to 128, and add default route instead
    wsrd->ws.ipv6.addr_uc_global = *addr;
    tun_addr_add(&wsrd->ws.ipv6.tun, &wsrd->ws.ipv6.addr_uc_global, 64);
    ipv6_nud_set_state(&wsrd->ws.ipv6, pref_parent, IPV6_NUD_PROBE);
    // TODO: NS(ARO) error handling

    // HACK: Wait for GUA to be registered by Linux, otherwise it may send
    // the DAO with a link-local address.
    usleep(100000);

    rpl_start_dao(&wsrd->ws.ipv6);
}

static void wsrd_on_dhcp_addr_del(struct dhcp_client *client, const struct in6_addr *addr)
{
    struct wsrd *wsrd = container_of(client, struct wsrd, dhcp);

    tun_addr_del(&wsrd->ws.ipv6.tun, &wsrd->ws.ipv6.addr_uc_global, 64);
    memset(&wsrd->ws.ipv6.addr_uc_global, 0, sizeof(wsrd->ws.ipv6.addr_uc_global));
    // TODO: send NS(ARO) with 0 lifetime
}

static struct in6_addr wsrd_dhcp_get_dst(struct dhcp_client *client)
{
    struct wsrd *wsrd = container_of(client, struct wsrd, dhcp);
    struct ipv6_neigh *pref_parent = rpl_neigh_pref_parent(&wsrd->ws.ipv6);
    struct in6_addr parent_ll = ipv6_prefix_linklocal;

    BUG_ON(!pref_parent);
    ipv6_addr_conv_iid_eui64(parent_ll.s6_addr + 8, pref_parent->eui64);
    return parent_ll;
}

static void wsrd_init_rcp(struct wsrd *wsrd)
{
    struct pollfd pfd = { };
    int ret;

    if (wsrd->config.uart_dev[0]) {
        wsrd->rcp.bus.fd = uart_open(wsrd->config.uart_dev, wsrd->config.uart_baudrate, wsrd->config.uart_rtscts);
        wsrd->rcp.version_api = VERSION(2, 0, 0); // default assumed version
        wsrd->rcp.bus.tx = uart_tx;
        wsrd->rcp.bus.rx = uart_rx;
    } else if (wsrd->config.cpc_instance[0]) {
        wsrd->rcp.bus.tx = cpc_tx;
        wsrd->rcp.bus.rx = cpc_rx;
        wsrd->rcp.bus.fd = cpc_open(&wsrd->rcp.bus, wsrd->config.cpc_instance, g_enabled_traces & TR_CPC);
        wsrd->rcp.version_api = cpc_secondary_app_version(&wsrd->rcp.bus);
        if (version_older_than(wsrd->rcp.version_api, 2, 0, 0))
            FATAL(3, "RCP API < 2.0.0 (too old)");
    } else {
        BUG();
    }

    rcp_req_reset(&wsrd->rcp, false);

    pfd.fd = wsrd->rcp.bus.fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 5000);
    FATAL_ON(ret < 0, 2, "%s poll: %m", __func__);
    WARN_ON(!ret, "RCP is not responding");

    wsrd->rcp.bus.uart.init_phase = true;
    while (!wsrd->rcp.has_reset) {
        if (!wsrd->rcp.bus.uart.data_ready) {
            ret = poll(&pfd, 1, 5000);
            FATAL_ON(ret < 0, 2, "%s poll: %m", __func__);
            WARN_ON(!ret, "RCP is not responding (no IND_RESET)");
        }
        rcp_rx(&wsrd->rcp);
    }
    wsrd->rcp.bus.uart.init_phase = false;

    rcp_set_host_api(&wsrd->rcp, version_daemon_api);

    rcp_req_radio_list(&wsrd->rcp);
    while (!wsrd->rcp.has_rf_list)
        rcp_rx(&wsrd->rcp);

    if (wsrd->config.list_rf_configs) {
        rail_print_config_list(&wsrd->rcp);
        exit(0);
    }
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

    for (rail_config = wsrd->rcp.rail_config_list; rail_config->chan0_freq; rail_config++)
        if (rail_config->rail_phy_mode_id == wsrd->ws.phy.params->rail_phy_mode_id   &&
            rail_config->chan0_freq       == wsrd->ws.fhss.chan_params->chan0_freq   &&
            rail_config->chan_spacing     == wsrd->ws.fhss.chan_params->chan_spacing &&
            rail_config->chan_count       == wsrd->ws.fhss.chan_params->chan_count)
            break;
    if (!rail_config->chan0_freq)
        FATAL(2, "unsupported radio configuration (check --list-rf-configs)");
    rcp_set_radio(&wsrd->rcp, rail_config->index, wsrd->ws.phy.params->ofdm_mcs, false);

    ws_chan_mask_calc_reg(chan_mask, wsrd->ws.fhss.chan_params, HIF_REG_NONE);
    bitand(chan_mask, wsrd->config.ws_allowed_channels, 256);
    if (!memzcmp(chan_mask, sizeof(chan_mask)))
        FATAL(1, "combination of allowed_channels and regulatory constraints results in no valid channel (see --list-rf-configs)");
    rcp_set_fhss_uc(&wsrd->rcp, wsrd->config.ws_uc_dwell_interval_ms, chan_mask);
    rcp_set_fhss_async(&wsrd->rcp, 500, chan_mask);

    rcp_req_radio_enable(&wsrd->rcp);
}

static void wsrd_init_ws(struct wsrd *wsrd)
{
    strcpy(wsrd->ws.netname, wsrd->config.ws_netname);

    timer_group_init(&wsrd->ws.neigh_table.timer_group);
    ipv6_init(&wsrd->ws.ipv6, wsrd->rcp.eui64);
    dhcp_client_init(&wsrd->dhcp, &wsrd->ws.ipv6.tun, wsrd->rcp.eui64);
    ipv6_addr_add_mc(&wsrd->ws.ipv6, &ipv6_addr_all_nodes_link);     // ff02::1
    ipv6_addr_add_mc(&wsrd->ws.ipv6, &ipv6_addr_all_routers_link);   // ff02::2
    ipv6_addr_add_mc(&wsrd->ws.ipv6, &ipv6_addr_all_rpl_nodes_link); // ff02::1a
    ipv6_addr_add_mc(&wsrd->ws.ipv6, &ipv6_addr_all_nodes_realm);    // ff03::1
    ipv6_addr_add_mc(&wsrd->ws.ipv6, &ipv6_addr_all_routers_realm);  // ff03::2
    ipv6_addr_add_mc(&wsrd->ws.ipv6, &ipv6_addr_all_mpl_fwd_realm);  // ff03::fc
}

int wsrd_main(int argc, char *argv[])
{
    struct pollfd pfd[POLLFD_COUNT] = { };
    struct wsrd *wsrd = &g_wsrd;
    int ret;

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);

    parse_commandline(&wsrd->config, argc, argv);
    if (wsrd->config.color_output != -1)
        g_enable_color_traces = wsrd->config.color_output;

    check_mbedtls_features();
    wsrd_init_rcp(wsrd);
    wsrd_init_radio(wsrd);
    wsrd_init_ws(wsrd);
    supp_init(&wsrd->ws.supp, &wsrd->config.ca_cert, &wsrd->config.cert, &wsrd->config.key, wsrd->rcp.eui64);
    dbus_register("com.silabs.Wisun.Router",
                  "/com/silabs/Wisun/Router",
                  "com.silabs.Wisun.Router",
                  wsrd_dbus_vtable, wsrd);

    INFO("Wi-SUN Router successfully started");

    pfd[POLLFD_RCP].fd = wsrd->rcp.bus.fd;
    pfd[POLLFD_RCP].events = POLLIN;
    pfd[POLLFD_TIMER].fd = timer_fd();
    pfd[POLLFD_TIMER].events = POLLIN;
    pfd[POLLFD_TUN].fd = wsrd->ws.ipv6.tun.fd;
    pfd[POLLFD_TUN].events = POLLIN;
    pfd[POLLFD_RPL].fd = wsrd->ws.ipv6.rpl.fd;
    pfd[POLLFD_RPL].events = POLLIN;
    pfd[POLLFD_DHCP].fd = wsrd->dhcp.fd;
    pfd[POLLFD_DHCP].events = POLLIN;
    pfd[POLLFD_DBUS].fd = dbus_get_fd();
    pfd[POLLFD_DBUS].events = POLLIN;
    while (true) {
        ret = poll(pfd, POLLFD_COUNT, wsrd->rcp.bus.uart.data_ready ? 0 : -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (wsrd->rcp.bus.uart.data_ready ||
            pfd[POLLFD_RCP].revents & POLLIN)
            rcp_rx(&wsrd->rcp);
        if (pfd[POLLFD_TIMER].revents & POLLIN)
            timer_process();
        if (pfd[POLLFD_TUN].revents & POLLIN)
            ipv6_recvfrom_tun(&wsrd->ws.ipv6);
        if (pfd[POLLFD_RPL].revents & POLLIN)
            rpl_recv(&wsrd->ws.ipv6);
        if (pfd[POLLFD_DHCP].revents & POLLIN)
            dhcp_client_recv(&wsrd->dhcp);
        if (pfd[POLLFD_DBUS].revents & POLLIN)
            dbus_process();
    }

    return EXIT_SUCCESS;
}
