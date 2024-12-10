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
#include <poll.h>

#include "common/crypto/ws_keys.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/mbedtls_config_check.h"
#include "common/drop_privileges.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/memutils.h"
#include "common/version.h"
#include "common/sl_ws.h"
#include "common/bits.h"
#include "common/log.h"

#include "ws.h"

#include "dc.h"

/*
 * We send a NS every 50 seconds to maintain the link considering the session will
 * be closed by the server after 60s with no communication.
 */
#define DIRECT_CONNECT_SYNC_PERIOD_S 50
#define DIRECT_CONNECT_NEIGH_LIFETIME_S 60

#define DC_KEY_INDEX 8

enum {
    POLLFD_RCP,
    POLLFD_TIMER,
    POLLFD_TUN,
    POLLFD_COUNT,
};

static void dc_on_rcp_reset(struct rcp *rcp)
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
    if (version_older_than(rcp->version_api, 2, 5, 0))
        FATAL(3, "RCP API < 2.5.0 (too old)");
}

static void dc_on_disc_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct dc *dc = container_of(timer, struct dc, disc_timer);
    struct ws_send_req req = {
        .frame_type    = SL_FT_DCS,
        .fhss_type     = HIF_FHSS_TYPE_ASYNC,
        .wh_ies.sl_utt = true,
        .wp_ies.us     = true,
        .dst = &dc->cfg.target_eui64,
    };

    if (dc->disc_count >= dc->cfg.disc_count_max)
        FATAL(1, "%s is unreachable, please check your configuration", tr_eui64(dc->cfg.target_eui64.u8));

    ws_if_send(&dc->ws, &req);
    dc->disc_count++;
}

static void dc_restart_disc_timer(struct dc *dc)
{
    dc->disc_count = 0;
    timer_start_rel(NULL, &dc->disc_timer, 0);
}

static void dc_remove_target_route(struct dc *dc)
{
    struct in6_addr client_linklocal;

    memcpy(client_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
    ipv6_addr_conv_iid_eui64(client_linklocal.s6_addr + 8, dc->cfg.target_eui64.u8);
    tun_route_del(&dc->tun, &client_linklocal);
}

static void dc_on_neigh_del(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct dc *dc = container_of(table, struct dc, ws.neigh_table);

    if (memcmp(dc->cfg.target_eui64.u8, neigh->mac64, sizeof(dc->cfg.target_eui64.u8)))
        return;
    INFO("Direct Connection with %s lost, attempting to reconnect...", tr_eui64(dc->cfg.target_eui64.u8));
    dc_restart_disc_timer(dc);
    dc_remove_target_route(dc);
    dc->ws.gak_index = 0;
    timer_stop(NULL, &dc->probe_timer);
}

static void dc_auth_sendto_mac(struct auth_ctx *auth_ctx, uint8_t kmp_id, const void *pkt,
                               size_t pkt_len, const struct eui64 *dst)
{
    struct dc *dc = container_of(auth_ctx, struct dc, auth_ctx);

    ws_if_send_eapol(&dc->ws, kmp_id, pkt, pkt_len, dst);
}

static void dc_auth_on_supp_gtk_installed(struct auth_ctx *auth_ctx, const struct eui64 *eui64, uint8_t index)
{
    struct dc *dc = container_of(auth_ctx, struct dc, auth_ctx);
    struct ws_neigh *neigh = ws_neigh_get(&dc->ws.neigh_table, dc->cfg.target_eui64.u8);
    struct in6_addr client_linklocal;
    struct ws_neigh *it;
    uint8_t tk[16];

    if (memcmp(&dc->cfg.target_eui64, eui64, sizeof(dc->cfg.target_eui64)))
        return;
    if (index - 1 != dc->auth_ctx.cur_slot) // Do not act when the second GTK is installed during rotation
        return;
    BUG_ON(!neigh);
    // Direct Connect encryption relies on the Temporal Key (TK) portion of the PTK to secure traffic
    BUG_ON(!auth_get_supp_tk(auth_ctx, eui64, tk));

    rcp_set_sec_key(&dc->ws.rcp, DC_KEY_INDEX, tk, 0);
    SLIST_FOREACH(it, &dc->ws.neigh_table.neigh_list, link)
        it->frame_counter_min[DC_KEY_INDEX - 1] = 0;

    if (!dc->ws.gak_index) {
        memcpy(client_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
        ipv6_addr_conv_iid_eui64(client_linklocal.s6_addr + 8, eui64->u8);
        tun_route_add(&dc->tun, &client_linklocal);
        INFO("Direct Connection established with %s", tr_eui64(eui64->u8));
        INFO("%s reachable at %s", tr_eui64(eui64->u8), tr_ipv6(client_linklocal.s6_addr));
    }
    if (timer_stopped(&dc->probe_timer)) {
        dc->probe_handle = -1;
        timer_start_rel(NULL, &dc->probe_timer, dc->probe_timer.period_ms);
        ws_neigh_refresh(&dc->ws.neigh_table, neigh, DIRECT_CONNECT_NEIGH_LIFETIME_S);
    }
    dc->ws.gak_index = DC_KEY_INDEX;
}

struct dc g_dc = {
    // Arbitrary default params
    .cfg.rcp_cfg.uart_baudrate = 115200,
    .cfg.tun_autoconf = true,
    .cfg.ws_domain = REG_DOMAIN_UNDEF,
    .cfg.ws_uc_dwell_interval_ms = 255,
    .cfg.tx_power = 14,
    .cfg.disc_period_s = 10,
    .cfg.disc_count_max = 6,
    .cfg.ws_allowed_channels = { [0 ... sizeof(g_dc.cfg.ws_allowed_channels) - 1] = 0xff },
    .cfg.target_eui64 = IEEE802154_ADDR_BC_INIT,
    .cfg.color_output = -1,

    .cfg.auth_cfg.ptk_lifetime_s           = 60 * 24 * 60 * 60, // 60 days
    // Wi-SUN FAN 1.1v08, 6.3.1.1 Configuration Parameters
    .cfg.auth_cfg.gtk_expire_offset_s      = 30 * 24 * 60 * 60, // 30 days
    .cfg.auth_cfg.gtk_new_activation_time  = 720,
    .cfg.auth_cfg.gtk_new_install_required = 80,

    .auth_ctx.cfg                   = &g_dc.cfg.auth_cfg,
    .auth_ctx.on_supp_gtk_installed = dc_auth_on_supp_gtk_installed,
    .auth_ctx.sendto_mac            = dc_auth_sendto_mac,

    .ws.rcp.bus.fd = -1,
    .ws.rcp.on_reset  = dc_on_rcp_reset,
    .ws.rcp.on_rx_ind = ws_if_recv_ind,
    .ws.rcp.on_tx_cnf = ws_if_recv_cnf,

    .ws.pan_id = 0xffff,
    .ws.pan_version = -1,
    .ws.on_recv_ind = ws_on_recv_ind,
    .ws.on_recv_cnf = ws_on_recv_cnf,
    .ws.neigh_table.on_del = dc_on_neigh_del,

    .disc_timer.callback = dc_on_disc_timer_timeout,
    .probe_timer.callback = ws_on_probe_timer_timeout,
    .probe_timer.period_ms = DIRECT_CONNECT_SYNC_PERIOD_S * 1000,

    .tun.fd = -1,
};

static void dc_init_tun(struct dc *dc)
{
    strcpy(dc->tun.ifname, dc->cfg.tun_dev);
    tun_init(&dc->tun, dc->cfg.tun_autoconf);
    tun_sysctl_set("/proc/sys/net/ipv6/conf", dc->tun.ifname, "accept_ra", '0');
    memcpy(dc->addr_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
    ipv6_addr_conv_iid_eui64(dc->addr_linklocal.s6_addr + 8, dc->ws.rcp.eui64.u8);
    tun_addr_add(&dc->tun, &dc->addr_linklocal, 64);
}

static void dc_init_radio(struct dc *dc)
{
    const struct rcp_rail_config *rail_config;
    uint8_t chan_mask[WS_CHAN_MASK_LEN];
    struct chan_params *chan_params;

    dc->ws.phy.params = ws_regdb_phy_params(dc->cfg.ws_phy_mode_id,
                                              dc->cfg.ws_mode);
    BUG_ON(!dc->ws.phy.params);
    dc->ws.fhss.chan_params = ws_regdb_chan_params(dc->cfg.ws_domain,
                                                     dc->cfg.ws_chan_plan_id,
                                                     dc->cfg.ws_class);
    if (!dc->ws.fhss.chan_params) {
        chan_params = zalloc(sizeof(*chan_params));
        chan_params->reg_domain   = dc->cfg.ws_domain;
        chan_params->chan0_freq   = dc->cfg.ws_chan0_freq;
        chan_params->chan_spacing = dc->cfg.ws_chan_spacing;
        chan_params->chan_count   = dc->cfg.ws_chan_count;
        dc->ws.fhss.chan_params = chan_params;
        dc->ws.fhss.chan_plan = 1;
    } else {
        dc->ws.fhss.chan_plan = dc->cfg.ws_chan_plan_id ? 2 : 0;
    }
    dc->ws.fhss.uc_dwell_interval = dc->cfg.ws_uc_dwell_interval_ms;
    memcpy(dc->ws.fhss.uc_chan_mask, dc->cfg.ws_allowed_channels, sizeof(dc->ws.fhss.uc_chan_mask));

    for (rail_config = dc->ws.rcp.rail_config_list; rail_config->chan0_freq; rail_config++)
        if (rail_config->rail_phy_mode_id == dc->ws.phy.params->rail_phy_mode_id   &&
            rail_config->chan0_freq       == dc->ws.fhss.chan_params->chan0_freq   &&
            rail_config->chan_spacing     == dc->ws.fhss.chan_params->chan_spacing &&
            rail_config->chan_count       == dc->ws.fhss.chan_params->chan_count)
            break;
    if (!rail_config->chan0_freq)
        FATAL(2, "unsupported radio configuration (check --list-rf-configs)");
    rcp_set_radio_tx_power(&dc->ws.rcp, dc->cfg.tx_power);
    rcp_set_radio(&dc->ws.rcp, rail_config->index, dc->ws.phy.params->ofdm_mcs, false);
    dc->ws.phy.rcp_rail_config_index = rail_config->index;

    ws_chan_mask_calc_reg(chan_mask, dc->ws.fhss.chan_params, HIF_REG_NONE);
    bitand(chan_mask, dc->cfg.ws_allowed_channels, 256);
    if (!memzcmp(chan_mask, sizeof(chan_mask)))
        FATAL(1, "combination of allowed_channels and regulatory constraints results in no valid channel (see --list-rf-configs)");
    rcp_set_fhss_uc(&dc->ws.rcp, dc->cfg.ws_uc_dwell_interval_ms, chan_mask);
    // Disable async fragmentation for faster advertisement
    rcp_set_fhss_async(&dc->ws.rcp, UINT32_MAX, chan_mask);

    rcp_req_radio_enable(&dc->ws.rcp);
}

int dc_main(int argc, char *argv[])
{
    struct pollfd pfd[POLLFD_COUNT] = { };
    struct dc *dc = &g_dc;
    int ret;

    INFO("Silicon Labs Wi-SUN Direct Connect %s", version_daemon_str);

    parse_commandline(&dc->cfg, argc, argv);
    if (dc->cfg.color_output != -1)
        g_enable_color_traces = dc->cfg.color_output;

    check_mbedtls_features();

    rcp_init(&dc->ws.rcp, &dc->cfg.rcp_cfg);
    if (dc->cfg.list_rf_configs) {
        rail_print_config_list(&dc->ws.rcp);
        exit(0);
    }

    dc_init_radio(dc);
    dc_init_tun(dc);
    auth_start(&dc->auth_ctx, &dc->ws.rcp.eui64);
    auth_set_supp_pmk(&dc->auth_ctx, &dc->cfg.target_eui64, dc->cfg.target_pmk);
    timer_group_init(&dc->ws.neigh_table.timer_group);
    if (dc->cfg.user[0] && dc->cfg.group[0])
        drop_privileges(dc->cfg.user, dc->cfg.group, true); // keep privileges to manage route to target later

    dc->disc_timer.period_ms = dc->cfg.disc_period_s * 1000;
    dc_restart_disc_timer(dc);

    INFO("Silicon Labs Wi-SUN Direct Connect successfully started");

    pfd[POLLFD_RCP].fd = dc->ws.rcp.bus.fd;
    pfd[POLLFD_RCP].events = POLLIN;
    pfd[POLLFD_TIMER].fd = timer_fd();
    pfd[POLLFD_TIMER].events = POLLIN;
    pfd[POLLFD_TUN].fd = dc->tun.fd;
    pfd[POLLFD_TUN].events = POLLIN;
    while (true) {
        ret = poll(pfd, POLLFD_COUNT, dc->ws.rcp.bus.uart.data_ready ? 0 : -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (dc->ws.rcp.bus.uart.data_ready ||
            pfd[POLLFD_RCP].revents & POLLIN)
            rcp_rx(&dc->ws.rcp);
        if (pfd[POLLFD_TIMER].revents & POLLIN)
            timer_process();
        if (pfd[POLLFD_TUN].revents & POLLIN)
            ws_recvfrom_tun(dc);
    }
}
