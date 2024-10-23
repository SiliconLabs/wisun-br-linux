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

#include "common/ipv6/ipv6_addr.h"
#include "common/mbedtls_config_check.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/memutils.h"
#include "common/version.h"
#include "common/sl_ws.h"
#include "common/bits.h"
#include "common/log.h"

#include "ws.h"

#include "dc.h"

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
    if (version_older_than(rcp->version_api, 2, 0, 0))
        FATAL(3, "RCP API < 2.0.0 (too old)");
}

static void dc_on_disc_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct dc *dc = container_of(timer, struct dc, disc_timer);
    struct ws_send_req req = {
        .frame_type    = SL_FT_DCS,
        .fhss_type     = HIF_FHSS_TYPE_ASYNC,
        .wh_ies.sl_utt = true,
        .wp_ies.us     = true,
        .dst = (struct eui64 *)dc->cfg.target_eui64,
    };

    if (dc->disc_count >= dc->cfg.disc_count_max)
        FATAL(1, "%s is unreachable, please check your configuration", tr_eui64(dc->cfg.target_eui64));

    ws_if_send(&dc->ws, &req);
    dc->disc_count++;
}

static void dc_on_neigh_del(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct dc *dc = container_of(table, struct dc, ws.neigh_table);
    struct in6_addr client_linklocal;

    if (memcmp(dc->cfg.target_eui64, neigh->mac64, sizeof(dc->cfg.target_eui64)))
        return;
    INFO("Direct Connection with %s lost, attempting to reconnect...", tr_eui64(dc->cfg.target_eui64));
    dc->disc_count = 0;
    timer_start_rel(NULL, &dc->disc_timer, dc->disc_timer.period_ms);
    memcpy(client_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
    ipv6_addr_conv_iid_eui64(client_linklocal.s6_addr + 8, neigh->mac64);
    tun_route_del(&dc->tun, &client_linklocal);
}

struct dc g_dc = {
    .ws.rcp.bus.fd = -1,
    .ws.rcp.on_reset  = dc_on_rcp_reset,
    .ws.rcp.on_rx_ind = ws_if_recv_ind,
    .ws.rcp.on_tx_cnf = ws_if_recv_cnf,

    .ws.pan_id = 0xffff,
    .ws.pan_version = -1,
    .ws.on_recv_ind = ws_on_recv_ind,
    .ws.neigh_table.on_del = dc_on_neigh_del,

    .disc_timer.callback = dc_on_disc_timer_timeout,

    .tun.fd = -1,
};

static void dc_init_tun(struct dc *dc)
{
    tun_init(&dc->tun, true);
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
    timer_group_init(&dc->ws.neigh_table.timer_group);

    dc->disc_timer.period_ms = dc->cfg.disc_period_s * 1000;
    timer_start_rel(NULL, &dc->disc_timer, 0);

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
    return 0;
}
