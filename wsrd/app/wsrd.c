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

#include "wsrd/app/commandline.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/rail_config.h"
#include "common/version.h"
#include "common/ws_regdb.h"
#include "wsrd.h"

enum {
    POLLFD_RCP,
    POLLFD_TIMER,
    POLLFD_COUNT,
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
    if (version_older_than(rcp->version_api, 2, 0, 0))
        FATAL(3, "RCP API < 2.0.0 (too old)");
}

static void wsrd_on_rcp_rx_ind(struct rcp *rcp, const struct rcp_rx_ind *ind)
{
    struct wsrd *wsrd = container_of(rcp, struct wsrd, rcp);

    ws_recv_ind(&wsrd->ws, ind);
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
        ret = poll(&pfd, 1, 5000);
        FATAL_ON(ret < 0, 2, "%s poll: %m", __func__);
        WARN_ON(!ret, "RCP is not responding (no IND_RESET)");
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
    memset(wsrd->ws.fhss.uc_chan_mask, 0xff, sizeof(wsrd->ws.fhss.uc_chan_mask));

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
    rcp_set_fhss_uc(&wsrd->rcp, wsrd->config.ws_uc_dwell_interval_ms, chan_mask);
    rcp_set_fhss_async(&wsrd->rcp, 500, chan_mask);

    rcp_req_radio_enable(&wsrd->rcp);
}

static void wsrd_init_ws(struct wsrd *wsrd)
{
    strcpy(wsrd->ws.netname, wsrd->config.ws_netname);
}

int main(int argc, char *argv[])
{
    struct pollfd pfd[POLLFD_COUNT] = { };
    struct wsrd wsrd = {
        .rcp.bus.fd = -1,
        .rcp.on_reset = wsrd_on_rcp_reset,
        .rcp.on_rx_ind = wsrd_on_rcp_rx_ind,

        .timer_ctx.fd = -1,
    };
    int ret;

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);

    parse_commandline(&wsrd.config, argc, argv);
    if (wsrd.config.color_output != -1)
        g_enable_color_traces = wsrd.config.color_output;

    timer_ctxt_init(&wsrd.timer_ctx);

    wsrd_init_rcp(&wsrd);
    wsrd_init_radio(&wsrd);
    wsrd_init_ws(&wsrd);

    pfd[POLLFD_RCP].fd = wsrd.rcp.bus.fd;
    pfd[POLLFD_RCP].events = POLLIN;
    pfd[POLLFD_TIMER].fd = wsrd.timer_ctx.fd;
    pfd[POLLFD_TIMER].events = POLLIN;
    while (true) {
        ret = poll(pfd, POLLFD_COUNT, wsrd.rcp.bus.uart.data_ready ? 0 : -1);
        FATAL_ON(ret < 0, 2, "poll: %m");
        if (wsrd.rcp.bus.uart.data_ready ||
            pfd[POLLFD_RCP].revents & POLLIN)
            rcp_rx(&wsrd.rcp);
        if (pfd[POLLFD_TIMER].revents & POLLIN)
            timer_ctxt_process(&wsrd.timer_ctx);
    }

    return EXIT_SUCCESS;
}
