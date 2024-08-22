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
#include "common/ipv6/ipv6_addr.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/memutils.h"
#include "common/version.h"
#include "common/bits.h"
#include "common/log.h"

#include "dc.h"

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

struct dc g_dc = {
    .ws.rcp.bus.fd = -1,
    .ws.rcp.on_reset  = dc_on_rcp_reset,

    .ws.pan_id = 0xffff,
    .ws.pan_version = -1,

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
    struct dc *dc = &g_dc;

    INFO("Silicon Labs Wi-SUN Direct Connect %s", version_daemon_str);

    parse_commandline(&dc->cfg, argc, argv);
    if (dc->cfg.color_output != -1)
        g_enable_color_traces = dc->cfg.color_output;

    rcp_init(&dc->ws.rcp, &dc->cfg.rcp_cfg);
    if (dc->cfg.list_rf_configs) {
        rail_print_config_list(&dc->ws.rcp);
        exit(0);
    }

    dc_init_radio(dc);
    dc_init_tun(dc);
    return 0;
}
