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
#include "common/rail_config.h"
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
    .rcp.bus.fd = -1,
    .rcp.on_reset  = dc_on_rcp_reset,
};

int dc_main(int argc, char *argv[])
{
    struct dc *dc = &g_dc;

    INFO("Silicon Labs Wi-SUN Direct Connect %s", version_daemon_str);

    parse_commandline(&dc->cfg, argc, argv);
    if (dc->cfg.color_output != -1)
        g_enable_color_traces = dc->cfg.color_output;

    rcp_init(&dc->rcp, &dc->cfg.rcp_cfg);
    if (dc->cfg.list_rf_configs) {
        rail_print_config_list(&dc->rcp);
        exit(0);
    }
    return 0;
}
