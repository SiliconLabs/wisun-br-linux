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
#include <stdlib.h>

#include "wsrd/app/commandline.h"
#include "common/log.h"
#include "common/version.h"
#include "wsrd.h"

static void wsrd_init_rcp(struct wsrd *wsrd)
{
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
}

int main(int argc, char *argv[])
{
    struct wsrd wsrd = {
        .rcp.bus.fd = -1,
    };

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);

    parse_commandline(&wsrd.config, argc, argv);
    if (wsrd.config.color_output != -1)
        g_enable_color_traces = wsrd.config.color_output;

    wsrd_init_rcp(&wsrd);

    return EXIT_SUCCESS;
}
