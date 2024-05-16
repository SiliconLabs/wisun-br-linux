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
#include "common/bits.h"
#include "common/hif.h"
#include "common/log.h"
#include "common/ws_regdb.h"
#include "common/specs/ws.h"

#include "wsbr_cfg.h"

#include "commandline_values.h"

const struct name_value valid_ws_size[] = {
    { "CERT",   WS_NETWORK_SIZE_CERTIFICATION },
    { "SMALL",  WS_NETWORK_SIZE_SMALL },
    { "S",      WS_NETWORK_SIZE_SMALL },
    { "MEDIUM", WS_NETWORK_SIZE_MEDIUM },
    { "M",      WS_NETWORK_SIZE_MEDIUM },
    { "LARGE",  WS_NETWORK_SIZE_LARGE },
    { "L",      WS_NETWORK_SIZE_LARGE },
    { "XLARGE", WS_NETWORK_SIZE_XLARGE },
    { "XL",     WS_NETWORK_SIZE_XLARGE },
    { NULL },
};

const struct name_value valid_fan_versions[] = {
    { "auto", WS_FAN_VERSION_1_1 }, // backwards compatibility
    { "1.0",  WS_FAN_VERSION_1_0 },
    { "1.1",  WS_FAN_VERSION_1_1 },
    { NULL },
};

const struct name_value valid_traces[] = {
    { "bus",        TR_BUS },
    { "cpc",        TR_CPC },
    { "hdlc",       TR_HDLC },
    { "hif",        TR_HIF },
    { "hif-extra",  TR_HIF_EXTRA },
    { "trickle",    TR_TRICKLE },
    { "15.4-mngt",  TR_15_4_MNGT },
    { "15.4",       TR_15_4_MNGT | TR_15_4_DATA },
    { "eap",        TR_EAP },
    { "icmp",       TR_ICMP },
    { "icmp-rf",    TR_ICMP }, // legacy name
    { "icmp-tun",   0 },       // legacy name
    { "dhcp",       TR_DHCP },
    { "tun",        TR_TUN },
    { "timers",     TR_TIMERS },
    { "drop",       TR_DROP | TR_TX_ABORT | TR_IGNORE },
    { "rpl",        TR_RPL },
    { "neigh",      TR_NEIGH_15_4 }, // legacy name
    { "neigh-15.4", TR_NEIGH_15_4 },
    { "neigh-ipv6", TR_NEIGH_IPV6 },
    { "queue",      TR_QUEUE },
    { NULL },
};

const struct name_value valid_join_metrics[] = {
    { "none", 0 },
    { "plf",  BIT(WS_JM_PLF) },
};

const struct name_value valid_ws_regional_regulations[] = {
    { "none", HIF_REG_NONE },
    { "arib", HIF_REG_ARIB },
    { "wpc",  HIF_REG_WPC  },
    { NULL },
};
