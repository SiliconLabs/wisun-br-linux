/*
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
#include "common/log.h"
#include "common/ws_regdb.h"

#include "stack/ws_management_api.h"
#include "stack/mac/channel_list.h"
#include "stack/source/6lowpan/ws/ws_regulation.h"
#include "stack/source/6lowpan/ws/ws_common_defines.h"

#include "commandline_values.h"

const struct name_value valid_ws_domains[] = {
    { "WW", REG_DOMAIN_WW }, // World wide
    { "NA", REG_DOMAIN_NA }, // North America
    { "JP", REG_DOMAIN_JP }, // Japan
    { "EU", REG_DOMAIN_EU }, // European Union
    { "CN", REG_DOMAIN_CN }, // China
    { "IN", REG_DOMAIN_IN }, // India
    { "MX", REG_DOMAIN_MX }, // Mexico
    { "BZ", REG_DOMAIN_BZ }, // Brazil
    { "AZ", REG_DOMAIN_AZ }, // Australia
    { "NZ", REG_DOMAIN_NZ }, // New Zealand (share its ID with Australia)
    { "KR", REG_DOMAIN_KR }, // Korea
    { "PH", REG_DOMAIN_PH }, // Philippines
    { "MY", REG_DOMAIN_MY }, // Malaysia
    { "HK", REG_DOMAIN_HK }, // Hong Kong
    { "SG", REG_DOMAIN_SG }, // Singapore
    { "TH", REG_DOMAIN_TH }, // Thailand
    { "VN", REG_DOMAIN_VN }, // Vietnam
    { NULL },
};

const struct name_value valid_fsk_modulation_indexes[] = {
    { "0.5", MODULATION_INDEX_0_5 },
    { "1.0", MODULATION_INDEX_1_0 },
    { NULL },
};

const struct name_value valid_ws_size[] = {
    { "AUTO",   NETWORK_SIZE_AUTOMATIC },
    { "CERT",   NETWORK_SIZE_CERTIFICATE },
    { "SMALL",  NETWORK_SIZE_SMALL },
    { "S",      NETWORK_SIZE_SMALL },
    { "MEDIUM", NETWORK_SIZE_MEDIUM },
    { "M",      NETWORK_SIZE_MEDIUM },
    { "LARGE",  NETWORK_SIZE_LARGE },
    { "L",      NETWORK_SIZE_LARGE },
    { "XLARGE", NETWORK_SIZE_XLARGE },
    { "XL",     NETWORK_SIZE_XLARGE },
    { NULL },
};

const struct name_value valid_fan_versions[] = {
    { "auto",      0 },
    { "1.0",       WS_FAN_VERSION_1_0 },
    { "1.1",       WS_FAN_VERSION_1_1 },
    { NULL },
};

const struct name_value valid_traces[] = {
    { "bus",       TR_BUS },
    { "cpc",       TR_CPC },
    { "hdlc",      TR_HDLC },
    { "hif",       TR_HIF },
    { "hif-extra", TR_HIF_EXTRA },
    { "trickle",   TR_TRICKLE },
    { "15.4-mngt", TR_15_4_MNGT },
    { "15.4",      TR_15_4_MNGT | TR_15_4_DATA },
    { "eap",       TR_EAP },
    { "icmp",      TR_ICMP },
    { "icmp-rf",   TR_ICMP }, // legacy name
    { "icmp-tun",  0 },       // legacy name
    { "dhcp",      TR_DHCP },
    { "timers",    TR_TIMERS },
    { "drop",      TR_DROP },
    { NULL },
};

const struct name_value valid_tristate[] = {
    { "auto",    -1 },
    { "true",    1 },
    { "false",   0 },
    { "enable",  1 },
    { "disable", 0 },
    { "yes",     1 },
    { "no",      0 },
    { "y",       1 },
    { "n",       0 },
    { "1",       1 },
    { "0",       0 },
    { NULL },
};

const struct name_value valid_booleans[] = {
    { "true",    1 },
    { "false",   0 },
    { "enable",  1 },
    { "disable", 0 },
    { "yes",     1 },
    { "no",      0 },
    { "y",       1 },
    { "n",       0 },
    { "1",       1 },
    { "0",       0 },
    { NULL },
};

const struct name_value valid_ws_regional_regulations[] = {
    { "none", REG_REGIONAL_NONE },
    { "arib", REG_REGIONAL_ARIB },
    { NULL },
};
