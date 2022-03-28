/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "common/log.h"

#include "nanostack/ws_management_api.h"

#include "commandline_values.h"

const struct name_value valid_ws_domains[] = {
    { "WW", REG_DOMAIN_WW }, // World wide
    { "NA", REG_DOMAIN_NA }, // North America
    { "JP", REG_DOMAIN_JP }, // Japan
    { "EU", REG_DOMAIN_EU }, // European Union
    { "CN", REG_DOMAIN_CN }, // China
    { "IN", REG_DOMAIN_IN }, // India
    { "MX", REG_DOMAIN_MX }, //
    { "BZ", REG_DOMAIN_BZ }, // Brazil
    { "AZ", REG_DOMAIN_AZ }, // Australia
    { "NZ", REG_DOMAIN_NZ }, // New zealand
    { "KR", REG_DOMAIN_KR }, // Korea
    { "PH", REG_DOMAIN_PH }, //
    { "MY", REG_DOMAIN_MY }, //
    { "HK", REG_DOMAIN_HK }, //
    { "SG", REG_DOMAIN_SG }, // band 866-869
    { "TH", REG_DOMAIN_TH }, //
    { "VN", REG_DOMAIN_VN }, //
    { "SG", REG_DOMAIN_SG_H }, // band 920-925
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

const struct name_value valid_traces[] = {
    { "bus",       TR_BUS },
    { "hdlc",      TR_HDLC },
    { "hif",       TR_HIF },
    { "trickle",   TR_TRICKLE },
    { "15.4-mngt", TR_15_4_MNGT },
    { "15.4",      TR_15_4_MNGT | TR_15_4_DATA },
    { "eap",       TR_EAP },
    { "icmp-rf",   TR_ICMP_RF },
    { "icmp-tun",  TR_ICMP_TUN },
    { "dhcp",      TR_DHCP },
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
    { "none", 0 },
    { "arib", 1 },
    { NULL },
};
