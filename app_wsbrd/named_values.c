/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "nanostack/ws_management_api.h"

#include "host-common/log.h"
#include "named_values.h"

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
    { "bus",  TR_BUS },
    { "hdlc", TR_HDLC },
    { "hif",  TR_HIF },
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

const char *val_to_str(int val, const struct name_value table[])
{
    int i;

    for (i = 0; table[i].name; i++)
        if (val == table[i].val)
            return table[i].name;

    // This function is called to print values. If val does not exists, it is a
    // bug
    BUG("invalid value: %d", val);
    return NULL;
}

int str_to_val(const char *str, const struct name_value table[])
{
    int i;

    for (i = 0; table[i].name; i++)
        if (!strcasecmp(table[i].name, str))
            return table[i].val;

    // This function is called to convert user provided user. So exit with FATAL
    // in case of error
    FATAL(1, "invalid value: %s", str);
    return -1;
}
