/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023-2024 Silicon Laboratories Inc. (www.silabs.com)
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
#include <stdint.h>

#include "common/commandline.h"
#include "common/log.h"
#include "common/rcp_api.h"
#include "common/ws_regdb.h"
#include "rail_config.h"

static void rail_print_config(const struct phy_params *phy_params, const struct chan_params *chan_params,
                              const struct rcp_rail_config *rail_params, uint8_t phy_mode_id)
{
    char str[256];
    bool is_std;
    int i;

    *str = '\0';
    if (chan_params)
        sprintf(str + strlen(str), " %-2s", val_to_str(chan_params->reg_domain, valid_ws_domains, "??"));
    else
        sprintf(str + strlen(str), " ??");

    if (rail_params->phy_mode_group)
        sprintf(str + strlen(str), "   %c", 'a' - 1 + rail_params->phy_mode_group);
    else
        sprintf(str + strlen(str), "   %c", '-');

    if (chan_params && chan_params->op_class)
        sprintf(str + strlen(str), "   %d", chan_params->op_class);
    else if (chan_params)
        sprintf(str + strlen(str), "   -");
    else
        sprintf(str + strlen(str), "   ?");

    if (chan_params && chan_params->chan_plan_id)
        sprintf(str + strlen(str), "  %3d", chan_params->chan_plan_id);
    else if (chan_params)
        sprintf(str + strlen(str), "   --");
    else
        sprintf(str + strlen(str), "   ??");

    sprintf(str + strlen(str), "  0x%02x", phy_mode_id);

    if (phy_params && phy_params->op_mode)
        sprintf(str + strlen(str), "  %-2x", phy_params->op_mode);
    else if (phy_params)
        sprintf(str + strlen(str), "  --");
    else
        sprintf(str + strlen(str), "  ??");

    if (phy_params && phy_params->modulation == MODULATION_OFDM) {
        sprintf(str + strlen(str), "   OFDM");
        sprintf(str + strlen(str), "    %1d", phy_params->ofdm_mcs);
        sprintf(str + strlen(str), "    %1d", phy_params->ofdm_option);
        sprintf(str + strlen(str), "          --");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), "     --");
        sprintf(str + strlen(str), "   --");
    } else if (phy_params && phy_params->modulation == MODULATION_2FSK) {
        sprintf(str + strlen(str), "    FSK");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), "          --");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), "     --");
        sprintf(str + strlen(str), "  %3s", val_to_str(phy_params->fsk_modulation_index, valid_fsk_modulation_indexes, "??"));
    } else if (phy_params && phy_params->modulation == MODULATION_OQPSK) {
        sprintf(str + strlen(str), "  OQPSK");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), "   --");
        sprintf(str + strlen(str), " %4dkchip/s", phy_params->oqpsk_chip_rate / 1000);
        sprintf(str + strlen(str), "    %1d", phy_params->oqpsk_rate_mode);
        sprintf(str + strlen(str), "      %1d", phy_params->oqpsk_spreading_mode);
        sprintf(str + strlen(str), "   --");
    } else {
        sprintf(str + strlen(str), "     ??");
        sprintf(str + strlen(str), "   ??");
        sprintf(str + strlen(str), "   ??");
        sprintf(str + strlen(str), "          ??");
        sprintf(str + strlen(str), "   ??");
        sprintf(str + strlen(str), "     ??");
        sprintf(str + strlen(str), "   ??");
    }

    if (phy_params)
        sprintf(str + strlen(str), " %4dkbps", phy_params->datarate / 1000);
    else
        sprintf(str + strlen(str), "       ??");

    sprintf(str + strlen(str), " %4.1fMHz", (double)rail_params->chan0_freq / 1000000);
    sprintf(str + strlen(str), " %4dkHz", rail_params->chan_spacing / 1000);
    sprintf(str + strlen(str), "  %3d", rail_params->chan_count);

    is_std = false;
    if (chan_params) {
        for (i = 0; chan_params->valid_phy_modes[i]; i++) {
            if (chan_params->valid_phy_modes[i] == phy_mode_id) {
                is_std = true;
                break;
            }
        }
    }
    if (is_std)
        sprintf(str + strlen(str), "  yes");
    else
        sprintf(str + strlen(str), "   no");

    if (chan_params && chan_params->chan_allowed)
        sprintf(str + strlen(str), " %s", chan_params->chan_allowed);
    else if (chan_params)
        sprintf(str + strlen(str), " --");
    else
        sprintf(str + strlen(str), " ??");

    INFO("%s", str);
}

void rail_print_config_list(struct rcp *rcp)
{
    const struct rcp_rail_config *rail_params;
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    bool entry_found;
    int domain;

    INFO("dom  phy cla chan phy  mode modula mcs opt.   chip rate rate spread  mod    data    chan    chan  #chans is  chans");
    INFO("-ain grp -ss plan mode      -tion                       mode   mode  idx    rate    base    space        std allowed");

    for (domain = REG_DOMAIN_WW; domain < REG_DOMAIN_UNDEF; domain++) {
        for (rail_params = rcp->rail_config_list; rail_params->chan0_freq; rail_params++) {
            for (chan_params = chan_params_table; chan_params->chan0_freq; chan_params++) {
                if (chan_params->reg_domain != domain ||
                    chan_params->chan0_freq != rail_params->chan0_freq ||
                    chan_params->chan_spacing != rail_params->chan_spacing ||
                    chan_params->chan_count != rail_params->chan_count)
                    continue;
                entry_found = false;
                for (phy_params = phy_params_table; phy_params->phy_mode_id; phy_params++) {
                    if (phy_params->rail_phy_mode_id == rail_params->rail_phy_mode_id) {
                        entry_found = true;
                        rail_print_config(phy_params, chan_params, rail_params, phy_params->phy_mode_id);
                    }
                }
                if (!entry_found)
                    rail_print_config(NULL, chan_params, rail_params, rail_params->rail_phy_mode_id);
            }
        }
    }
    for (rail_params = rcp->rail_config_list; rail_params->chan0_freq; rail_params++) {
        for (chan_params = chan_params_table; chan_params->chan0_freq; chan_params++)
            if (chan_params->chan0_freq == rail_params->chan0_freq &&
                chan_params->chan_spacing == rail_params->chan_spacing &&
                chan_params->chan_count == rail_params->chan_count)
                break;
        if (chan_params->chan0_freq)
            continue;
        entry_found = false;
        for (phy_params = phy_params_table; phy_params->phy_mode_id; phy_params++) {
            if (phy_params->rail_phy_mode_id == rail_params->rail_phy_mode_id) {
                entry_found = true;
                rail_print_config(phy_params, NULL, rail_params, phy_params->phy_mode_id);
            }
        }
        if (!entry_found)
            rail_print_config(NULL, NULL, rail_params, rail_params->rail_phy_mode_id);
    }
}
