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
#define _GNU_SOURCE
#include <stdint.h>
#include "common/version.h"
#include "common/memutils.h"
#include "common/log.h"
#include "common/ws_regdb.h"
#include "common/named_values.h"

#include "net/protocol.h"

#include "commandline_values.h"
#include "wsbrd.h"
#include "rail_config.h"

static const struct rcp_rail_config *rail_get_next_config(struct wsbr_ctxt *ctxt,
                                                          const struct rcp_rail_config *iterator)
{
    const struct chan_params *chan_params = ws_regdb_chan_params(ctxt->config.ws_domain, ctxt->config.ws_chan_plan_id, ctxt->config.ws_class);
    const struct phy_params *phy_params = ws_regdb_phy_params(ctxt->config.ws_phy_mode_id, ctxt->config.ws_mode);
    uint32_t chan0_freq   = chan_params ? chan_params->chan0_freq   : ctxt->config.ws_chan0_freq;
    uint32_t chan_spacing = chan_params ? chan_params->chan_spacing : ctxt->config.ws_chan_spacing;
    uint16_t chan_count   = chan_params ? chan_params->chan_count   : ctxt->config.ws_chan_count;

    WARN_ON(!ctxt->rcp.rail_config_list);
    if (!ctxt->rcp.rail_config_list)
        return NULL;
    if (!iterator)
        iterator = ctxt->rcp.rail_config_list;
    else
        iterator++;
    while (iterator->chan0_freq) {
        if (iterator->rail_phy_mode_id == phy_params->rail_phy_mode_id &&
            iterator->chan0_freq       == chan0_freq &&
            iterator->chan_count       == chan_count &&
            iterator->chan_spacing     == chan_spacing)
            return iterator;
        iterator++;
    }
    return NULL;
}

static void rail_fill_pom_disabled(struct wsbr_ctxt *ctxt)
{
    const struct rcp_rail_config *config = rail_get_next_config(ctxt, NULL);

    if (!config)
        FATAL(1, "can't match any RAIL configuration");
    ctxt->net_if.ws_info.phy_config.rcp_rail_config_index = config->index;
}

static void rail_fill_pom_auto(struct wsbr_ctxt *ctxt)
{
    struct ws_phy_config *phy_config = &ctxt->net_if.ws_info.phy_config;
    const struct rcp_rail_config *base_rail_params, *rail_params;
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    const uint8_t *phy_mode;
    int i;

    for (base_rail_params = rail_get_next_config(ctxt, NULL);
         base_rail_params;
         base_rail_params = rail_get_next_config(ctxt, base_rail_params))
        // FIXME: if base PHY is OFDM, the rail config may not be associated to
        // any group
        // FIXME: display a warning if several rail configs match
        if (base_rail_params->phy_mode_group)
            break;
    if (!base_rail_params) {
        INFO("No PHY operating modes available for your configuration");
        rail_fill_pom_disabled(ctxt);
        return;
    }
    i = 0;
    phy_config->rcp_rail_config_index = base_rail_params->index;
    for (rail_params = ctxt->rcp.rail_config_list; rail_params->chan0_freq; rail_params++) {
        for (chan_params = chan_params_table; chan_params->chan0_freq; chan_params++) {
            for (phy_mode = chan_params->valid_phy_modes; *phy_mode; phy_mode++) {
                phy_params = ws_regdb_phy_params(*phy_mode, 0);
                if (i >= ARRAY_SIZE(phy_config->phy_op_modes) - 1)
                    continue;
                // Ignore base mode
                if (phy_params->phy_mode_id == ctxt->config.ws_phy_mode_id)
                    continue;
                // Ignore FAN1.0
                if (!chan_params->chan_plan_id)
                    continue;
                if (strchr((char *)phy_config->phy_op_modes, *phy_mode))
                    continue;
                if (chan_params->reg_domain != ctxt->config.ws_domain)
                    continue;
                if (rail_params->phy_mode_group != base_rail_params->phy_mode_group)
                    continue;
                // If base PHY is OFDM, we can only switch to another MCS
                if (phy_config->params->modulation == MODULATION_OFDM &&
                    phy_config->params->rail_phy_mode_id != phy_params->rail_phy_mode_id)
                    continue;
                if (rail_params->rail_phy_mode_id != phy_params->rail_phy_mode_id)
                    continue;
                if (phy_config->params->phy_mode_id == phy_params->phy_mode_id)
                    continue;
                phy_config->phy_op_modes[i++] = *phy_mode;
            }
        }
    }
}

static void rail_fill_pom_manual(struct wsbr_ctxt *ctxt)
{
    struct ws_phy_config *phy_config = &ctxt->net_if.ws_info.phy_config;
    const struct phy_params *base_phy_params = ws_regdb_phy_params(ctxt->config.ws_phy_mode_id, ctxt->config.ws_mode);
    const struct rcp_rail_config *base_rail_params, *rail_params;
    const struct phy_params *phy_params;
    const uint8_t *phy_mode;
    int found;
    int i;

    for (base_rail_params = rail_get_next_config(ctxt, NULL);
         base_rail_params;
         base_rail_params = rail_get_next_config(ctxt, base_rail_params)) {
        // FIXME: if base PHY is OFDM, the rail config may not be associated to
        // any group
        if (!base_rail_params->phy_mode_group)
            continue;
        i = 0;
        phy_config->rcp_rail_config_index = base_rail_params->index;
        for (phy_mode = ctxt->config.ws_phy_op_modes; *phy_mode; phy_mode++) {
            phy_params = ws_regdb_phy_params(*phy_mode, 0);
            if (phy_params->phy_mode_id == ctxt->config.ws_phy_mode_id)
                WARN("base \"phy_mode_id\" should not be present in \"phy_operating_modes\"");
            found = 0;
            if (base_phy_params->modulation == MODULATION_OFDM &&
                base_phy_params->rail_phy_mode_id != phy_params->rail_phy_mode_id)
                FATAL(1, "unsupported phy_operating_mode %d with phy_mode %d",
                      phy_params->rail_phy_mode_id, base_phy_params->rail_phy_mode_id);
            for (rail_params = ctxt->rcp.rail_config_list; rail_params->chan0_freq; rail_params++)
                if (rail_params->phy_mode_group   == base_rail_params->phy_mode_group &&
                    rail_params->rail_phy_mode_id == phy_params->rail_phy_mode_id)
                    found++;
            if (!found)
                break;
            if (found > 1)
                ERROR("ambiguous RAIL configuration");
            BUG_ON(i >= ARRAY_SIZE(phy_config->phy_op_modes) - 1);
            phy_config->phy_op_modes[i++] = *phy_mode;
        }
        // It may exist other possible configurations (eg. user may define NA
        // and BZ with the same parameters set). We stop on the first found.
        if (!*phy_mode) {
            BUG_ON(phy_config->phy_op_modes[i] != 0);
            return;
        }
    }
    FATAL(1, "phy_operating_modes: can't match any RAIL configuration");
}

void rail_fill_pom(struct wsbr_ctxt *ctxt)
{
    if (ctxt->config.ws_phy_op_modes[0] == (uint8_t)-1)
        rail_fill_pom_auto(ctxt);
    else if (ctxt->config.ws_phy_op_modes[0])
        rail_fill_pom_manual(ctxt);
    else
        rail_fill_pom_disabled(ctxt);
}
