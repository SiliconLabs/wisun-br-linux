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

#include "common/ws/ws_regdb.h"
#include "common/commandline.h"
#include "common/log.h"
#include "common/rcp_api.h"
#include "common/version.h"
#include "common/memutils.h"
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
        sprintf(str + strlen(str), " %4ukchip/s", phy_params->oqpsk_chip_rate / 1000);
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
        sprintf(str + strlen(str), " %4ukbps", phy_params->datarate / 1000);
    else
        sprintf(str + strlen(str), "       ??");

    sprintf(str + strlen(str), " %4.1fMHz", (double)rail_params->chan0_freq / 1000000);
    sprintf(str + strlen(str), " %4ukHz", rail_params->chan_spacing / 1000);
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

static const struct rcp_rail_config *rail_get_next_config(const struct rcp_rail_config *iterator,
                                                          const struct chan_params *chan_params,
                                                          const struct phy_params *phy_params)
{
    WARN_ON(!iterator);
    if (!iterator)
        return NULL;
    while (iterator->chan0_freq) {
        if (iterator->rail_phy_mode_id == phy_params->rail_phy_mode_id &&
            iterator->chan0_freq       == chan_params->chan0_freq &&
            iterator->chan_count       == chan_params->chan_count &&
            iterator->chan_spacing     == chan_params->chan_spacing)
            return iterator;
        iterator++;
    }
    return NULL;
}

static const struct chan_params *rail_get_ms_chan_params(int reg_domain, const struct rcp_rail_config *rail_config)
{
    const struct chan_params *ret = NULL;

    for (const struct chan_params *it = chan_params_table; it->chan0_freq; it++) {
        if (!it->chan_plan_id) // Ignore FAN 1.0 entries
            continue;
        if (it->reg_domain   != reg_domain ||
            it->chan0_freq   != rail_config->chan0_freq ||
            it->chan_spacing != rail_config->chan_spacing ||
            it->chan_count   != rail_config->chan_count)
            continue;
        BUG_ON(ret, "ambiguous channel parameters");
        ret = it;
    }
    return ret;
}

void rail_fill_ms_chan_masks(const struct rcp *rcp, const struct ws_fhss_config *fhss, const struct ws_phy_config *phy,
                             struct ws_ms_chan_mask *ms_chan_mask)
{
    const struct rcp_rail_config *base_rail_params, *rail_params;
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    uint8_t chan_mask[WS_CHAN_MASK_LEN];
    struct ws_ms_chan_mask *it;
    int i;

    base_rail_params = rcp->rail_config_list + phy->rcp_rail_config_index;
    for (i = 0; phy->phy_op_modes[i]; i++) {
        for (rail_params = rcp->rail_config_list; rail_params->chan0_freq; rail_params++) {
            if (rail_params->phy_mode_group != base_rail_params->phy_mode_group)
                continue;
            phy_params = ws_regdb_phy_params(phy->phy_op_modes[i], 0);
            FATAL_ON(!phy_params, 1, "unknown phy parameters for phy %d", phy->phy_op_modes[i]);
            if (phy_params->rail_phy_mode_id != rail_params->rail_phy_mode_id)
                continue;
            chan_params = rail_get_ms_chan_params(fhss->chan_params->reg_domain, rail_params);
            FATAL_ON(!chan_params, 1, "unknown channel parameters for phy %d", phy->phy_op_modes[i]);
            // Insert if unique
            for (it = ms_chan_mask; it->chan_spacing; it++)
                if (it->chan_spacing == chan_params->chan_spacing)
                    break;
            ws_chan_mask_calc_reg(chan_mask, chan_params);
            if (it->chan_spacing) {
                WARN_ON(memcmp(it->chan_mask, chan_mask, sizeof(chan_mask)), "ambiguous channel masks for spacing %u", chan_params->chan_spacing);
                continue;
            }
            it->chan_spacing = chan_params->chan_spacing;
            memcpy(it->chan_mask, chan_mask, sizeof(chan_mask));
        }
    }
}

static void rail_fill_pom_disabled(const struct rcp *rcp, const struct ws_fhss_config *fhss, struct ws_phy_config *phy)
{
    const struct rcp_rail_config *config = rail_get_next_config(rcp->rail_config_list, fhss->chan_params, phy->params);

    if (!config)
        FATAL(1, "can't match any RAIL configuration");
    phy->rcp_rail_config_index = config->index;
}

static void rail_fill_pom_auto(const struct rcp *rcp, const struct ws_fhss_config *fhss, struct ws_phy_config *phy)
{
    const struct rcp_rail_config *base_rail_params, *rail_params;
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    const uint8_t *phy_mode;
    int i;

    for (base_rail_params = rail_get_next_config(rcp->rail_config_list, fhss->chan_params, phy->params);
         base_rail_params;
         base_rail_params = rail_get_next_config(base_rail_params + 1, fhss->chan_params, phy->params))
        // FIXME: if base PHY is OFDM, the rail config may not be associated to
        // any group
        // FIXME: display a warning if several rail configs match
        if (base_rail_params->phy_mode_group)
            break;
    if (version_older_than(rcp->version_api, 2, 6, 0)) {
        WARN("\"phy_operating_modes = auto\" with RCP API < 2.6.0");
        base_rail_params = NULL;
    }
    if (!base_rail_params) {
        INFO("No PHY operating modes available for your configuration");
        rail_fill_pom_disabled(rcp, fhss, phy);
        return;
    }
    i = 0;
    phy->rcp_rail_config_index = base_rail_params->index;
    for (rail_params = rcp->rail_config_list; rail_params->chan0_freq; rail_params++) {
        for (chan_params = chan_params_table; chan_params->chan0_freq; chan_params++) {
            for (phy_mode = chan_params->valid_phy_modes; *phy_mode; phy_mode++) {
                phy_params = ws_regdb_phy_params(*phy_mode, 0);
                if (i >= ARRAY_SIZE(phy->phy_op_modes) - 1)
                    continue;
                // Ignore FAN1.0
                if (!chan_params->chan_plan_id)
                    continue;
                if (strchr((char *)phy->phy_op_modes, *phy_mode))
                    continue;
                if (chan_params->reg_domain != fhss->chan_params->reg_domain)
                    continue;
                if (rail_params->phy_mode_group != base_rail_params->phy_mode_group)
                    continue;
                // If base PHY is OFDM, we can only switch to another MCS
                if (phy->params->modulation == MODULATION_OFDM &&
                    phy->params->rail_phy_mode_id != phy_params->rail_phy_mode_id)
                    continue;
                if (rail_params->rail_phy_mode_id != phy_params->rail_phy_mode_id)
                    continue;
                // Ignore base mode
                if (phy->params->phy_mode_id == phy_params->phy_mode_id)
                    continue;
                phy->phy_op_modes[i++] = *phy_mode;
            }
        }
    }
}

static void rail_fill_pom_manual(const struct rcp *rcp, const struct ws_fhss_config *fhss, struct ws_phy_config *phy,
                                 const uint8_t ws_phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) - 1 + 1])
{
    const struct rcp_rail_config *base_rail_params, *rail_params;
    const struct phy_params *phy_params;
    const uint8_t *phy_mode;
    int found;
    int i;

    for (base_rail_params = rail_get_next_config(rcp->rail_config_list, fhss->chan_params, phy->params);
         base_rail_params;
         base_rail_params = rail_get_next_config(base_rail_params + 1, fhss->chan_params, phy->params)) {
        // FIXME: if base PHY is OFDM, the rail config may not be associated to
        // any group
        if (!base_rail_params->phy_mode_group)
            continue;
        i = 0;
        phy->rcp_rail_config_index = base_rail_params->index;
        for (phy_mode = ws_phy_op_modes; *phy_mode; phy_mode++) {
            phy_params = ws_regdb_phy_params(*phy_mode, 0);
            if (phy_params->phy_mode_id == phy->params->phy_mode_id)
                WARN("base \"phy_mode_id\" should not be present in \"phy_operating_modes\"");
            found = 0;
            if (phy->params->modulation == MODULATION_OFDM &&
                phy->params->rail_phy_mode_id != phy_params->rail_phy_mode_id)
                FATAL(1, "unsupported phy_operating_mode %d with phy_mode %d",
                      phy_params->rail_phy_mode_id, phy->params->rail_phy_mode_id);
            for (rail_params = rcp->rail_config_list; rail_params->chan0_freq; rail_params++)
                if (rail_params->phy_mode_group   == base_rail_params->phy_mode_group &&
                    rail_params->rail_phy_mode_id == phy_params->rail_phy_mode_id)
                    found++;
            if (!found)
                break;
            if (found > 1)
                ERROR("ambiguous RAIL configuration");
            BUG_ON(i >= ARRAY_SIZE(phy->phy_op_modes) - 1);
            phy->phy_op_modes[i++] = *phy_mode;
        }
        // It may exist other possible configurations (eg. user may define NA
        // and BZ with the same parameters set). We stop on the first found.
        if (!*phy_mode) {
            BUG_ON(phy->phy_op_modes[i] != 0);
            return;
        }
    }
    FATAL(1, "phy_operating_modes: can't match any RAIL configuration");
}

void rail_fill_pom(const struct rcp *rcp, const struct ws_fhss_config *fhss, struct ws_phy_config *phy,
                   const uint8_t ws_phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) - 1 + 1])
{
    if (ws_phy_op_modes[0] == (uint8_t)-1)
        rail_fill_pom_auto(rcp, fhss, phy);
    else if (ws_phy_op_modes[0])
        rail_fill_pom_manual(rcp, fhss, phy, ws_phy_op_modes);
    else
        rail_fill_pom_disabled(rcp, fhss, phy);
}
