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
#include "ws/ws_common.h"
#include "ws/ws_llc.h"
#include "common/log.h"
#include "common/ws_ie.h"
#include "common/ws_regdb.h"

#include "ws_ie_validation.h"

static bool ws_ie_validate_chan_plan(const struct ws_generic_channel_info *rx_plan,
                                     const struct ws_fhss_config *fhss_config)
{
    const struct ws_channel_plan_zero *plan0 = &rx_plan->plan.zero;
    const struct ws_channel_plan_one *plan1 = &rx_plan->plan.one;
    const struct ws_channel_plan_two *plan2 = &rx_plan->plan.two;
    int plan_nr = rx_plan->channel_plan;
    const struct chan_params *parms = NULL;

    BUG_ON(!fhss_config->chan_params);
    if (plan_nr == 1)
        return plan1->ch0 * 1000 == fhss_config->chan_params->chan0_freq &&
               plan1->channel_spacing == ws_regdb_chan_spacing_id(fhss_config->chan_params->chan_spacing) &&
               plan1->number_of_channel == fhss_config->chan_params->chan_count;
    if (plan_nr == 0)
        parms = ws_regdb_chan_params(plan0->regulatory_domain,
                                     0, plan0->operating_class);
    if (plan_nr == 2)
        parms = ws_regdb_chan_params(plan2->regulatory_domain,
                                     plan2->channel_plan_id, 0);
    if (!parms)
        return false;
    return parms->chan0_freq   == fhss_config->chan_params->chan0_freq &&
           parms->chan_count   == fhss_config->chan_params->chan_count &&
           parms->chan_spacing == fhss_config->chan_params->chan_spacing;
}

static bool ws_ie_validate_schedule(const struct ws_info *ws_info,
                                    const struct ws_generic_channel_info *chan_info,
                                    const char *ie_str)
{
    if (!ws_ie_validate_chan_plan(chan_info, &ws_info->fhss_config)) {
        TRACE(TR_DROP, "drop %-9s: %s channel plan mismatch", "15.4", ie_str);
        return false;
    }

    switch (chan_info->channel_function) {
    case WS_CHAN_FUNC_FIXED:
        if (chan_info->function.zero.fixed_channel >= 8 * WS_CHAN_MASK_LEN) {
            TRACE(TR_DROP, "drop %-9s: %s fixed channel >= %u",
                  "15.4", ie_str, 8 * WS_CHAN_FUNC_FIXED);
            return false;
        }
        break;
    case WS_CHAN_FUNC_TR51CF:
    case WS_CHAN_FUNC_DH1CF:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: %s channel function unsupported", "15.4", ie_str);
        return false;
    }

    switch (chan_info->excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_NONE:
    case WS_EXC_CHAN_CTRL_RANGE:
    case WS_EXC_CHAN_CTRL_BITMASK:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: %s excluded channel control unsupported", "15.4", ie_str);
        return false;
    }

    return true;
}

bool ws_ie_validate_us(const struct ws_info *ws_info, const struct ws_us_ie *ie_us)
{
    return ws_ie_validate_schedule(ws_info, &ie_us->chan_plan, "US-IE");
}

bool ws_ie_validate_bs(const struct ws_info *ws_info, const struct ws_bs_ie *ie_bs)
{
    return ws_ie_validate_schedule(ws_info, &ie_bs->chan_plan, "BS-IE");
}

bool ws_ie_validate_lcp(const struct ws_info *ws_info, const struct ws_lcp_ie *ie_lcp)
{
    if (ie_lcp->chan_plan.channel_plan != 2) {
        TRACE(TR_DROP, "drop %-9s: LCP-IE channel plan invalid", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(ws_info, &ie_lcp->chan_plan, "LCP-IE");
}

bool ws_ie_validate_netname(const struct ws_info *ws_info, const struct ws_netname_ie *ie_netname)
{
    if (strcmp(ws_info->network_name, ie_netname->netname)) {
        TRACE(TR_DROP, "drop %-9s: NETNAME-IE mismatch", "15.4-mngt");
        return false;
    }
    return true;
}
