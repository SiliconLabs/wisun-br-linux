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
#include "common/ws_types.h"
#include "common/iobuf.h"
#include "common/ws_ie.h"
#include "common/log.h"

#include "ws_ie_validation.h"

bool ws_ie_validate_chan_plan(struct ws_fhss_config *fhss, const struct ws_generic_channel_info *schedule)
{
    const struct ws_channel_plan_zero *plan0 = &schedule->plan.zero;
    const struct ws_channel_plan_one *plan1 = &schedule->plan.one;
    const struct ws_channel_plan_two *plan2 = &schedule->plan.two;
    const struct chan_params *parms = NULL;
    int plan_nr = schedule->channel_plan;

    if (plan_nr == 1)
        return plan1->ch0 * 1000      == fhss->chan_params->chan0_freq &&
               plan1->channel_spacing == ws_regdb_chan_spacing_id(fhss->chan_params->chan_spacing);
    if (plan_nr == 0)
        parms = ws_regdb_chan_params(plan0->regulatory_domain,
                                     0, plan0->operating_class);
    if (plan_nr == 2)
        parms = ws_regdb_chan_params(plan2->regulatory_domain,
                                     plan2->channel_plan_id, 0);
    if (!parms)
        return false;
    return parms->chan0_freq   == fhss->chan_params->chan0_freq &&
           parms->chan_spacing == fhss->chan_params->chan_spacing;
}

bool ws_ie_validate_schedule(struct ws_fhss_config *fhss, const struct ws_generic_channel_info *schedule)
{
    if (!ws_ie_validate_chan_plan(fhss, schedule)) {
        TRACE(TR_DROP, "drop %-9s: invalid channel plan", "15.4");
        return false;
    }

    switch (schedule->channel_function) {
    case WS_CHAN_FUNC_FIXED:
        if (schedule->function.zero.fixed_channel >= 8 * WS_CHAN_MASK_LEN) {
            TRACE(TR_DROP, "drop %-9s: fixed channel >= %u", "15.4", 8 * WS_CHAN_MASK_LEN);
            return false;
        }
        break;
    case WS_CHAN_FUNC_TR51CF:
    case WS_CHAN_FUNC_DH1CF:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported channel function", "15.4");
        return false;
    }

    switch (schedule->excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_NONE:
    case WS_EXC_CHAN_CTRL_RANGE:
    case WS_EXC_CHAN_CTRL_BITMASK:
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported excluded channel control", "15.4");
        return false;
    }
    return true;
}

bool ws_ie_validate_us(struct ws_fhss_config *fhss, const struct iobuf_read *ie_wp, struct ws_us_ie *ie_us)
{
    if (!ws_wp_nested_us_read(ie_wp->data, ie_wp->data_size, ie_us)) {
        TRACE(TR_DROP, "drop %-9s: missing US-IE", "15.4");
        return false;
    }
    if (ie_us->chan_plan.channel_function != WS_CHAN_FUNC_FIXED && !ie_us->dwell_interval) {
        TRACE(TR_DROP, "drop %-9s: invalid dwell interval", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(fhss, &ie_us->chan_plan);
}

bool ws_ie_validate_bs(struct ws_fhss_config *fhss, const struct iobuf_read *ie_wp, struct ws_bs_ie *ie_bs)
{
    if (!ws_wp_nested_bs_read(ie_wp->data, ie_wp->data_size, ie_bs)) {
        TRACE(TR_DROP, "drop %-9s: missing BS-IE", "15.4");
        return false;
    }
    return ws_ie_validate_schedule(fhss, &ie_bs->chan_plan);
}

bool ws_ie_validate_netname(const char *netname, const struct iobuf_read *ie_wp)
{
    struct ws_netname_ie ie_netname;

    if (!ws_wp_nested_netname_read(ie_wp->data, ie_wp->data_size, &ie_netname)) {
        TRACE(TR_DROP, "drop %-9s: missing NETNAME-IE", "15.4");
        return false;
    }
    if (strcmp(netname, ie_netname.netname)) {
        TRACE(TR_DROP, "drop %-9s: NETNAME-IE mismatch", "15.4");
        return false;
    }
    return true;
}

bool ws_ie_validate_pan(const struct iobuf_read *ie_wp, struct ws_pan_ie *ie_pan)
{
    if (!ws_wp_nested_pan_read(ie_wp->data, ie_wp->data_size, ie_pan)) {
        TRACE(TR_DROP, "drop %-9s: missing PAN-IE", "15.4");
        return false;
    }
    if (!ie_pan->routing_method) {
        TRACE(TR_DROP, "drop %-9s: unsupported routing method", "15.4");
        return false;
    }
    if (!ie_pan->use_parent_bs_ie)
        TRACE(TR_IGNORE, "ignore %-9s: unsupported local broadcast", "15.4");
    return true;
}
