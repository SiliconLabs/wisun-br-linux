/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/parsers.h"
#include "common/rand.h"
#include "common/ws_regdb.h"
#include "common/log.h"
#include "common/endian.h"
#include "common/ns_list.h"
#include "common/specs/icmpv6.h"
#include "common/mathutils.h"
#include "common/specs/ws.h"
#include "common/events_scheduler.h"

#include "6lowpan/mac/mpx_api.h"
#include "ws/ws_config.h"
#include "ws/ws_llc.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_bootstrap_6lbr.h"
#include "ws/ws_pae_controller.h"
#include "ws/ws_ie_lib.h"

#include "ws/ws_common.h"

int DEVICE_MIN_SENS = -93;

int8_t ws_common_generate_channel_list(uint8_t chan_mask[32],
                                       uint16_t chan_count,
                                       uint8_t regional_regulation,
                                       uint8_t regulatory_domain,
                                       uint8_t op_class,
                                       uint8_t chan_plan_id)
{
    const struct chan_params *chan_params;

    chan_params = ws_regdb_chan_params(regulatory_domain, chan_plan_id, op_class);
    WARN_ON(chan_params && chan_params->chan_count != chan_count);

    memset(chan_mask, 0xFF, 32);
    if (chan_params && chan_params->chan_allowed)
        parse_bitmask(chan_mask, 32, chan_params->chan_allowed);
    if (regional_regulation == HIF_REG_ARIB) {
        // For now, ARIB is not supported for custom channel plans
        BUG_ON(!chan_params);
        // For now, ARIB is not supported outside of Japan
        BUG_ON(chan_params->reg_domain != REG_DOMAIN_JP);
        // Note: if user specify a FAN1.1 channel plan, these mask are already
        // applied
        if (chan_params->op_class == 1)
            bitfill(chan_mask, false, 0, 8); // Allowed channels: "9-255"
        if (chan_params->op_class == 2)
            bitfill(chan_mask, false, 0, 3); // Allowed channels: "4-255"
        if (chan_params->op_class == 3)
            bitfill(chan_mask, false, 0, 2); // Allowed channels: "3-255"
    }
    bitfill(chan_mask, false, chan_count, 255);
    return 0;
}

void ws_common_calc_chan_excl(ws_excluded_channel_data_t *chan_excl, const uint8_t chan_mask_custom[],
                              const uint8_t chan_mask_reg[], uint16_t chan_count)
{
    bool in_range = false;
    int range_cnt = 0;

    /*
     *   Wi-SUN FAN 1.1v08 6.3.2.3.2.1.3 Field Definitions
     * The Excluded Channel Control field MUST be set to 0 when the Channel
     * Function field is set to zero.
     */
    if (ws_common_get_fixed_channel(chan_mask_custom) >= 0) {
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_NONE;
        return;
    }

    memset(chan_excl, 0, sizeof(ws_excluded_channel_data_t));
    for (uint16_t i = 0; i < chan_count; i++) {
        if (!bittest(chan_mask_reg, i) || bittest(chan_mask_custom, i)) {
            if (in_range)
                in_range = false;
            continue;
        }

        bitset(chan_excl->channel_mask, i);

        if (!in_range) {
            in_range = true;
            range_cnt++;
            if (range_cnt < WS_EXCLUDED_MAX_RANGE_TO_SEND) {
                chan_excl->excluded_range[range_cnt - 1].range_start = i;
                chan_excl->excluded_range_length = range_cnt;
            }
        }
        if (range_cnt <= WS_EXCLUDED_MAX_RANGE_TO_SEND)
            chan_excl->excluded_range[range_cnt - 1].range_end = i;
    }
    chan_excl->channel_mask_bytes_inline = roundup(chan_count, 8) / 8;

    if (!range_cnt)
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_NONE;
    else if (range_cnt <= WS_EXCLUDED_MAX_RANGE_TO_SEND &&
             1 + range_cnt * 4 < chan_excl->channel_mask_bytes_inline)
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_RANGE;
    else
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_BITMASK;
}

void ws_common_seconds_timer(int seconds)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    ws_bootstrap_seconds_timer(cur, seconds);
    ws_mngt_async_trickle_timer_cb(cur, seconds);
}

uint8_t ws_common_allow_child_registration(struct net_if *interface, const uint8_t *eui64, uint16_t aro_timeout)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, eui64);
    uint32_t lifetime_s = aro_timeout * 60;

    if (!ws_neigh)
        return ARO_TOPOLOGICALLY_INCORRECT;

    if (aro_timeout == 0) {
        //DeRegister Address Reg
        return ARO_SUCCESS;
    }

    ws_neigh_refresh(ws_neigh, lifetime_s);
    return ARO_SUCCESS;
}

bool ws_common_negative_aro_mark(struct net_if *interface, const uint8_t *eui64)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, eui64);

    if (!ws_neigh)
        return false;

    ws_neigh_refresh(ws_neigh, WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME);
    return true;
}

uint32_t ws_common_datarate_get_from_phy_mode(uint8_t phy_mode_id, uint8_t operating_mode)
{
    const struct phy_params *phy_params;

    phy_params = ws_regdb_phy_params(phy_mode_id, operating_mode);
    if (!phy_params)
        return 0;
    return phy_params->datarate;
}

uint32_t ws_common_datarate_get(struct net_if *cur)
{
    return ws_common_datarate_get_from_phy_mode(cur->ws_info.phy_config.phy_mode_id, cur->ws_info.phy_config.op_mode);
}

bool ws_common_is_valid_nr(uint8_t node_role)
{
    switch (node_role) {
    case WS_NR_ROLE_BR:
    case WS_NR_ROLE_ROUTER:
    case WS_NR_ROLE_LFN:
        return true;
    }
    return false;
}

// Wi-SUN FAN 1.1v07 - 3.1 Definitions
// Exponentially Weighted Moving Average (EWMA).
//
// Given a sequence of values X (t=0, 1, 2, 3, …), EWMA(t) is
// defined as S(X(t)) + (1-S)(EWMA(t-1)).
//
// … where …
//
// Smoothing Factor 0 < S < 1
// EWMA (0) = X(0).
float ws_common_rsl_calc(float rsl_dbm, int rx_power_dbm)
{
    if (isnan(rsl_dbm))
        return rx_power_dbm;
    else
        return (rx_power_dbm + 7 * rsl_dbm) / 8;
}

int ws_common_get_fixed_channel(const uint8_t bitmask[32])
{
    int val = -EINVAL;

    for (int i = 0; i < 256; i++) {
        if (bittest(bitmask, i)) {
            if (val >= 0)
                return -EINVAL;
            val = i;
        }
    }
    return val;
}
