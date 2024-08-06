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
#include <errno.h>

#include "common/bits.h"
#include "common/log.h"
#include "common/hif.h"
#include "common/parsers.h"
#include "common/ws_regdb.h"

#include "ws_chan_mask.h"

int ws_chan_mask_get_fixed(const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    int val = -EINVAL;

    for (int i = 0; i < 8 * WS_CHAN_MASK_LEN; i++) {
        if (bittest(chan_mask, i)) {
            if (val >= 0)
                return -EINVAL;
            val = i;
        }
    }
    return val;
}

int ws_chan_mask_width(const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    for (int i = WS_CHAN_MASK_LEN - 1; i >= 0; i--)
        if (chan_mask[i])
            return i + 1;
    return 0;
}

void ws_chan_mask_calc_reg(uint8_t  chan_mask[WS_CHAN_MASK_LEN],
                           const struct chan_params *chan_params,
                           uint8_t  regional_regulation)
{
    memset(chan_mask, 0xFF, 32);
    if (chan_params->chan_allowed)
        parse_bitmask(chan_mask, 32, chan_params->chan_allowed);
    if (regional_regulation == HIF_REG_ARIB) {
        // For now, ARIB is not supported for custom channel plans
        BUG_ON(!chan_params->valid_phy_modes[0]);
        // For now, ARIB is not supported outside of Japan
        BUG_ON(chan_params->reg_domain != REG_DOMAIN_JP);
        // Note: ChanPlanIds for JP already include these masks
        if (chan_params->op_class == 1)
            bitfill(chan_mask, false, 0, 8); // Allowed channels: "9-255"
        if (chan_params->op_class == 2)
            bitfill(chan_mask, false, 0, 3); // Allowed channels: "4-255"
        if (chan_params->op_class == 3)
            bitfill(chan_mask, false, 0, 2); // Allowed channels: "3-255"
    }
    bitfill(chan_mask, false, chan_params->chan_count, 255);
}

void ws_chan_mask_calc_excl(uint8_t chan_mask_excl[WS_CHAN_MASK_LEN],
                            const uint8_t chan_mask_reg[WS_CHAN_MASK_LEN],
                            const uint8_t chan_mask_custom[WS_CHAN_MASK_LEN])
{
    /*
     *   Wi-SUN FAN 1.1v08 6.3.2.3.2.1.3 Field Definitions
     * The Excluded Channel Control field MUST be set to 0 when the Channel
     * Function field is set to zero.
     */
    if (ws_chan_mask_get_fixed(chan_mask_custom) >= 0) {
        memset(chan_mask_excl, 0, WS_CHAN_MASK_LEN);
    } else {
        for (int i = 0; i < WS_CHAN_MASK_LEN; i++)
            chan_mask_excl[i] = chan_mask_reg[i] & ~chan_mask_custom[i];
    }
}

int ws_chan_mask_ranges(const uint8_t chan_mask[WS_CHAN_MASK_LEN])
{
    bool in_range = false;
    int cnt = 0;

    for (int i = 0; i < 8 * WS_CHAN_MASK_LEN; i++) {
        if (in_range != bittest(chan_mask, i)) {
            in_range = !in_range;
            cnt += in_range;
        }
    }
    return cnt;
}
