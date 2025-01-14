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
#ifndef WS_CHAN_MASK_H
#define WS_CHAN_MASK_H

#include <stdint.h>

struct chan_params;

// Arbitrary value used internally. There can theoretically be more than 256
// channels, but this is currently not supported (eg. the 2.4GHz PHY).
#define WS_CHAN_MASK_LEN 32

// Get the channel number from a channel mask containing extactly 1 channel.
int ws_chan_mask_get_fixed(const uint8_t chan_mask[WS_CHAN_MASK_LEN]);

// Get the minimum number of bytes needed to represent the mask.
int ws_chan_mask_width(const uint8_t chan_mask[WS_CHAN_MASK_LEN]);

// Compute the channel mask based on regulation parameters.
void ws_chan_mask_calc_reg(uint8_t  chan_mask[WS_CHAN_MASK_LEN],
                           const struct chan_params *chan_params,
                           uint8_t  regional_regulation);

// Compute a mask of excluded channels for advertising in schedule IEs.
void ws_chan_mask_calc_excl(uint8_t chan_mask[WS_CHAN_MASK_LEN],
                            const uint8_t chan_mask_reg[WS_CHAN_MASK_LEN],
                            const uint8_t chan_mask_custom[WS_CHAN_MASK_LEN]);

// Count the number of ranges present in the mask. For example 01110011
// contains 2 ranges.
int ws_chan_mask_ranges(const uint8_t chan_mask[WS_CHAN_MASK_LEN]);

#endif
