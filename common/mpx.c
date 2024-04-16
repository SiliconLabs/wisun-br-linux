/*
 * Copyright (c) 2018-2019, Pelion and affiliates.
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

#include "common/bits.h"
#include "common/iobuf.h"

#include "mpx.h"

// IEEE-802.15.9 Figure 10 Transaction Control field
#define MPX_IE_TRANSFER_TYPE_MASK  0b00000111
#define MPX_IE_TRANSACTION_ID_MASK 0b11111000

bool mpx_ie_parse(const uint8_t *ptr, uint16_t length, struct mpx_ie *ie)
{
    struct iobuf_read ie_buf = {
        .data_size = length,
        .data = ptr,
    };
    bool fragmented_number_present = false;
    bool multiplex_id_present = false;
    bool fragment_total_size = false;
    uint8_t tmp8;

    memset(ie, 0, sizeof(struct mpx_ie));
    tmp8 = iobuf_pop_u8(&ie_buf);
    ie->transfer_type  = FIELD_GET(MPX_IE_TRANSFER_TYPE_MASK,  tmp8);
    ie->transaction_id = FIELD_GET(MPX_IE_TRANSACTION_ID_MASK, tmp8);

    switch (ie->transfer_type) {
    case MPX_FT_FULL_FRAME:
        multiplex_id_present = true;
        break;
    case MPX_FT_FULL_FRAME_SMALL_MULTILEX_ID:
        break;
    case MPX_FT_FIRST_OR_SUB_FRAGMENT:
    case MPX_FT_LAST_FRAGMENT:
        fragmented_number_present = true;
        break;
    case MPX_FT_ABORT:
        fragment_total_size = (bool)iobuf_remaining_size(&ie_buf);
        break;
    default:
        return false;
    }
    if (fragmented_number_present) {
        ie->fragment_number = iobuf_pop_u8(&ie_buf);
        if (ie->fragment_number == 0) { // First fragment
            fragment_total_size = true;
            multiplex_id_present = true;
        }
    }
    if (fragment_total_size)
        ie->total_upper_layer_size = iobuf_pop_le16(&ie_buf);
    if (multiplex_id_present)
        ie->multiplex_id = iobuf_pop_le16(&ie_buf);
    ie->frame_ptr = iobuf_ptr(&ie_buf);
    ie->frame_length = iobuf_remaining_size(&ie_buf);
    return !ie_buf.err;
}

void mpx_ie_write(struct iobuf_write *buf, const struct mpx_ie *ie)
{
    bool fragmented_number_present = false;
    bool multiplex_id_present = false;
    bool fragment_total_size = false;
    uint8_t tmp8;

    tmp8 = 0;
    tmp8 |= FIELD_PREP(MPX_IE_TRANSFER_TYPE_MASK,  ie->transfer_type);
    tmp8 |= FIELD_PREP(MPX_IE_TRANSACTION_ID_MASK, ie->transaction_id);
    iobuf_push_u8(buf, tmp8);

    switch (ie->transfer_type) {
        case MPX_FT_FULL_FRAME:
            multiplex_id_present = true;
            break;
        case MPX_FT_FULL_FRAME_SMALL_MULTILEX_ID:
            break;
        case MPX_FT_FIRST_OR_SUB_FRAGMENT:
        case MPX_FT_LAST_FRAGMENT:
            fragmented_number_present = true;
            if (ie->fragment_number == 0) {
                fragment_total_size = true;
                multiplex_id_present = true;
            }
            break;
        case MPX_FT_ABORT:
            if (ie->total_upper_layer_size) {
                fragment_total_size = true;
            }
            break;
        default:
            break;
    }
    if (fragmented_number_present)
        iobuf_push_u8(buf, ie->fragment_number);
    if (fragment_total_size)
        iobuf_push_le16(buf, ie->total_upper_layer_size);
    if (multiplex_id_present)
        iobuf_push_le16(buf, ie->multiplex_id);
}
