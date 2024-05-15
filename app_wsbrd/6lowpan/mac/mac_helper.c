/*
 * Copyright (c) 2016-2021, Pelion and affiliates.
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
#include <stdlib.h>
#include <inttypes.h>
#include "common/log.h"
#include "common/endian.h"
#include "common/specs/ieee802154.h"

#include "app/wsbr_mac.h"
#include "net/ns_buffer.h"
#include "net/protocol.h"

#include "6lowpan/mac/mac_helper.h"

static uint8_t mac_helper_header_security_aux_header_length(uint8_t keyIdmode);
static uint8_t mac_helper_security_mic_length_get(uint8_t security_level);

/*
 * Given a buffer, with address and security flags set, compute the maximum
 * MAC payload that could be put in that buffer.
 */
uint_fast16_t mac_helper_max_payload_size(struct net_if *cur, uint_fast16_t frame_overhead)
{
    return cur->mac_parameters.mtu - frame_overhead;
}

/*
 * Given a buffer, with address and security flags set, compute the MAC overhead
 * size once MAC header and footer are added.
 * May not be accurate if MAC_MAX_PHY_PACKET_SIZE isn't set, implying a
 * non-standard MAC.
 */
uint_fast8_t mac_helper_frame_overhead(struct net_if *cur, const buffer_t *buf)
{
    uint_fast8_t length = 15;

    /*8bytes src address, 2 frame control, 1 sequence, 2 pan-id, 2 FCS*/
    if (buf->src_sa.addr_type == ADDR_802_15_4_SHORT) {
        length -= 6; //Cut 6 bytes from src address
    }

    if (memcmp(buf->dst_sa.address, buf->src_sa.address, 2) == 0) {
        length -= 2; // Cut Pan-id
    }

    if (buf->dst_sa.addr_type == ADDR_802_15_4_LONG) {
        length += 10;
    } else if (buf->dst_sa.addr_type == ADDR_802_15_4_SHORT || buf->dst_sa.addr_type == ADDR_BROADCAST) {
        length += 4;
    }

    length += mac_helper_header_security_aux_header_length(IEEE802154_KEY_ID_MODE_IDX);
    length += mac_helper_security_mic_length_get(IEEE802154_SEC_LEVEL_ENC_MIC64);

    return length;
}

static uint8_t mac_helper_security_mic_length_get(uint8_t security_level)
{
    uint8_t mic_length;
    switch (security_level) {
        case IEEE802154_SEC_LEVEL_MIC32:
        case IEEE802154_SEC_LEVEL_ENC_MIC32:
            mic_length = 4;
            break;
        case IEEE802154_SEC_LEVEL_MIC64:
        case IEEE802154_SEC_LEVEL_ENC_MIC64:
            mic_length = 8;
            break;
        case IEEE802154_SEC_LEVEL_MIC128:
        case IEEE802154_SEC_LEVEL_ENC_MIC128:
            mic_length = 16;
            break;
        case IEEE802154_SEC_LEVEL_NONE:
        case IEEE802154_SEC_LEVEL_ENC:
        default:
            mic_length = 0;
            break;
    }

    return mic_length;
}

static uint8_t mac_helper_header_security_aux_header_length(uint8_t keyIdmode)
{

    uint8_t header_length = 5; //Header + 32-bit counter
    switch (keyIdmode) {
        case IEEE802154_KEY_ID_MODE_SRC8_IDX:
            header_length += 4; //64-bit key source first part
        /* fall through  */
        case IEEE802154_KEY_ID_MODE_SRC4_IDX:
            header_length += 4; //32-bit key source inline
        /* fall through  */
        case IEEE802154_KEY_ID_MODE_IDX:
            header_length += 1;
            break;
        default:
            break;
    }
    return header_length;
}
