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
#include "common/log_legacy.h"
#include "common/endian.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mlme.h"

#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/rcp_api.h"
#include "app_wsbrd/dbus.h"
#include "app_wsbrd/wsbr.h"
#include "nwk_interface/protocol.h"

#include "6lowpan/mac/mac_helper.h"

#define TRACE_GROUP "MACh"

static const uint8_t mac_helper_default_key_source[8] = {0xff, 0, 0, 0, 0, 0, 0, 0};

static uint8_t mac_helper_header_security_aux_header_length(uint8_t keyIdmode);
static uint8_t mac_helper_security_mic_length_get(uint8_t security_level);

uint16_t mac_helper_panid_get(const struct net_if *interface)
{
    uint16_t panId = 0xffff;
    if (interface) {
        panId = interface->mac_parameters.pan_id;
    }
    return panId;
}

void mac_helper_set_default_key_source(struct net_if *interface)
{
    rcp_set_default_key_source(mac_helper_default_key_source);
}

int8_t mac_helper_security_key_to_descriptor_set(struct net_if *interface, const uint8_t *key, uint8_t id, uint8_t slot)
{
    uint8_t lookup_data[9];

    BUG_ON(!id);
    memcpy(lookup_data, mac_helper_default_key_source, 8);
    lookup_data[8] = id;
    rcp_set_key(slot, lookup_data, key);
    dbus_emit_keys_change(&g_ctxt);
    return 0;
}

int8_t mac_helper_security_key_descriptor_clear(struct net_if *interface, uint8_t slot)
{
    rcp_set_key(slot, NULL, NULL);
    return 0;
}

static bool mac_helper_write_16bit(uint16_t temp16, uint8_t *addrPtr)
{
    write_be16(addrPtr, temp16);
    return temp16 != 0xffff;
}

/* Write functions return "false" if they write an "odd" address, true if they
 * write a "normal" address. They still write odd addresses, as certain special
 * packets may want them, but this allows normal data paths to check and block
 * odd cases.
 * "Odd" is currently defined as PAN ID == 0xffff, or short address > 0xfffd.
 */
bool mac_helper_write_our_addr(struct net_if *interface, sockaddr_t *ptr)
{
    bool normal;

    BUG_ON(ptr->addr_type == ADDR_802_15_4_SHORT);
    //Set First PANID
    normal = mac_helper_write_16bit(interface->mac_parameters.pan_id, ptr->address);
    ptr->addr_type = ADDR_802_15_4_LONG;
    memcpy(&ptr->address[2], interface->mac, 8);
    return normal;
}

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

    if (cur->mac_parameters.mac_security_level && (!buf->options.ll_security_bypass_tx)) {
        length += mac_helper_header_security_aux_header_length(cur->mac_parameters.mac_key_id_mode);
        length += mac_helper_security_mic_length_get(cur->mac_parameters.mac_security_level);
    }

    return length;
}

static uint8_t mac_helper_security_mic_length_get(uint8_t security_level)
{
    uint8_t mic_length;
    switch (security_level) {
        case SEC_MIC32:
        case SEC_ENC_MIC32:
            mic_length = 4;
            break;
        case SEC_MIC64:
        case SEC_ENC_MIC64:
            mic_length = 8;
            break;
        case SEC_MIC128:
        case SEC_ENC_MIC128:
            mic_length = 16;
            break;
        case SEC_NONE:
        case SEC_ENC:
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
        case MAC_KEY_ID_MODE_SRC8_IDX:
            header_length += 4; //64-bit key source first part
        /* fall through  */
        case MAC_KEY_ID_MODE_SRC4_IDX:
            header_length += 4; //32-bit key source inline
        /* fall through  */
        case MAC_KEY_ID_MODE_IDX:
            header_length += 1;
            break;
        default:
            break;
    }
    return header_length;
}

int8_t mac_helper_key_link_frame_counter_read(int8_t interface_id, uint32_t *seq_ptr, uint8_t descriptor)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (!cur || !seq_ptr) {
        return -1;
    }
    rcp_get_frame_counter(descriptor);
    *seq_ptr = cur->rcp->frame_counter;

    return 0;
}
