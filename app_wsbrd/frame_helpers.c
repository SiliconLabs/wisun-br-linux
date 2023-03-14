/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#include <stdbool.h>
#include <string.h>

#include "common/log.h"
#include "common/string_extra.h"
#include "common/utils.h"
#include "common/endian.h"
#include "common/bits.h"

#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mac_mcps.h"

#include "frame_helpers.h"

// Figure 7-2 Format of the Frame Control field
#define IEEE802154_FCF_FRAME_TYPE         0b0000000000000111
#define IEEE802154_FCF_SECURITY_ENABLED   0b0000000000001000
#define IEEE802154_FCF_FRAME_PENDING      0b0000000000010000
#define IEEE802154_FCF_ACK_REQ            0b0000000000100000
#define IEEE802154_FCF_PAN_ID_COMPRESSION 0b0000000001000000
#define IEEE802154_FCF_SEQ_NUM_SUPPR      0b0000000100000000
#define IEEE802154_FCF_IE_PRESENT         0b0000001000000000
#define IEEE802154_FCF_DST_ADDR_MODE      0b0000110000000000
#define IEEE802154_FCF_FRAME_VERSION      0b0011000000000000
#define IEEE802154_FCF_SRC_ADDR_MODE      0b1100000000000000

// Table 7-1 Values of the Frame Type field
#define IEEE802154_FRAME_TYPE_DATA 0b001

// Figure 7-21 Format of Header IEs
#define IEEE802154_HEADER_IE_LEN_MASK  0b0000000001111111
#define IEEE802154_HEADER_IE_ID_MASK   0b0111111110000000
#define IEEE802154_HEADER_IE_TYPE_MASK 0b1000000000000000
#define IEEE802154_HEADER_IE(len, id) (               \
      FIELD_PREP(IEEE802154_HEADER_IE_LEN_MASK,  len) \
    | FIELD_PREP(IEEE802154_HEADER_IE_ID_MASK,   id ) \
    | FIELD_PREP(IEEE802154_HEADER_IE_TYPE_MASK, 0  ) \
)

// Figure 7-46 Format of Payload IEs
#define IEEE802154_PAYLOAD_IE_LEN_MASK  0b0000011111111111
#define IEEE802154_PAYLOAD_IE_ID_MASK   0b0111100000000000
#define IEEE802154_PAYLOAD_IE_TYPE_MASK 0b1000000000000000
#define IEEE802154_PAYLOAD_IE(len, id) (               \
      FIELD_PREP(IEEE802154_PAYLOAD_IE_LEN_MASK,  len) \
    | FIELD_PREP(IEEE802154_PAYLOAD_IE_ID_MASK,   id ) \
    | FIELD_PREP(IEEE802154_PAYLOAD_IE_TYPE_MASK, 1  ) \
)

// Table 7-7 Element IDs for Header IEs
#define IEEE802154_IE_ID_HT1 0x7e
#define IEEE802154_IE_ID_HT2 0x7f
// Table 7-15 Payload IE Group ID
#define IEEE802154_IE_ID_PT  0xf

// 7.4.2.17 Header Termination 1 IE
#define IEEE802154_IE_HT1 IEEE802154_HEADER_IE(0, IEEE802154_IE_ID_HT1)
// 7.4.2.18 Header Termination 2 IE
#define IEEE802154_IE_HT2 IEEE802154_HEADER_IE(0, IEEE802154_IE_ID_HT2)
// 7.4.3.3 Payload Termination IE
#define IEEE802154_IE_PT IEEE802154_PAYLOAD_IE(0, IEEE802154_IE_ID_PT)

// Table 7-2 PAN ID Compression field value for frame version 0b10
static const struct {
    uint8_t dst_addr_mode;
    uint8_t src_addr_mode;
    bool dst_pan_id;
    bool src_pan_id;
    bool pan_id_compression;
} ieee802154_table_pan_id_comp[] = {
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_NONE,   false, false, 0 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_NONE,   true,  false, 1 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_NONE,   true,  false, 0 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_NONE,   true,  false, 0 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_NONE,   false, false, 1 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_NONE,   false, false, 1 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_16_BIT, false, true,  0 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_64_BIT, false, true,  0 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_16_BIT, false, false, 1 },
    { MAC_ADDR_MODE_NONE,   MAC_ADDR_MODE_64_BIT, false, false, 1 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_64_BIT, true,  false, 0 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_64_BIT, false, false, 1 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_16_BIT, true,  true,  0 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_64_BIT, true,  true,  0 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_16_BIT, true,  true,  0 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_64_BIT, true,  false, 1 },
    { MAC_ADDR_MODE_64_BIT, MAC_ADDR_MODE_16_BIT, true,  false, 1 },
    { MAC_ADDR_MODE_16_BIT, MAC_ADDR_MODE_16_BIT, true,  false, 1 },
};

// Table 7-6 termination IE inclusion rules
static const struct {
    bool header_ie;
    bool payload_ie;
    bool data_payload;
    uint16_t ie_ht;
    uint16_t ie_pt;
} ieee802154_table_term_ie[] = {
    { false, false, false, 0,                 0                },
    { true,  false, false, 0,                 0                },
    { false, true,  false, IEEE802154_IE_HT1, 0                },
    { true,  true,  false, IEEE802154_IE_HT1, 0                },
    { false, false, true,  0,                 0                },
    { true,  false, true,  IEEE802154_IE_HT2, 0                },
    { false, true,  true,  IEEE802154_IE_HT1, IEEE802154_IE_PT },
    { true,  true,  true,  IEEE802154_IE_HT1, IEEE802154_IE_PT },
};

int wsbr_data_ind_rebuild(uint8_t frame[],
                         const struct mcps_data_ind *ind,
                         const struct mcps_data_ie_list *ie)
{
    uint8_t *start = frame;
    uint16_t fcf;
    int i;

    fcf = FIELD_PREP(IEEE802154_FCF_FRAME_TYPE,         IEEE802154_FRAME_TYPE_DATA)
        | FIELD_PREP(IEEE802154_FCF_SECURITY_ENABLED,   false)
        | FIELD_PREP(IEEE802154_FCF_FRAME_PENDING,      ind->PendingBit)
        | FIELD_PREP(IEEE802154_FCF_ACK_REQ,            ind->TxAckReq)
        | FIELD_PREP(IEEE802154_FCF_PAN_ID_COMPRESSION, ind->PanIdSuppressed)
        | FIELD_PREP(IEEE802154_FCF_SEQ_NUM_SUPPR,      ind->DSN_suppressed)
        | FIELD_PREP(IEEE802154_FCF_IE_PRESENT,         ie->headerIeListLength || ie->payloadIeListLength)
        | FIELD_PREP(IEEE802154_FCF_DST_ADDR_MODE,      ind->DstAddrMode)
        | FIELD_PREP(IEEE802154_FCF_FRAME_VERSION,      MAC_FRAME_VERSION_2015)
        | FIELD_PREP(IEEE802154_FCF_SRC_ADDR_MODE,      ind->SrcAddrMode);
    frame = write_le16(frame, fcf);
    if (!ind->DSN_suppressed)
        *frame++ = ind->DSN;

    for (i = 0; i < ARRAY_SIZE(ieee802154_table_pan_id_comp); i++)
        if (ieee802154_table_pan_id_comp[i].dst_addr_mode      == ind->DstAddrMode &&
            ieee802154_table_pan_id_comp[i].src_addr_mode      == ind->SrcAddrMode &&
            ieee802154_table_pan_id_comp[i].pan_id_compression == ind->PanIdSuppressed)
            break;
    BUG_ON(i == ARRAY_SIZE(ieee802154_table_pan_id_comp), "invalid address mode");
    if (ieee802154_table_pan_id_comp[i].dst_pan_id)
        frame = write_le16(frame, ind->DstPANId);
    if (ind->DstAddrMode == MAC_ADDR_MODE_64_BIT) {
        memrcpy(frame, ind->DstAddr, 8);
        frame += 8;
    } else if (ind->DstAddrMode == MAC_ADDR_MODE_16_BIT) {
        memrcpy(frame, ind->DstAddr, 2);
        frame += 2;
    }
    if (ieee802154_table_pan_id_comp[i].src_pan_id)
        frame = write_le16(frame, ind->SrcPANId);
    if (ind->SrcAddrMode == MAC_ADDR_MODE_64_BIT) {
        memrcpy(frame, ind->SrcAddr, 8);
        frame += 8;
    } else if (ind->SrcAddrMode == MAC_ADDR_MODE_16_BIT) {
        memrcpy(frame, ind->SrcAddr, 2);
        frame += 2;
    }

    for (i = 0; i < ARRAY_SIZE(ieee802154_table_term_ie); i++)
        if (ieee802154_table_term_ie[i].header_ie    == (bool)ie->headerIeListLength  &&
            ieee802154_table_term_ie[i].payload_ie   == (bool)ie->payloadIeListLength &&
            ieee802154_table_term_ie[i].data_payload == (bool)ind->msduLength)
            break;
    memcpy(frame, ie->headerIeList, ie->headerIeListLength);
    frame += ie->headerIeListLength;
    if (ieee802154_table_term_ie[i].ie_ht)
        frame = write_le16(frame, ieee802154_table_term_ie[i].ie_ht);
    memcpy(frame, ie->payloadIeList, ie->payloadIeListLength);
    frame += ie->payloadIeListLength;
    if (ieee802154_table_term_ie[i].ie_pt)
        frame = write_le16(frame, ieee802154_table_term_ie[i].ie_pt);
    memcpy(frame, ind->msdu_ptr, ind->msduLength);
    frame += ind->msduLength;

    return frame - start;
}