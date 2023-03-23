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
#include "common/iobuf.h"
#include "common/string_extra.h"
#include "common/utils.h"
#include "common/endian.h"
#include "common/bits.h"

#include "stack/mac/mlme.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/mac_api.h"

#include "nwk_interface/protocol.h"

#include "rcp_api.h"
#include "wsbr_mac.h"
#include "frame_helpers.h"

// IEEE 802.15.4-2020 Figure 7-2 Format of the Frame Control field
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

#define IEEE802154_SECURITY_LEVEL             0b00000111
#define IEEE802154_SECURITY_KEY_MODE          0b00011000
#define IEEE802154_SECURITY_FRAME_COUNT_SUPPR 0b00100000
#define IEEE802154_SECURITY_ASN_IN_NONCE      0b01000000

// IEEE 802.15.4-2020 Table 7-1 Values of the Frame Type field
#define IEEE802154_FRAME_TYPE_DATA 0b001

// IEEE 802.15.4-2020 Figure 7-21 Format of Header IEs
#define IEEE802154_HEADER_IE_LEN_MASK  0b0000000001111111
#define IEEE802154_HEADER_IE_ID_MASK   0b0111111110000000
#define IEEE802154_HEADER_IE_TYPE_MASK 0b1000000000000000
#define IEEE802154_HEADER_IE(len, id) (               \
      FIELD_PREP(IEEE802154_HEADER_IE_LEN_MASK,  len) \
    | FIELD_PREP(IEEE802154_HEADER_IE_ID_MASK,   id ) \
    | FIELD_PREP(IEEE802154_HEADER_IE_TYPE_MASK, 0  ) \
)

// IEEE 802.15.4-2020 Figure 7-47 Format of Payload IEs
#define IEEE802154_PAYLOAD_IE_LEN_MASK  0b0000011111111111
#define IEEE802154_PAYLOAD_IE_ID_MASK   0b0111100000000000
#define IEEE802154_PAYLOAD_IE_TYPE_MASK 0b1000000000000000
#define IEEE802154_PAYLOAD_IE(len, id) (               \
      FIELD_PREP(IEEE802154_PAYLOAD_IE_LEN_MASK,  len) \
    | FIELD_PREP(IEEE802154_PAYLOAD_IE_ID_MASK,   id ) \
    | FIELD_PREP(IEEE802154_PAYLOAD_IE_TYPE_MASK, 1  ) \
)

// IEEE 802.15.4-2020 Table 7-7 Element IDs for Header IEs
#define IEEE802154_IE_ID_HT1 0x7e
#define IEEE802154_IE_ID_HT2 0x7f
// IEEE 802.15.4-2020 Table 7-17 Payload IE Group ID
#define IEEE802154_IE_ID_PT  0xf

// IEEE 802.15.4-2020 7.4.2.18 Header Termination 1 IE
#define IEEE802154_IE_HT1 IEEE802154_HEADER_IE(0, IEEE802154_IE_ID_HT1)
// IEEE 802.15.4-2020 7.4.2.19 Header Termination 2 IE
#define IEEE802154_IE_HT2 IEEE802154_HEADER_IE(0, IEEE802154_IE_ID_HT2)
// IEEE 802.15.4-2020 7.4.3.4 Payload Termination IE
#define IEEE802154_IE_PT IEEE802154_PAYLOAD_IE(0, IEEE802154_IE_ID_PT)

// IEEE 802.15.4-2020 Table 7-2 PAN ID Compression field value for frame version
// 0b10
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

int wsbr_data_ind_rebuild(uint8_t frame[],
                         const struct mcps_data_ind *ind,
                         const struct mcps_data_ie_list *ie)
{
    uint8_t *start = frame;
    uint16_t fcf;
    int i;

    BUG_ON(ind->msduLength);
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

    memcpy(frame, ie->headerIeList, ie->headerIeListLength);
    frame += ie->headerIeListLength;
    if (ie->payloadIeListLength)
        frame = write_le16(frame, IEEE802154_IE_HT1);
    memcpy(frame, ie->payloadIeList, ie->payloadIeListLength);
    frame += ie->payloadIeListLength;

    return frame - start;
}

void wsbr_data_req_rebuild(struct iobuf_write *frame,
                           const struct rcp *rcp,
                           const struct arm_15_4_mac_parameters *mac,
                           const struct mcps_data_req *req,
                           const struct mcps_data_req_ie_list *ie)
{
    uint8_t tmp[8];
    uint16_t fcf;
    int i;

    BUG_ON(!ie);
    BUG_ON(req->msduLength);
    fcf = 0;
    fcf |= FIELD_PREP(IEEE802154_FCF_FRAME_TYPE,         IEEE802154_FRAME_TYPE_DATA);
    fcf |= FIELD_PREP(IEEE802154_FCF_SECURITY_ENABLED,   !!req->Key.SecurityLevel);
    fcf |= FIELD_PREP(IEEE802154_FCF_FRAME_PENDING,      req->PendingBit);
    fcf |= FIELD_PREP(IEEE802154_FCF_ACK_REQ,            req->TxAckReq);
    fcf |= FIELD_PREP(IEEE802154_FCF_PAN_ID_COMPRESSION, req->PanIdSuppressed);
    fcf |= FIELD_PREP(IEEE802154_FCF_SEQ_NUM_SUPPR,      req->SeqNumSuppressed);
    fcf |= FIELD_PREP(IEEE802154_FCF_IE_PRESENT,         ie->headerIovLength || ie->payloadIovLength);
    fcf |= FIELD_PREP(IEEE802154_FCF_DST_ADDR_MODE,      req->DstAddrMode);
    fcf |= FIELD_PREP(IEEE802154_FCF_FRAME_VERSION,      MAC_FRAME_VERSION_2015);
    fcf |= FIELD_PREP(IEEE802154_FCF_SRC_ADDR_MODE,      req->SrcAddrMode);
    iobuf_push_le16(frame, fcf);
    if (!req->SeqNumSuppressed)
        iobuf_push_data_reserved(frame, 1); // Sequence number

    for (i = 0; i < ARRAY_SIZE(ieee802154_table_pan_id_comp); i++)
        if (ieee802154_table_pan_id_comp[i].dst_addr_mode      == req->DstAddrMode &&
            ieee802154_table_pan_id_comp[i].src_addr_mode      == req->SrcAddrMode &&
            ieee802154_table_pan_id_comp[i].pan_id_compression == req->PanIdSuppressed)
            break;
    BUG_ON(i == ARRAY_SIZE(ieee802154_table_pan_id_comp), "invalid address mode");
    if (ieee802154_table_pan_id_comp[i].dst_pan_id)
        iobuf_push_le16(frame, req->DstPANId);
    if (req->DstAddrMode == MAC_ADDR_MODE_64_BIT) {
        memrcpy(tmp, req->DstAddr, 8);
        iobuf_push_data(frame, tmp, 8);
    } else if (req->DstAddrMode == MAC_ADDR_MODE_16_BIT) {
        memrcpy(tmp, req->DstAddr, 2);
        iobuf_push_data(frame, tmp, 2);
    }

    if (ieee802154_table_pan_id_comp[i].src_pan_id)
        iobuf_push_le16(frame, mac->pan_id);
    if (req->SrcAddrMode == MAC_ADDR_MODE_64_BIT) {
        memrcpy(tmp, rcp->eui64, 8);
        iobuf_push_data(frame, tmp, 8);
    } else if (req->SrcAddrMode == MAC_ADDR_MODE_16_BIT) {
        BUG("unsupported");
    }

    if (req->Key.SecurityLevel) {
        iobuf_push_u8(frame, FIELD_PREP(IEEE802154_SECURITY_KEY_MODE, req->Key.KeyIdMode) |
                             FIELD_PREP(IEEE802154_SECURITY_LEVEL, req->Key.SecurityLevel));
        iobuf_push_data_reserved(frame, 4);  // Frame counter (never suppressed)
        if (req->Key.KeyIdMode == MAC_KEY_ID_MODE_SRC8_IDX)
            iobuf_push_data(frame, req->Key.Keysource, 8);
        else if (req->Key.KeyIdMode == MAC_KEY_ID_MODE_SRC4_IDX)
            iobuf_push_data(frame, req->Key.Keysource, 4);
        else if (req->Key.KeyIdMode == MAC_KEY_ID_MODE_IDX)
            iobuf_push_u8(frame, req->Key.KeyIndex);
    }

    if (ie->headerIovLength > 0)
        iobuf_push_data(frame, ie->headerIeVectorList[0].iov_base, ie->headerIeVectorList[0].iov_len);
    BUG_ON(ie->headerIovLength > 1);

    if (ie->payloadIovLength)
        iobuf_push_le16(frame, IEEE802154_IE_HT1);

    if (ie->payloadIovLength > 0)
        iobuf_push_data(frame, ie->payloadIeVectorList[0].iov_base, ie->payloadIeVectorList[0].iov_len);
    if (ie->payloadIovLength > 1)
        iobuf_push_data(frame, ie->payloadIeVectorList[1].iov_base, ie->payloadIeVectorList[1].iov_len);
    BUG_ON(ie->payloadIovLength > 2);

    // MIC
    if (req->Key.SecurityLevel == SEC_MIC32 || req->Key.SecurityLevel == SEC_ENC_MIC32)
        iobuf_push_data_reserved(frame, 4);
    if (req->Key.SecurityLevel == SEC_MIC64 || req->Key.SecurityLevel == SEC_ENC_MIC64)
        iobuf_push_data_reserved(frame, 8);
    if (req->Key.SecurityLevel == SEC_MIC128 || req->Key.SecurityLevel == SEC_ENC_MIC128)
        iobuf_push_data_reserved(frame, 16);
}
