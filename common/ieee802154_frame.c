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
#include "common/endian.h"
#include "common/log.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/memutils.h"
#include "common/specs/ieee802154.h"
#include "ieee802154_frame.h"

// IEEE 802.15.4-2020 Figure 7-2 Format of the Frame Control field
#define IEEE802154_MASK_FCF_FRAME_TYPE    0b0000000000000111
#define IEEE802154_MASK_FCF_SECURED       0b0000000000001000
#define IEEE802154_MASK_FCF_FRAME_PENDING 0b0000000000010000
#define IEEE802154_MASK_FCF_ACK_REQ       0b0000000000100000
#define IEEE802154_MASK_FCF_PAN_ID_CMPR   0b0000000001000000
#define IEEE802154_MASK_FCF_DEL_SEQNO     0b0000000100000000
#define IEEE802154_MASK_FCF_HAS_IE        0b0000001000000000
#define IEEE802154_MASK_FCF_DST_ADDR_MODE 0b0000110000000000
#define IEEE802154_MASK_FCF_FRAME_VERSION 0b0011000000000000
#define IEEE802154_MASK_FCF_SRC_ADDR_MODE 0b1100000000000000

#define IEEE802154_MASK_SECHDR_LEVEL        0b00000111
#define IEEE802154_MASK_SECHDR_KEY_ID_MODE  0b00011000
#define IEEE802154_MASK_SECHDR_DEL_FRAMECTR 0b00100000
#define IEEE802154_MASK_SECHDR_ASN_IN_NONCE 0b01000000

const struct eui64 ieee802154_addr_bc = IEEE802154_ADDR_BC_INIT;

// IEEE 802.15.4-2020 Table 7-2 PAN ID Compression field value for frame version 0b10
static const struct {
    uint8_t dst_addr_mode;
    uint8_t src_addr_mode;
    bool has_dst_pan_id;
    bool has_src_pan_id;
    bool pan_id_cmpr;
} ieee802154_table_pan_id_cmpr[] = {
//  { IEEE802154_ADDR_MODE_NONE,   IEEE802154_ADDR_MODE_NONE,   false, false, 0 }, // Unsupported
//  { IEEE802154_ADDR_MODE_NONE,   IEEE802154_ADDR_MODE_NONE,   true,  false, 1 }, // Unsupported
//  { IEEE802154_ADDR_MODE_16_BIT, IEEE802154_ADDR_MODE_NONE,   true,  false, 0 }, // Unsupported
//  { IEEE802154_ADDR_MODE_64_BIT, IEEE802154_ADDR_MODE_NONE,   true,  false, 0 }, // Unsupported
//  { IEEE802154_ADDR_MODE_16_BIT, IEEE802154_ADDR_MODE_NONE,   false, false, 1 }, // Unsupported
    { IEEE802154_ADDR_MODE_64_BIT, IEEE802154_ADDR_MODE_NONE,   false, false, 1 },
//  { IEEE802154_ADDR_MODE_NONE,   IEEE802154_ADDR_MODE_16_BIT, false, true,  0 }, // Unsupported
    { IEEE802154_ADDR_MODE_NONE,   IEEE802154_ADDR_MODE_64_BIT, false, true,  0 },
//  { IEEE802154_ADDR_MODE_NONE,   IEEE802154_ADDR_MODE_16_BIT, false, false, 1 }, // Unsupported
    { IEEE802154_ADDR_MODE_NONE,   IEEE802154_ADDR_MODE_64_BIT, false, false, 1 },
//  { IEEE802154_ADDR_MODE_64_BIT, IEEE802154_ADDR_MODE_64_BIT, true,  false, 0 }, // Unsupported
    { IEEE802154_ADDR_MODE_64_BIT, IEEE802154_ADDR_MODE_64_BIT, false, false, 1 },
//  { IEEE802154_ADDR_MODE_16_BIT, IEEE802154_ADDR_MODE_16_BIT, true,  true,  0 }, // Unsupported
//  { IEEE802154_ADDR_MODE_16_BIT, IEEE802154_ADDR_MODE_64_BIT, true,  true,  0 }, // Unsupported
//  { IEEE802154_ADDR_MODE_64_BIT, IEEE802154_ADDR_MODE_16_BIT, true,  true,  0 }, // Unsupported
//  { IEEE802154_ADDR_MODE_16_BIT, IEEE802154_ADDR_MODE_64_BIT, true,  false, 1 }, // Unsupported
//  { IEEE802154_ADDR_MODE_64_BIT, IEEE802154_ADDR_MODE_16_BIT, true,  false, 1 }, // Unsupported
//  { IEEE802154_ADDR_MODE_16_BIT, IEEE802154_ADDR_MODE_16_BIT, true,  false, 1 }, // Unsupported
};

static int ieee802154_frame_parse_sec(struct iobuf_read *iobuf, struct ieee802154_hdr *hdr)
{
    uint8_t scf;

    scf = iobuf_pop_u8(iobuf);
    if (FIELD_GET(IEEE802154_MASK_SECHDR_LEVEL, scf) != IEEE802154_SEC_LEVEL_ENC_MIC64) {
        TRACE(TR_DROP, "drop %-9s: unsupported security level", "15.4");
        return -ENOTSUP;
    }
    if (FIELD_GET(IEEE802154_MASK_SECHDR_KEY_ID_MODE, scf) != IEEE802154_KEY_ID_MODE_IDX) {
        TRACE(TR_DROP, "drop %-9s: unsupported security level", "15.4");
        return -ENOTSUP;
    }
    if (FIELD_GET(IEEE802154_MASK_SECHDR_DEL_FRAMECTR, scf)) {
        TRACE(TR_DROP, "drop %-9s: unsupported frame counter suppression", "15.4");
        return -ENOTSUP;
    }
    if (FIELD_GET(IEEE802154_MASK_SECHDR_ASN_IN_NONCE, scf))
        TRACE(TR_IGNORE, "ignore %-9s: ASN in nonce", "15.4");

    hdr->frame_counter = iobuf_pop_le32(iobuf);
    hdr->key_index     = iobuf_pop_u8(iobuf);

    if (iobuf_remaining_size(iobuf) < 8) {
        TRACE(TR_DROP, "drop %-9s: missing MIC-64", "15.4");
        return -EINVAL;
    }
    iobuf->data_size -= 8;

    return 0;
}

static int ieee802154_frame_parse_ie(struct iobuf_read *iobuf,
                                     struct iobuf_read *ie_header,
                                     struct iobuf_read *ie_payload)
{
    struct iobuf_read iobuf_ie;
    int ret;

    memset(ie_header, 0, sizeof(*ie_header));
    memset(ie_payload, 0, sizeof(*ie_payload));

    ret = ieee802154_ie_find_header(iobuf_ptr(iobuf), iobuf_remaining_size(iobuf),
                                    IEEE802154_IE_ID_HT1, &iobuf_ie);
    if (ret < 0 && ret != -ENOENT) {
        TRACE(TR_DROP, "drop %-9s: malformed IEs", "15.4");
        return ret;
    }

    if (!ret || !ieee802154_ie_find_header(iobuf_ptr(iobuf), iobuf_remaining_size(iobuf),
                                           IEEE802154_IE_ID_HT2, &iobuf_ie)) {
        ie_header->data_size = iobuf_ptr(&iobuf_ie) - 2 - iobuf_ptr(iobuf);
        ie_header->data = (void *)iobuf_pop_data_ptr(iobuf, ie_header->data_size);
        iobuf_pop_le16(iobuf); // Header Termination IE
    } else {
        ie_header->data_size = iobuf_remaining_size(iobuf);
        ie_header->data = (void *)iobuf_pop_data_ptr(iobuf, ie_header->data_size);
    }

    if (ret == -ENOENT)
        return 0;

    ret = ieee802154_ie_find_payload(iobuf_ptr(iobuf), iobuf_remaining_size(iobuf),
                                     IEEE802154_IE_ID_PT, &iobuf_ie);
    if (ret < 0 && ret != -ENOENT) {
        TRACE(TR_DROP, "drop %-9s: malformed IEs", "15.4");
        return ret;
    }

    if (!ret) {
        ie_payload->data_size = iobuf_ptr(&iobuf_ie) - 2 - iobuf_ptr(iobuf);
        ie_payload->data = (void *)iobuf_pop_data_ptr(iobuf, ie_payload->data_size);
        iobuf_pop_le16(iobuf); // Payload Termination IE
    } else {
        ie_payload->data_size = iobuf_remaining_size(iobuf);
        ie_payload->data = (void *)iobuf_pop_data_ptr(iobuf, ie_payload->data_size);
    }

    return 0;
}

int ieee802154_frame_parse(const uint8_t *frame, size_t frame_len,
                           struct ieee802154_hdr *hdr,
                           struct iobuf_read *ie_header,
                           struct iobuf_read *ie_payload)
{
    struct iobuf_read iobuf = {
        .data_size = frame_len,
        .data = frame,
    };
    uint8_t dst_addr_mode;
    uint8_t src_addr_mode;
    bool pan_id_cmpr;
    uint16_t fcf;
    int ret, i;

    fcf = iobuf_pop_le16(&iobuf);
    hdr->frame_type = FIELD_GET(IEEE802154_MASK_FCF_FRAME_TYPE, fcf);
    if (hdr->frame_type != IEEE802154_FRAME_TYPE_DATA &&
        hdr->frame_type != IEEE802154_FRAME_TYPE_ACK) {
        TRACE(TR_DROP, "drop %-9s: unsupported frame type", "15.4");
        return -ENOTSUP;
    }
    if (FIELD_GET(IEEE802154_MASK_FCF_FRAME_VERSION, fcf) != IEEE802154_FRAME_VERSION_2015) {
        TRACE(TR_DROP, "drop %-9s: unsupported frame version", "15.4");
        return -ENOTSUP;
    }
    if (FIELD_GET(IEEE802154_MASK_FCF_FRAME_PENDING, fcf))
        TRACE(TR_IGNORE, "ignore %-9s: frame pending bit", "15.4");

    hdr->ack_req = FIELD_GET(IEEE802154_MASK_FCF_ACK_REQ, fcf);

    hdr->seqno = -1;
    if (!FIELD_GET(IEEE802154_MASK_FCF_DEL_SEQNO, fcf))
        hdr->seqno = iobuf_pop_u8(&iobuf);

    pan_id_cmpr   = FIELD_GET(IEEE802154_MASK_FCF_PAN_ID_CMPR,   fcf);
    dst_addr_mode = FIELD_GET(IEEE802154_MASK_FCF_DST_ADDR_MODE, fcf);
    src_addr_mode = FIELD_GET(IEEE802154_MASK_FCF_SRC_ADDR_MODE, fcf);
    for (i = 0; i < ARRAY_SIZE(ieee802154_table_pan_id_cmpr); i++)
        if (ieee802154_table_pan_id_cmpr[i].dst_addr_mode == dst_addr_mode &&
            ieee802154_table_pan_id_cmpr[i].src_addr_mode == src_addr_mode &&
            ieee802154_table_pan_id_cmpr[i].pan_id_cmpr   == pan_id_cmpr)
            break;
    if (i == ARRAY_SIZE(ieee802154_table_pan_id_cmpr)) {
        TRACE(TR_DROP, "drop %-9s: unsupported address mode", "15.4");
        return -ENOTSUP;
    }

    BUG_ON(ieee802154_table_pan_id_cmpr[i].has_dst_pan_id);

    if (ieee802154_table_pan_id_cmpr[i].dst_addr_mode == IEEE802154_ADDR_MODE_64_BIT)
        hdr->dst.be64 = htobe64(iobuf_pop_le64(&iobuf));
    else
        hdr->dst = ieee802154_addr_bc;

    hdr->pan_id = 0xffff;
    if (ieee802154_table_pan_id_cmpr[i].has_src_pan_id)
        hdr->pan_id = iobuf_pop_le16(&iobuf);


    if (ieee802154_table_pan_id_cmpr[i].src_addr_mode == IEEE802154_ADDR_MODE_64_BIT)
        hdr->src.be64 = htobe64(iobuf_pop_le64(&iobuf));
    else
        hdr->src = ieee802154_addr_bc;

    hdr->key_index = 0;
    if (FIELD_GET(IEEE802154_MASK_FCF_SECURED, fcf)) {
        ret = ieee802154_frame_parse_sec(&iobuf, hdr);
        if (ret < 0)
            return ret;
    }

    if (FIELD_GET(IEEE802154_MASK_FCF_HAS_IE, fcf)) {
        ret = ieee802154_frame_parse_ie(&iobuf, ie_header, ie_payload);
        if (ret < 0)
            return ret;
    }

    if (iobuf_remaining_size(&iobuf))
        TRACE(TR_IGNORE, "ignore %-9s: unsupported frame payload", "15.4");

    if (iobuf.err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "15.4");
        return -EINVAL;
    }

    return 0;
}

void ieee802154_frame_write_hdr(struct iobuf_write *iobuf,
                                const struct ieee802154_hdr *hdr)
{
    uint8_t dst_addr_mode = !memcmp(&ieee802154_addr_bc, &hdr->dst, 8) ?
                            IEEE802154_ADDR_MODE_NONE :
                            IEEE802154_ADDR_MODE_64_BIT;
    uint8_t src_addr_mode = !memcmp(&ieee802154_addr_bc, &hdr->src, 8) ?
                            IEEE802154_ADDR_MODE_NONE :
                            IEEE802154_ADDR_MODE_64_BIT;
    int i;

    for (i = 0; i < ARRAY_SIZE(ieee802154_table_pan_id_cmpr); i++)
        if (ieee802154_table_pan_id_cmpr[i].dst_addr_mode  == dst_addr_mode &&
            ieee802154_table_pan_id_cmpr[i].has_src_pan_id == (hdr->pan_id != 0xffff))
            break;
    BUG_ON(i == ARRAY_SIZE(ieee802154_table_pan_id_cmpr));

    iobuf_push_le16(iobuf, FIELD_PREP(IEEE802154_MASK_FCF_FRAME_TYPE,    hdr->frame_type)
                         | FIELD_PREP(IEEE802154_MASK_FCF_SECURED,       hdr->key_index != 0)
                         | FIELD_PREP(IEEE802154_MASK_FCF_ACK_REQ,       hdr->ack_req)
                         | FIELD_PREP(IEEE802154_MASK_FCF_PAN_ID_CMPR,   ieee802154_table_pan_id_cmpr[i].pan_id_cmpr)
                         | FIELD_PREP(IEEE802154_MASK_FCF_DEL_SEQNO,     hdr->seqno < 0)
                         | FIELD_PREP(IEEE802154_MASK_FCF_HAS_IE,        true)
                         | FIELD_PREP(IEEE802154_MASK_FCF_DST_ADDR_MODE, dst_addr_mode)
                         | FIELD_PREP(IEEE802154_MASK_FCF_FRAME_VERSION, IEEE802154_FRAME_VERSION_2015)
                         | FIELD_PREP(IEEE802154_MASK_FCF_SRC_ADDR_MODE, src_addr_mode));

    if (hdr->seqno >= 0)
        iobuf_push_u8(iobuf, hdr->seqno);

    BUG_ON(ieee802154_table_pan_id_cmpr[i].has_dst_pan_id);
    if (dst_addr_mode == IEEE802154_ADDR_MODE_64_BIT)
        iobuf_push_le64(iobuf, be64toh(hdr->dst.be64));
    if (hdr->pan_id != 0xffff)
        iobuf_push_le16(iobuf, hdr->pan_id);
    if (src_addr_mode == IEEE802154_ADDR_MODE_64_BIT)
        iobuf_push_le64(iobuf, be64toh(hdr->src.be64));

    if (hdr->key_index) {
        iobuf_push_u8(iobuf, FIELD_PREP(IEEE802154_MASK_SECHDR_LEVEL,       IEEE802154_SEC_LEVEL_ENC_MIC64)
                           | FIELD_PREP(IEEE802154_MASK_SECHDR_KEY_ID_MODE, IEEE802154_KEY_ID_MODE_IDX));
        iobuf_push_data_reserved(iobuf, 4); // Frame Counter
        iobuf_push_u8(iobuf, hdr->key_index);
    }
}
