/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <errno.h>

#include "common/bits.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/memutils.h"

#include "ieee802154_ie.h"

static inline int ieee802154_ie_push(struct iobuf_write *buf, bool type, uint8_t id, uint16_t id_mask)
{
    int offset = buf->len;
    uint16_t hdr = 0;

    hdr |= FIELD_PREP(IEEE802154_IE_TYPE_MASK, type);
    hdr |= FIELD_PREP(id_mask, id);
    iobuf_push_le16(buf, hdr);
    return offset;
}

int ieee802154_ie_push_header(struct iobuf_write *buf, uint8_t id)
{
    return ieee802154_ie_push(buf, IEEE802154_IE_TYPE_HEADER,
                              id, IEEE802154_IE_HEADER_ID_MASK);
}

int ieee802154_ie_push_payload(struct iobuf_write *buf, uint8_t id)
{
    return ieee802154_ie_push(buf, IEEE802154_IE_TYPE_PAYLOAD,
                              id, IEEE802154_IE_PAYLOAD_ID_MASK);
}

int ieee802154_ie_push_nested(struct iobuf_write *buf, uint8_t id, bool is_long)
{
    if (is_long)
        return ieee802154_ie_push(buf, IEEE802154_IE_TYPE_NESTED_LONG,
                                  id, IEEE802154_IE_NESTED_LONG_ID_MASK);
    else
        return ieee802154_ie_push(buf, IEEE802154_IE_TYPE_NESTED_SHORT,
                                  id, IEEE802154_IE_NESTED_SHORT_ID_MASK);
}

static inline void ieee802154_ie_fill_len(struct iobuf_write *buf, int offset, uint16_t len_mask)
{
    ieee802154_ie_set_len(buf, offset, buf->len - offset - 2, len_mask);
}

void ieee802154_ie_fill_len_header(struct iobuf_write *buf, int offset)
{
    ieee802154_ie_fill_len(buf, offset, IEEE802154_IE_HEADER_LEN_MASK);
}

void ieee802154_ie_fill_len_payload(struct iobuf_write *buf, int offset)
{
    ieee802154_ie_fill_len(buf, offset, IEEE802154_IE_PAYLOAD_LEN_MASK);
}

void ieee802154_ie_fill_len_nested(struct iobuf_write *buf, int offset, bool is_long)
{
    if (is_long)
        ieee802154_ie_fill_len(buf, offset, IEEE802154_IE_NESTED_LONG_LEN_MASK);
    else
        ieee802154_ie_fill_len(buf, offset, IEEE802154_IE_NESTED_SHORT_LEN_MASK);
}

void ieee802154_ie_set_len(struct iobuf_write *buf, int offset, uint16_t len, uint16_t len_mask)
{
    uint8_t *ptr = buf->data + offset;
    uint16_t hdr;

    hdr = read_le16(ptr);
    if (len > FIELD_MAX(len_mask))
        BUG("IE length too big (%d)", len);
    BUG_ON(hdr & len_mask, "IE length already set");
    write_le16(ptr, hdr | FIELD_PREP(len_mask, len));
}

static int ieee802154_ie_find_non_nested(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content,
                                         bool type, uint16_t id_mask, uint16_t len_mask)
{
    struct iobuf_read input = {
        .data_size = len,
        .data = data,
    };
    uint16_t ie_hdr;
    int ie_len;

    memset(ie_content, 0, sizeof(struct iobuf_read));
    ie_content->err = true;
    while (iobuf_remaining_size(&input)) {
        ie_hdr = iobuf_pop_le16(&input);
        if (FIELD_GET(IEEE802154_IE_TYPE_MASK, ie_hdr) != type)
            return -EINVAL;
        ie_len = FIELD_GET(len_mask, ie_hdr);
        if (FIELD_GET(id_mask, ie_hdr) == id) {
            ie_content->data = iobuf_pop_data_ptr(&input, ie_len);
            if (!ie_content->data)
                return -EINVAL;
            ie_content->err = false;
            ie_content->data_size = ie_len;
            return ie_len;
        }
        iobuf_pop_data_ptr(&input, ie_len);
    }
    return -ENOENT;
}

int ieee802154_ie_find_header(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content)
{
    return ieee802154_ie_find_non_nested(data, len, id, ie_content, IEEE802154_IE_TYPE_HEADER,
                                         IEEE802154_IE_HEADER_ID_MASK, IEEE802154_IE_HEADER_LEN_MASK);
}

int ieee802154_ie_find_payload(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content)
{
    return ieee802154_ie_find_non_nested(data, len, id, ie_content, IEEE802154_IE_TYPE_PAYLOAD,
                                         IEEE802154_IE_PAYLOAD_ID_MASK, IEEE802154_IE_PAYLOAD_LEN_MASK);
}

int ieee802154_ie_find_nested(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content, bool is_long)
{
    struct iobuf_read input = {
        .data_size = len,
        .data = data,
    };
    uint16_t len_mask, id_mask;
    bool ie_is_long;
    uint16_t ie_hdr;
    int ie_len;

    memset(ie_content, 0, sizeof(struct iobuf_read));
    ie_content->err = true;
    while (iobuf_remaining_size(&input)) {
        ie_hdr = iobuf_pop_le16(&input);
        ie_is_long = FIELD_GET(IEEE802154_IE_TYPE_MASK, ie_hdr) == IEEE802154_IE_TYPE_NESTED_LONG;
        if (ie_is_long) {
            len_mask = IEEE802154_IE_NESTED_LONG_LEN_MASK;
            id_mask  = IEEE802154_IE_NESTED_LONG_ID_MASK;
        } else {
            len_mask = IEEE802154_IE_NESTED_SHORT_LEN_MASK;
            id_mask  = IEEE802154_IE_NESTED_SHORT_ID_MASK;
        }
        ie_len = FIELD_GET(len_mask, ie_hdr);
        if (ie_is_long == is_long && FIELD_GET(id_mask, ie_hdr) == id) {
            ie_content->data = iobuf_pop_data_ptr(&input, ie_len);
            if (!ie_content->data)
                return -EINVAL;
            ie_content->err = false;
            ie_content->data_size = ie_len;
            return ie_len;
        }
        iobuf_pop_data_ptr(&input, ie_len);
    }
    return -ENOENT;
}
