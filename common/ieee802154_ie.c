#include "common/bits.h"
#include "common/endian.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/utils.h"
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
    if (len >= (1u << __builtin_popcount(len_mask)))
        BUG("IE length too big (%d)", len);
    BUG_ON(hdr & len_mask, "IE length already set");
    write_le16(ptr, hdr | FIELD_PREP(len_mask, len));
}
