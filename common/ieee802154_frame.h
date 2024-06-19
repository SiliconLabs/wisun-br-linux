#ifndef IEEE802154_FRAME_H
#define IEEE802154_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct iobuf_read;
struct iobuf_write;

extern uint8_t ieee802154_addr_bc[8]; // ff:ff:ff:ff:ff:ff:ff:ff

struct ieee802154_hdr {
    uint8_t  frame_type;
    bool     ack_req;
    int      seqno;         // < 0 if elided
    uint16_t pan_id;        // 0xffff if elided
    uint8_t  dst[8];        // ff:ff:ff:ff:ff:ff:ff:ff if elided
    uint8_t  src[8];        // ff:ff:ff:ff:ff:ff:ff:ff if elided
    uint8_t  key_index;     // 0 if unsecured
    uint32_t frame_counter; // ignored if unsecured
};

int ieee802154_frame_parse(const uint8_t *frame, size_t frame_len,
                           struct ieee802154_hdr *hdr,
                           struct iobuf_read *ie_header,
                           struct iobuf_read *ie_payload);

void ieee802154_frame_write_hdr(struct iobuf_write *iobuf,
                                const struct ieee802154_hdr *hdr);

#endif
