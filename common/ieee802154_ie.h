/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef IEEE802154_IE_H
#define IEEE802154_IE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct iobuf_read;
struct iobuf_write;

#define IEEE802154_IE_TYPE_MASK             0b1000000000000000
#define IEEE802154_IE_TYPE_HEADER             0
#define IEEE802154_IE_TYPE_PAYLOAD            1
#define IEEE802154_IE_TYPE_NESTED_SHORT       0
#define IEEE802154_IE_TYPE_NESTED_LONG        1

// Figure 7-21 Format of Header IEs
#define IEEE802154_IE_HEADER_LEN_MASK       0b0000000001111111
#define IEEE802154_IE_HEADER_ID_MASK        0b0111111110000000
// Figure 7-46 Format of Payload IEs
#define IEEE802154_IE_PAYLOAD_LEN_MASK      0b0000011111111111
#define IEEE802154_IE_PAYLOAD_ID_MASK       0b0111100000000000
// Figure 7-48 Nested IE of type short format
#define IEEE802154_IE_NESTED_SHORT_LEN_MASK 0b0000000011111111
#define IEEE802154_IE_NESTED_SHORT_ID_MASK  0b0111111100000000
// Figure 7-49 Nested IE of type long format
#define IEEE802154_IE_NESTED_LONG_LEN_MASK  0b0000011111111111
#define IEEE802154_IE_NESTED_LONG_ID_MASK   0b0111100000000000

/*
 * Functions ieee802154_ie_push*() return an offset into the iobuf, pointing
 * to the start of the IE. An offset is returned instead of a pointer since
 * iobuf_push*() functions call realloc(), which can move data to another
 * address. This offset can then be used to fill the length field of an IE
 * once its content have been pushed. Typically one can write:
 *
 * ie_offset = ieee802154_ie_push_header(buf, id);
 * // iobuf_push*(buf, ...) calls
 * ieee802154_ie_fill_len_header(buf, ie_offset);
 */
int ieee802154_ie_push_header(struct iobuf_write *buf, uint8_t id);
int ieee802154_ie_push_payload(struct iobuf_write *buf, uint8_t id);
int ieee802154_ie_push_nested(struct iobuf_write *buf, uint8_t id, bool is_long);
void ieee802154_ie_fill_len_header(struct iobuf_write *buf, int offset);
void ieee802154_ie_fill_len_payload(struct iobuf_write *buf, int offset);
void ieee802154_ie_fill_len_nested(struct iobuf_write *buf, int offset, bool is_long);
void ieee802154_ie_set_len(struct iobuf_write *buf, int offset, uint16_t len, uint16_t len_mask);

int ieee802154_ie_find_header(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content);
int ieee802154_ie_find_payload(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content);
int ieee802154_ie_find_nested(const uint8_t *data, size_t len, uint8_t id, struct iobuf_read *ie_content, bool is_long);

#endif
