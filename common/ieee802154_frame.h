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
#ifndef IEEE802154_FRAME_H
#define IEEE802154_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/eui64.h"

struct iobuf_read;
struct iobuf_write;

struct ieee802154_hdr {
    uint8_t  frame_type;
    bool     ack_req;
    int      seqno;         // < 0 if elided
    uint16_t pan_id;        // 0xffff if elided
    struct eui64 dst;       // ff:ff:ff:ff:ff:ff:ff:ff if elided
    struct eui64 src;       // ff:ff:ff:ff:ff:ff:ff:ff if elided
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
