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
#ifndef WS_IE_CUSTOM_H
#define WS_IE_CUSTOM_H

#include <sys/queue.h>
#include <stdint.h>
#include <stddef.h>

#include "common/iobuf.h"

// Wi-SUN TBU API v1.1.4 /config/borderRouter/informationElement
enum ws_ie_custom_type {
    WS_IE_CUSTOM_TYPE_HEADER       = 0,
    WS_IE_CUSTOM_TYPE_NESTED_SHORT = 1,
    WS_IE_CUSTOM_TYPE_NESTED_LONG  = 2,
};

struct ws_ie_custom {
    uint16_t frame_type_mask;
    enum ws_ie_custom_type ie_type;
    uint8_t ie_id;
    struct iobuf_write buf;
    SLIST_ENTRY(ws_ie_custom) link;
};

// Define struct ws_ie_custom_list
SLIST_HEAD(ws_ie_custom_list, ws_ie_custom);

// If frame_type_mask is 0, remove IE(type, id), otherwise insert/update IE(type, id).
int ws_ie_custom_update(struct ws_ie_custom_list *list, enum ws_ie_custom_type type, uint8_t id,
                        const uint8_t *content, size_t content_len, uint16_t frame_type_mask);
void ws_ie_custom_clear(struct ws_ie_custom_list *list);

#endif
