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
#include <errno.h>
#include <stdlib.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/ieee802154_ie.h"
#include "common/sys_queue_extra.h"
#include "common/specs/ieee802154.h"

#include "ws_ie_list.h"

void ws_ie_list_clear(struct ws_ie_list *list)
{
    struct ws_ie *ie;

    while ((ie = SLIST_POP(list, link))) {
        iobuf_free(&ie->buf);
        free(ie);
    }
}

int ws_ie_list_update(struct ws_ie_list *list, enum ws_ie_type type, uint8_t id,
                         const uint8_t *content, size_t content_len, uint16_t frame_type_mask)
{
    struct ws_ie *ie;
    int offset;

    switch (type) {
    case WS_IE_TYPE_HEADER:
        if (content_len > FIELD_MAX(IEEE802154_IE_HEADER_LEN_MASK) - 1)
            return -EINVAL;
        break;
    case WS_IE_TYPE_NESTED_SHORT:
        if (content_len > FIELD_MAX(IEEE802154_IE_NESTED_SHORT_LEN_MASK) ||
            id          > FIELD_MAX(IEEE802154_IE_NESTED_SHORT_ID_MASK))
            return -EINVAL;
        break;
    case WS_IE_TYPE_NESTED_LONG:
        if (content_len > FIELD_MAX(IEEE802154_IE_NESTED_LONG_LEN_MASK) ||
            id          > FIELD_MAX(IEEE802154_IE_NESTED_LONG_ID_MASK))
            return -EINVAL;
        break;
    default:
        return -EINVAL;
    }

    ie = SLIST_FIND(ie, list, link, ie->ie_type == type && ie->ie_id == id);
    if (ie) {
        iobuf_free(&ie->buf);
        if (!frame_type_mask) {
            SLIST_REMOVE(list, ie, ws_ie, link);
            free(ie);
            return 0;
        }
    } else {
        ie = calloc(1, sizeof(struct ws_ie));
        if (!ie)
            return -errno;
        SLIST_INSERT_HEAD(list, ie, link);
    }

    ie->frame_type_mask = frame_type_mask;
    ie->ie_type         = type;
    ie->ie_id           = id;

    if (type == WS_IE_TYPE_HEADER) {
        offset = ieee802154_ie_push_header(&ie->buf, IEEE802154_IE_ID_WH);
        iobuf_push_u8(&ie->buf, id);
        iobuf_push_data(&ie->buf, content, content_len);
        ieee802154_ie_fill_len_header(&ie->buf, offset);
    } else {
        offset = ieee802154_ie_push_nested(&ie->buf, id, type == WS_IE_TYPE_NESTED_LONG);
        iobuf_push_data(&ie->buf, content, content_len);
        ieee802154_ie_fill_len_nested(&ie->buf, offset, type == WS_IE_TYPE_NESTED_LONG);
    }
    return 0;
}
