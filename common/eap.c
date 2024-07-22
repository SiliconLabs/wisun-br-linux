/*
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
#define _DEFAULT_SOURCE
#include <endian.h>

#include "common/specs/eap.h"
#include "common/pktbuf.h"

#include "eap.h"

const struct name_value eap_frames[] = {
    { "request",  EAP_CODE_REQUEST },
    { "response", EAP_CODE_RESPONSE },
    { "success",  EAP_CODE_SUCCESS },
    { "failure",  EAP_CODE_FAILURE },
};

const struct name_value eap_types[] = {
    { "identity",     EAP_TYPE_IDENTITY },
    { "notification", EAP_TYPE_NOTIFICATION },
    { "nak",          EAP_TYPE_NAK },
    { "tls",          EAP_TYPE_TLS },
};

void eap_write_hdr_head(struct pktbuf *buf, uint8_t code, uint8_t identifier, uint8_t type)
{
    struct eap_hdr hdr = {
        .code = code,
        .identifier = identifier,
    };

    if (type)
        pktbuf_push_head_u8(buf, type);
    hdr.length = htobe16(pktbuf_len(buf) + sizeof(struct eap_hdr)),
    pktbuf_push_head(buf, &hdr, sizeof(hdr));
}
