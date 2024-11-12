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
#define _DEFAULT_SOURCE
#include <endian.h>

#include "common/specs/eap.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/pktbuf.h"

#include "eap.h"

static const char *tr_eap_code(uint8_t code)
{
    static const struct name_value table[] = {
        { "request",  EAP_CODE_REQUEST },
        { "response", EAP_CODE_RESPONSE },
        { "success",  EAP_CODE_SUCCESS },
        { "failure",  EAP_CODE_FAILURE },
        { }
    };

    return val_to_str(code, table, "unknown");
}

static const char *tr_eap_type(uint8_t type)
{
    static const struct name_value table[] = {
        { "identity",     EAP_TYPE_IDENTITY },
        { "notification", EAP_TYPE_NOTIFICATION },
        { "nak",          EAP_TYPE_NAK },
        { "tls",          EAP_TYPE_TLS },
        { }
    };

    return val_to_str(type, table, "unknown");
}

void eap_trace(const char *prefix, const void *buf, size_t buf_len)
{
    struct iobuf_read iobuf = {
        .data      = buf,
        .data_size = buf_len,
    };
    struct eap_hdr eap;
    uint8_t type;

    iobuf_pop_data(&iobuf, &eap, sizeof(eap));
    if (eap.code == EAP_CODE_REQUEST || eap.code == EAP_CODE_RESPONSE) {
        type = iobuf_pop_u8(&iobuf);
        TRACE(TR_SECURITY, "sec: %-8s code=%-8s id=%-3u type=%s", prefix,
              tr_eap_code(eap.code), eap.identifier, tr_eap_type(type));
    } else {
        TRACE(TR_SECURITY, "sec: %-8s code=%-8s id=%u", prefix,
              tr_eap_code(eap.code), eap.identifier);
    }
}

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
