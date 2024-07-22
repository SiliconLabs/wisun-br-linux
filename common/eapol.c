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

#include "common/named_values.h"
#include "common/specs/eapol.h"
#include "common/pktbuf.h"

#include "eapol.h"

const struct name_value eapol_frames[] = {
    { "eap", EAPOL_PACKET_TYPE_EAP },
    { "key", EAPOL_PACKET_TYPE_KEY },
    { NULL },
};

void eapol_write_hdr_head(struct pktbuf *buf, uint8_t packet_type)
{
    struct eapol_hdr header = {
        .protocol_version = EAPOL_PROTOCOL_VERSION,
        .packet_type = packet_type,
        .packet_body_length = htobe16(pktbuf_len(buf)),
    };

    pktbuf_push_head(buf, &header, sizeof(header));
}
