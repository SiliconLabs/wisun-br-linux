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
#ifndef EAP_H
#define EAP_H

#include <inttypes.h>

#include "common/named_values.h"
#include "common/endian.h"

struct pktbuf;

struct eap_hdr {
    uint8_t code;
    uint8_t identifier;
    be16_t  length;
} __attribute__((packed));

extern const struct name_value eap_frames[];
extern const struct name_value eap_types[];

void eap_write_hdr_head(struct pktbuf *buf, uint8_t code, uint8_t identifier, uint8_t type);

#endif
