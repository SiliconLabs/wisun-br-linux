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
#ifndef EAPOL_H
#define EAPOL_H

#include "common/named_values.h"
#include "common/endian.h"

struct pktbuf;

struct eapol_hdr {
    uint8_t  protocol_version; // 0x03
    uint8_t  packet_type;
    be16_t   packet_body_length;
} __attribute__((packed));

struct eapol_key_frame {
    uint8_t  descriptor_type; // 0x02
    be16_t   information;
    be16_t   length;
    be64_t   replay_counter;
    uint8_t  nonce[32];
    uint8_t  eapol_key_iv[16];
    be64_t   rsc;
    uint64_t reserved;
    uint8_t  mic[16];
    be16_t   data_length;
} __attribute__((packed));

extern const struct name_value eapol_frames[];

void eapol_write_hdr_head(struct pktbuf *buf, uint8_t packet_type);

#endif
