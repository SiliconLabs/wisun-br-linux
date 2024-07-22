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
#ifndef KDE_H
#define KDE_H

#include <inttypes.h>

struct pktbuf;

struct kde_hdr {
    uint8_t type; // 0xdd
    uint8_t length;
    uint8_t oui[3];
    uint8_t data_type;
} __attribute__((packed));

void kde_write_pmkid(struct pktbuf *buf, const uint8_t pmkid[16]);
void kde_write_ptkid(struct pktbuf *buf, const uint8_t ptkid[16]);
void kde_write_gtkl(struct pktbuf *buf, uint8_t gtkl);
void kde_write_lgtkl(struct pktbuf *buf, uint8_t lgtkl);
void kde_write_nr(struct pktbuf *buf, uint8_t node_role);

#endif
