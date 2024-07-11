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

#define KDE_GTK_MASK_KEY_ID 0b00000011
#define KDE_GTK_MASK_TX     0b00000100

struct kde_gtk {
    uint8_t flags;
    uint8_t reserved;
    uint8_t gtk[16];
} __attribute__((packed));

void kde_write_pmkid(struct pktbuf *buf, const uint8_t pmkid[16]);
void kde_write_ptkid(struct pktbuf *buf, const uint8_t ptkid[16]);
void kde_write_gtkl(struct pktbuf *buf, uint8_t gtkl);
void kde_write_lgtkl(struct pktbuf *buf, uint8_t lgtkl);
void kde_write_nr(struct pktbuf *buf, uint8_t node_role);

bool kde_read_pmk_id(const uint8_t *data, int data_len, uint8_t pmkid[16]);
bool kde_read_gtk(const uint8_t *data, int data_len, struct kde_gtk *gtk_kde);
bool kde_read_gtkl(const uint8_t *data, int data_len, uint8_t *gtkl);
bool kde_read_lgtk(const uint8_t *data, int data_len, struct kde_gtk *gtk_kde);
bool kde_read_lgtkl(const uint8_t *data, int data_len,  uint8_t *lgtkl);
bool kde_read_lifetime(const uint8_t *data, int data_len, uint32_t *lifetime);

#endif
