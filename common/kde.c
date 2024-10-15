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
#include <string.h>

#include "common/specs/ieee80211.h"
#include "common/specs/oui.h"
#include "common/specs/ws.h"
#include "common/endian.h"
#include "common/pktbuf.h"
#include "common/iobuf.h"
#include "common/bits.h"

#include "kde.h"

static void kde_write(struct pktbuf *buf, uint24_t oui, uint8_t data_type,
                      const void *data, uint8_t data_size)
{
    struct kde_hdr hdr = {
        .type      = IEEE80211_KDE_TYPE,
        .length    = data_size + sizeof(hdr.oui) + sizeof(hdr.data_type),
        .data_type = data_type,
    };

    write_be24(hdr.oui, oui);
    pktbuf_push_tail(buf, &hdr, sizeof(hdr));
    pktbuf_push_tail(buf, data, data_size);
}

static const uint8_t *kde_find(const uint8_t *data, int data_length, uint8_t type, uint24_t oui,
                               uint8_t data_type, int size)
{
    struct iobuf_read input = {
        .data = data,
        .data_size = data_length,
    };
    const struct kde_hdr *hdr;

    while (iobuf_remaining_size(&input)) {
        hdr = iobuf_pop_data_ptr(&input, sizeof(*hdr));
        if (!hdr)
            return NULL;
        if (hdr->type == type && read_be24(hdr->oui) == oui && iobuf_remaining_size(&input) >= size &&
            hdr->data_type == data_type)
            return iobuf_ptr(&input);
        iobuf_pop_data(&input, NULL, hdr->length - 4); // length includes oui and data type
    }
    return NULL;
}

bool kde_read_lifetime(const uint8_t *data, int data_len, uint32_t *lifetime)
{
    const uint8_t *ptr = kde_find(data, data_len, IEEE80211_KDE_TYPE, OUI_IEEE80211,
                                  IEEE80211_KDE_LIFETIME, sizeof(be32_t));

    if (!ptr)
        return false;

    *lifetime = read_be32(ptr);
    return true;
}

bool kde_read_lgtkl(const uint8_t *data, int data_len,  uint8_t *lgtkl)
{
    const uint8_t *ptr = kde_find(data, data_len, IEEE80211_KDE_TYPE, OUI_WISUN_ALLIANCE,
                                  WS_KDE_LGTKL, sizeof(uint8_t));

    if (!ptr)
        return false;

    *lgtkl = *ptr;
    return true;
}

bool kde_read_lgtk(const uint8_t *data, int data_len, struct kde_gtk *lgtk_kde)
{
    const uint8_t *ptr = kde_find(data, data_len, IEEE80211_KDE_TYPE, OUI_WISUN_ALLIANCE,
                                  WS_KDE_LGTK, sizeof(struct kde_gtk));

    if (!ptr)
        return false;

    memcpy(lgtk_kde, ptr, sizeof(struct kde_gtk));
    return true;
}

bool kde_read_gtkl(const uint8_t *data, int data_len, uint8_t *gtkl)
{
    const uint8_t *ptr = kde_find(data, data_len, IEEE80211_KDE_TYPE, OUI_WISUN_ALLIANCE,
                                  WS_KDE_GTKL, sizeof(uint8_t));

    if (!ptr)
        return false;

    *gtkl = *ptr;
    return true;
}

bool kde_read_gtk(const uint8_t *data, int data_len, struct kde_gtk *gtk_kde)
{
    const uint8_t *ptr = kde_find(data, data_len, IEEE80211_KDE_TYPE, OUI_IEEE80211,
                                  IEEE80211_KDE_GTK, sizeof(struct kde_gtk));

    if (!ptr)
        return false;

    memcpy(gtk_kde, ptr, sizeof(struct kde_gtk));
    return true;
}

bool kde_read_pmk_id(const uint8_t *data, int data_len, uint8_t pmkid[16])
{
    const uint8_t *ptr = kde_find(data, data_len, IEEE80211_KDE_TYPE, OUI_IEEE80211, IEEE80211_KDE_PMKID, 16);

    if (!ptr)
        return false;

    memcpy(pmkid, ptr, 16);
    return true;
}

void kde_write_pmkid(struct pktbuf *buf, const uint8_t pmkid[16])
{
    kde_write(buf, OUI_IEEE80211, IEEE80211_KDE_PMKID, pmkid, 16);
}

void kde_write_ptkid(struct pktbuf *buf, const uint8_t ptkid[16])
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_PTKID, ptkid, 16);
}

void kde_write_gtk(struct pktbuf *buf, const uint8_t key_id, const uint8_t gtk[16])
{
    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.2.4 Group Transient Key KDE (GTK)
     * The TX field MUST be set to 0 and ignored upon reception.
     */
    struct kde_gtk gtk_kde = {
        .flags = FIELD_PREP(KDE_GTK_MASK_KEY_ID, key_id),
    };

    memcpy(gtk_kde.gtk, gtk, sizeof(gtk_kde.gtk));
    kde_write(buf, OUI_IEEE80211, IEEE80211_KDE_GTK, &gtk_kde, sizeof(gtk_kde));
}

void kde_write_gtkl(struct pktbuf *buf, uint8_t gtkl)
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_GTKL, &gtkl, sizeof(gtkl));
}

void kde_write_lgtk(struct pktbuf *buf, const uint8_t key_id, const uint8_t lgtk[16])
{
    /*
     *   Wi-SUN FAN 1.1v08, 6.3.2.2.4 Group Transient Key KDE (GTK)
     * The TX field MUST be set to 0 and ignored upon reception.
     */
    struct kde_gtk lgtk_kde = {
        .flags = FIELD_PREP(KDE_GTK_MASK_KEY_ID, key_id),
    };

    memcpy(lgtk_kde.gtk, lgtk, sizeof(lgtk_kde.gtk));
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_LGTK, &lgtk_kde, sizeof(lgtk_kde));
}

void kde_write_lgtkl(struct pktbuf *buf, uint8_t lgtkl)
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_LGTKL, &lgtkl, sizeof(lgtkl));
}

void kde_write_nr(struct pktbuf *buf, uint8_t node_role)
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_NR, &node_role, sizeof(node_role));
}
