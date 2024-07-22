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
#include "common/specs/ieee80211.h"
#include "common/specs/oui.h"
#include "common/specs/ws.h"
#include "common/endian.h"
#include "common/pktbuf.h"

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

void kde_write_pmkid(struct pktbuf *buf, const uint8_t pmkid[16])
{
    kde_write(buf, OUI_IEEE80211, IEEE80211_KDE_PMKID, pmkid, 16);
}

void kde_write_ptkid(struct pktbuf *buf, const uint8_t ptkid[16])
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_PTKID, ptkid, 16);
}

void kde_write_gtkl(struct pktbuf *buf, uint8_t gtkl)
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_GTKL, &gtkl, sizeof(gtkl));
}

void kde_write_lgtkl(struct pktbuf *buf, uint8_t lgtkl)
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_LGTKL, &lgtkl, sizeof(lgtkl));
}

void kde_write_nr(struct pktbuf *buf, uint8_t node_role)
{
    kde_write(buf, OUI_WISUN_ALLIANCE, WS_KDE_NR, &node_role, sizeof(node_role));
}
