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
#include "common/specs/ieee802154.h"
#include "common/hif.h"
#include "common/ieee802154_frame.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/log.h"
#include "common/named_values.h"
#include "common/rcp_api.h"
#include "common/ws_ie.h"
#include "common/ws_types.h"

#include "ws.h"

struct ws_ind {
    const struct rcp_rx_ind *hif;
    struct ieee802154_hdr hdr;
    struct iobuf_read ie_hdr;
    struct iobuf_read ie_wp;
    struct iobuf_read ie_mpx;
};

static const struct name_value ws_frames[] = {
    { "adv",       WS_FT_PA },
    { "adv-sol",   WS_FT_PAS },
    { "cfg",       WS_FT_PC },
    { "cfg-sol",   WS_FT_PCS },
    { "data",      WS_FT_DATA },
    { "ack",       WS_FT_ACK },
    { "eapol",     WS_FT_EAPOL },
    { "l-adv",     WS_FT_LPA },
    { "l-adv-sol", WS_FT_LPAS },
    { "l-cfg",     WS_FT_LPC },
    { "l-cfg-sol", WS_FT_LPCS },
    { "l-tsync",   WS_FT_LTS },
    { NULL },
};

static const char *tr_ws_frame(uint8_t type)
{
    return val_to_str(type, ws_frames, "unknown");
}

void ws_print_ind(const struct ws_ind *ind, uint8_t type)
{
    unsigned int tr_domain;

    if (type == WS_FT_DATA || type == WS_FT_ACK || type == WS_FT_EAPOL)
        tr_domain = TR_15_4_DATA;
    else
        tr_domain = TR_15_4_MNGT;

    if (ind->hdr.pan_id >= 0 && ind->hdr.pan_id != 0xffff)
        TRACE(tr_domain, "rx-15.4 %-9s src:%s panid:%x (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src),
              ind->hdr.pan_id, ind->hif->rx_power_dbm);
    else
        TRACE(tr_domain, "rx-15.4 %-9s src:%s (%ddBm)",
              tr_ws_frame(type), tr_eui64(ind->hdr.src),
              ind->hif->rx_power_dbm);
}

void ws_recv_ind(struct ws_ctx *ws, const struct rcp_rx_ind *hif_ind)
{
    struct ws_ind ind = { .hif = hif_ind };
    struct iobuf_read ie_payload;
    struct ws_utt_ie ie_utt;
    int ret;

    ret = ieee802154_frame_parse(hif_ind->frame, hif_ind->frame_len,
                                 &ind.hdr, &ind.ie_hdr, &ie_payload);
    if (ret < 0)
        return;

    if (!ws_wh_utt_read(ind.ie_hdr.data, ind.ie_hdr.data_size, &ie_utt)) {
        TRACE(TR_DROP, "drop %-9s: missing UTT-IE", "15.4");
        return;
    }

    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_WP, &ind.ie_wp);
    ieee802154_ie_find_payload(ie_payload.data, ie_payload.data_size,
                               IEEE802154_IE_ID_MPX, &ind.ie_mpx);

    ws_print_ind(&ind, ie_utt.message_type);

    switch (ie_utt.message_type) {
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type", "15.4");
        return;
    }
}
