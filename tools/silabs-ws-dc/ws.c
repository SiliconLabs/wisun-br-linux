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
#include "common/ipv6/ipv6_addr.h"
#include "common/ws_ie_validation.h"
#include "common/memutils.h"
#include "common/sl_ws.h"
#include "common/log.h"
#include "dc.h"

#include "ws.h"

static void ws_recv_dca(struct dc *dc, struct ws_ind *ind)
{
    struct in6_addr client_linklocal;
    struct ws_us_ie ie_us;

    if (!ws_ie_validate_us(&dc->ws.fhss, &ind->ie_wp, &ie_us))
        return;
    ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);

    if (!timer_stopped(&dc->disc_timer)) {
        memcpy(client_linklocal.s6_addr, ipv6_prefix_linklocal.s6_addr, 8);
        ipv6_addr_conv_iid_eui64(client_linklocal.s6_addr + 8, ind->neigh->mac64);
        ws_neigh_refresh(&dc->ws.neigh_table, ind->neigh, WS_NEIGHBOR_LINK_TIMEOUT);
        INFO("Direct Connection established with %s", tr_eui64(dc->cfg.target_eui64));
        INFO("%s reachable at %s", tr_eui64(dc->cfg.target_eui64), tr_ipv6(client_linklocal.s6_addr));
    }
    timer_stop(NULL, &dc->disc_timer);
}

void ws_on_recv_ind(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct dc *dc = container_of(ws, struct dc, ws);
    struct ws_utt_ie ie_utt;

    if (ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsupported secured frame", "15.4");
        return;
    }

    if (ws_wh_sl_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt)) {
        if (memcmp(dc->cfg.target_eui64, ind->neigh->mac64, sizeof(dc->cfg.target_eui64))) {
            TRACE(TR_DROP, "drop %-9s: direct connect target eui64 missmatch", "15.4");
            return;
        }
        ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src.u8);
        if (ind->hdr.key_index)
            ws_neigh_ut_update(&ind->neigh->fhss_data, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src.u8);
        switch (ie_utt.message_type)
        {
        case SL_FT_DCA:
            ws_recv_dca(dc, ind);
            break;
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported sl frame type %d", "15.4", ie_utt.message_type);
            break;
        }
        return;
    }

    BUG_ON(!ws_wh_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt));

    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src.u8);
    if (ind->hdr.key_index)
        ws_neigh_ut_update(&ind->neigh->fhss_data, ie_utt.ufsi, ind->hif->timestamp_us, ind->hdr.src.u8);

    switch (ie_utt.message_type) {
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type %d", "15.4", ie_utt.message_type);
        return;
    }
}
