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
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <unistd.h>

#include "common/specs/ieee802159.h"
#include "common/specs/6lowpan.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ipv6.h"
#include "common/ipv6/6lowpan_iphc.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/ws_ie_validation.h"
#include "common/ws_interface.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/sl_ws.h"
#include "common/bits.h"
#include "common/mpx.h"
#include "common/log.h"
#include "common/tun.h"
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
        tun_route_add(&dc->tun, &client_linklocal);
        ws_neigh_refresh(&dc->ws.neigh_table, ind->neigh, WS_NEIGHBOR_LINK_TIMEOUT);
        INFO("Direct Connection established with %s", tr_eui64(dc->cfg.target_eui64));
        INFO("%s reachable at %s", tr_eui64(dc->cfg.target_eui64), tr_ipv6(client_linklocal.s6_addr));
    }
    timer_stop(NULL, &dc->disc_timer);
}

static bool ws_is_exthdr(uint8_t ipproto)
{
    switch (ipproto) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_FRAGMENT:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MH:
        return true;
    default:
        return false;
    }
}

static bool ws_is_pkt_allowed(struct pktbuf *pktbuf)
{
    const struct ip6_ext *ext;
    struct icmpv6_hdr icmp;
    struct ip6_hdr hdr;
    size_t offset_head;
    uint8_t ipproto;

    offset_head = pktbuf->offset_head;
    pktbuf_pop_head(pktbuf, &hdr, sizeof(hdr));
    if (FIELD_GET(IPV6_MASK_VERSION, ntohl(hdr.ip6_flow)) != 6) {
        TRACE(TR_DROP, "drop %-9s: invalid IP version", "ipv6");
        return false;
    }
    if (!IN6_IS_ADDR_LINKLOCAL(&hdr.ip6_dst)) {
        TRACE(TR_DROP, "drop %-9s: invalid non-linklocal IPv6 destination", "ipv6");
        return false;
    }

    ipproto = hdr.ip6_nxt;
    while (ws_is_exthdr(ipproto) && !pktbuf->err) {
        if (ipproto == IPPROTO_FRAGMENT) {
            pktbuf->offset_head = offset_head;
            return true;
        }
        if (pktbuf_len(pktbuf) < sizeof(*ext)) {
            TRACE(TR_DROP, "drop %-9s: malformed extension header", "ipv6");
            return false;
        }
        ext = (struct ip6_ext *)pktbuf_head(pktbuf);
        ipproto = ext->ip6e_nxt;
        pktbuf_pop_head(pktbuf, NULL, 8 * (ext->ip6e_len + 1));
    }

    switch (ipproto) {
    case IPPROTO_NONE:
    case IPPROTO_UDP:
    case IPPROTO_TCP:
        break;
    case IPPROTO_ICMPV6:
        pktbuf_pop_head(pktbuf, &icmp, sizeof(icmp));
        switch (icmp.type) {
        case ICMP6_DST_UNREACH:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PARAM_PROB:
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
            break;
        default:
            TRACE(TR_DROP, "drop %-9s: unsupported ICMPv6 type %u", "ipv6", icmp.type);
            return false;
        }
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported next header %u", "ipv6", ipproto);
        return false;
    }

    if (pktbuf->err) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "ipv6");
        return false;
    }

    pktbuf->offset_head = offset_head;
    return true;
}

static void ws_recv_6lowpan(struct dc *dc, const uint8_t *buf, size_t buf_len, const uint8_t src[8],
                            const uint8_t dst[8])
{
    uint8_t src_iid[8], dst_iid[8];
    struct pktbuf pktbuf = { };
    struct ip6_hdr hdr;
    uint8_t dispatch;
    ssize_t ret;

    ipv6_addr_conv_iid_eui64(src_iid, src);
    ipv6_addr_conv_iid_eui64(dst_iid, dst);

    pktbuf_init(&pktbuf, buf, buf_len);

    if (pktbuf_len(&pktbuf) < 1)
        return;
    dispatch = pktbuf.buf[pktbuf.offset_head];

    // TODO: support FRAG1 and FRAGN
    if (LOWPAN_DISPATCH_IS_IPHC(dispatch)) {
        lowpan_iphc_decmpr(&pktbuf, src_iid, dst_iid);
    } else {
        TRACE(TR_DROP, "drop %-9s: unsupported dispatch type 0x%02x", "6lowpan", dispatch);
        goto err;
    }

    if (!ws_is_pkt_allowed(&pktbuf))
        goto err;

    pktbuf_pop_head(&pktbuf, &hdr, sizeof(hdr));

    if (!IN6_ARE_ADDR_EQUAL(&hdr.ip6_dst, &dc->addr_linklocal)) {
        TRACE(TR_DROP, "drop %-9s: invalid dst=%s", "ipv6", tr_ipv6(hdr.ip6_dst.s6_addr));
        goto err;
    }

    pktbuf_push_head(&pktbuf, &hdr, sizeof(hdr));

    TRACE(TR_IPV6, "rx-ipv6 src=%s dst=%s", tr_ipv6(hdr.ip6_src.s6_addr), tr_ipv6(hdr.ip6_dst.s6_addr));

    ret = write(dc->tun.fd, pktbuf.buf + pktbuf.offset_head, pktbuf_len(&pktbuf));
    if (ret < 0)
        WARN("write tun : %m");
    else if (ret != pktbuf_len(&pktbuf))
        WARN("write tun: Short write: %zi < %zu", ret, pktbuf_len(&pktbuf));

err:
    pktbuf_free(&pktbuf);
}

static void ws_recv_data(struct dc *dc, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;
    struct mpx_ie ie_mpx;

    if (!memcmp(&ind->hdr.dst, &ieee802154_addr_bc, 8)) {
        TRACE(TR_DROP, "drop %s: unsupported broadcast frame", "15.4");
        return;
    }
    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_6LOWPAN ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }
    if (ws_ie_validate_us(&dc->ws.fhss, &ind->ie_wp, &ie_us))
        ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    ws_recv_6lowpan(dc, ie_mpx.frame_ptr, ie_mpx.frame_length, ind->hdr.src.u8, ind->hdr.dst.u8);
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
    case WS_FT_DATA:
        ws_recv_data(dc, ind);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type %d", "15.4", ie_utt.message_type);
        return;
    }
}

void ws_recvfrom_tun(struct dc *dc)
{
    uint8_t src_iid[8], dst_iid[8];
    struct pktbuf pktbuf = { };
    const struct ip6_hdr *hdr;
    uint8_t dst_eui64[8];
    ssize_t size;

    pktbuf_init(&pktbuf, NULL, 1500);
    size = read(dc->tun.fd, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    if (size < 0) {
        WARN("%s read: %m", __func__);
        goto err;
    }
    pktbuf.offset_tail = size;

    if (!ws_is_pkt_allowed(&pktbuf))
        goto err;
    hdr = (const struct ip6_hdr *)pktbuf_head(&pktbuf);

    ipv6_addr_conv_iid_eui64(dst_eui64, hdr->ip6_dst.s6_addr + 8);
    ipv6_addr_conv_iid_eui64(src_iid, dc->ws.rcp.eui64.u8);
    ipv6_addr_conv_iid_eui64(dst_iid, dst_eui64);

    lowpan_iphc_cmpr(&pktbuf, src_iid, dst_iid);
    if (pktbuf.err)
        goto err;

    ws_if_send_data(&dc->ws, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf), (struct eui64 *)dst_eui64);

err:
    pktbuf_free(&pktbuf);
}
