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
#include <errno.h>

#include "common/ws/ws_ie_validation.h"
#include "common/ws/ws_interface.h"
#include "common/specs/ieee802159.h"
#include "common/specs/6lowpan.h"
#include "common/specs/icmpv6.h"
#include "common/specs/ipv6.h"
#include "common/ipv6/6lowpan_iphc.h"
#include "common/ipv6/ipv6_cksum.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/sl_ws.h"
#include "common/bits.h"
#include "common/mpx.h"
#include "common/log.h"
#include "common/tun.h"
#include "dc.h"

#include "ws.h"

static int ws_send_lowpan(struct dc *dc, struct pktbuf *pktbuf, const uint8_t src[8], const uint8_t dst[8])
{
    uint8_t src_iid[8], dst_iid[8];

    ipv6_addr_conv_iid_eui64(src_iid, src);
    ipv6_addr_conv_iid_eui64(dst_iid, dst);

    lowpan_iphc_cmpr(pktbuf, src_iid, dst_iid);
    if (pktbuf->err) {
        TRACE(TR_TX_ABORT, "tx-abort: 6lowpan compression error");
        return -EINVAL;
    }

    return ws_if_send_data(&dc->ws, pktbuf_head(pktbuf), pktbuf_len(pktbuf), &EUI64_FROM_BUF(dst));
}

static int ws_send_ipv6(struct dc *dc, struct pktbuf *pktbuf, uint8_t ipproto, uint8_t hlim,
                         const struct in6_addr *src, const struct in6_addr *dst)
{
    struct ip6_hdr hdr = {
        .ip6_flow = htonl(FIELD_PREP(IPV6_MASK_VERSION, 6)),
        .ip6_plen = htons(pktbuf_len(pktbuf)),
        .ip6_nxt  = ipproto,
        .ip6_hlim = hlim,
        .ip6_src  = *src,
        .ip6_dst  = *dst,
    };
    uint8_t dst_eui64[8];

    // We only do link-local with DC
    if (!IN6_IS_ADDR_LINKLOCAL(&hdr.ip6_src)) {
        TRACE(TR_TX_ABORT, "tx-abort: ipv6 src address %s is not link-local", tr_ipv6(hdr.ip6_src.s6_addr));
        return -EINVAL;
    }
    if (!IN6_IS_ADDR_LINKLOCAL(&hdr.ip6_dst)) {
        TRACE(TR_TX_ABORT, "tx-abort: ipv6 dst address %s is not link-local", tr_ipv6(hdr.ip6_dst.s6_addr));
        return -EINVAL;
    }

    pktbuf_push_head(pktbuf, &hdr, sizeof(hdr));
    ipv6_addr_conv_iid_eui64(dst_eui64, hdr.ip6_dst.s6_addr + 8);

    TRACE(TR_IPV6, "tx-ipv6 src=%s dst=%s", tr_ipv6(hdr.ip6_src.s6_addr), tr_ipv6(hdr.ip6_dst.s6_addr));

    return ws_send_lowpan(dc, pktbuf, dc->ws.rcp.eui64.u8, dst_eui64);
}

void ws_on_probe_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct dc *dc = container_of(timer, struct dc, probe_timer);
    struct nd_neighbor_solicit ns = { 0 };
    struct pktbuf pktbuf = { };
    struct in6_addr src, dst;
    int handle;

    src = ipv6_prefix_linklocal;
    ipv6_addr_conv_iid_eui64(src.s6_addr + 8, dc->ws.rcp.eui64.u8);
    dst = ipv6_prefix_linklocal;
    ipv6_addr_conv_iid_eui64(dst.s6_addr + 8, dc->cfg.target_eui64.u8);

    if (dc->probe_handle != -1) {
        TRACE(TR_TX_ABORT, "tx-abort: ns already in progress for %s", tr_ipv6(dst.s6_addr));
        return;
    }

    ns.nd_ns_type   = ND_NEIGHBOR_SOLICIT;
    ns.nd_ns_target = dst;
    pktbuf_push_tail(&pktbuf, &ns, sizeof(ns));

    ns.nd_ns_cksum = ipv6_cksum(&src, &dst, IPPROTO_ICMPV6, pktbuf_head(&pktbuf), pktbuf_len(&pktbuf));
    memcpy(pktbuf_head(&pktbuf) + offsetof(struct nd_neighbor_solicit, nd_ns_cksum),
           &ns.nd_ns_cksum, sizeof(ns.nd_ns_cksum));

    TRACE(TR_ICMP, "tx-icmp %-9s dst=%s", "ns", tr_ipv6(dst.s6_addr));
    handle = ws_send_ipv6(dc, &pktbuf, IPPROTO_ICMPV6, 255, &src, &dst);
    if (handle >= 0)
        dc->probe_handle = handle;

    pktbuf_free(&pktbuf);
}

static void ws_on_probe_done(struct dc *dc, int handle, bool success)
{
    if (handle != dc->probe_handle)
        return;
    if (success) {
        dc->probe_handle = -1;
        return;
    }

    /*
     * After 1 NS failure, we consider the link has been lost.
     * This covers the case where the router has rebooted, but does not timeout because
     * we heard other frames from him (PAS, PCS, ...).
     */
    ws_neigh_del(&dc->ws.neigh_table, &dc->cfg.target_eui64);
}

static void ws_recv_dca(struct dc *dc, struct ws_ind *ind)
{
    struct ws_us_ie ie_us;

    if (!ws_ie_validate_us(&dc->ws.fhss, &ind->ie_wp, &ie_us))
        return;
    ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
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
    TRACE(TR_TUN, "tx-tun: %zu bytes", pktbuf_len(&pktbuf));

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

    if (!ind->hdr.key_index) {
        TRACE(TR_DROP, "drop %s: unsecured frame", "15.4");
        return;
    }
    if (eui64_is_bc(&ind->hdr.dst)) {
        TRACE(TR_DROP, "drop %s: unsupported broadcast frame", "15.4");
        return;
    }
    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_6LOWPAN ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }
    if (ws_ie_validate_us(&dc->ws.fhss, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data, &ie_us.chan_plan, ie_us.dwell_interval);
    }
    ws_recv_6lowpan(dc, ie_mpx.frame_ptr, ie_mpx.frame_length, ind->hdr.src.u8, ind->hdr.dst.u8);
}

static void ws_recv_eapol(struct dc *dc, struct ws_ind *ind)
{
    struct iobuf_read buf = { };
    struct ws_us_ie ie_us;
    struct mpx_ie ie_mpx;
    uint8_t kmp_id;

    if (!mpx_ie_parse(ind->ie_mpx.data, ind->ie_mpx.data_size, &ie_mpx) ||
        ie_mpx.multiplex_id  != MPX_ID_KMP ||
        ie_mpx.transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %s: invalid MPX-IE", "15.4");
        return;
    }

    if (ws_ie_validate_us(&dc->ws.fhss, &ind->ie_wp, &ie_us)) {
        ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data, &ie_us.chan_plan, ie_us.dwell_interval);
        ws_neigh_us_update(&dc->ws.fhss, &ind->neigh->fhss_data_unsecured, &ie_us.chan_plan, ie_us.dwell_interval);
    }

    buf.data = ie_mpx.frame_ptr;
    buf.data_size = ie_mpx.frame_length;
    kmp_id = iobuf_pop_u8(&buf);
    if (buf.err) {
        TRACE(TR_DROP, "drop %-9s: invalid eapol packet", "15.4");
        return;
    }

    // Authentication started, disable discovery timer
    if (eui64_eq(&ind->neigh->eui64, &dc->cfg.target_eui64))
        timer_stop(NULL, &dc->disc_timer);
    auth_recv_eapol(&dc->auth_ctx, kmp_id, &ind->hdr.src, iobuf_ptr(&buf), iobuf_remaining_size(&buf));
}

void ws_on_recv_ind(struct ws_ctx *ws, struct ws_ind *ind)
{
    struct dc *dc = container_of(ws, struct dc, ws);
    struct ws_utt_ie ie_utt;

    if (ws_wh_sl_utt_read(ind->ie_hdr.data, ind->ie_hdr.data_size, &ie_utt)) {
        if (!eui64_eq(&dc->cfg.target_eui64, &ind->neigh->eui64)) {
            TRACE(TR_DROP, "drop %-9s: direct connect target eui64 missmatch", "15.4");
            return;
        }
        ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, &ind->hdr.src);
        if (ind->hdr.key_index)
            ws_neigh_ut_update(&ind->neigh->fhss_data, ie_utt.ufsi, ind->hif->timestamp_us, &ind->hdr.src);
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

    ws_neigh_ut_update(&ind->neigh->fhss_data_unsecured, ie_utt.ufsi, ind->hif->timestamp_us, &ind->hdr.src);
    if (ind->hdr.key_index)
        ws_neigh_ut_update(&ind->neigh->fhss_data, ie_utt.ufsi, ind->hif->timestamp_us, &ind->hdr.src);

    switch (ie_utt.message_type) {
    case WS_FT_DATA:
        ws_recv_data(dc, ind);
        break;
    case WS_FT_EAPOL:
        ws_recv_eapol(dc, ind);
        break;
    default:
        TRACE(TR_DROP, "drop %-9s: unsupported frame type %d", "15.4", ie_utt.message_type);
        return;
    }
}

void ws_on_recv_cnf(struct ws_ctx *ws, struct ws_frame_ctx *frame_ctx, const struct rcp_tx_cnf *cnf)
{
    struct dc *dc = container_of(ws, struct dc, ws);

    if (frame_ctx->type == WS_FT_DATA)
        ws_on_probe_done(dc, cnf->handle, cnf->status == HIF_STATUS_SUCCESS);
}

void ws_recvfrom_tun(struct dc *dc)
{
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

    TRACE(TR_TUN, "rx-tun: %zd bytes", size);

    if (!ws_is_pkt_allowed(&pktbuf))
        goto err;
    hdr = (const struct ip6_hdr *)pktbuf_head(&pktbuf);

    // We only do link-local with DC
    if (!IN6_IS_ADDR_LINKLOCAL(&hdr->ip6_src)) {
        TRACE(TR_TX_ABORT, "tx-abort: ipv6 src address %s is not link-local", tr_ipv6(hdr->ip6_src.s6_addr));
        goto err;
    }
    if (!IN6_IS_ADDR_LINKLOCAL(&hdr->ip6_dst)) {
        TRACE(TR_TX_ABORT, "tx-abort: ipv6 dst address %s is not link-local", tr_ipv6(hdr->ip6_dst.s6_addr));
        goto err;
    }

    TRACE(TR_IPV6, "tx-ipv6 src=%s dst=%s", tr_ipv6(hdr->ip6_src.s6_addr), tr_ipv6(hdr->ip6_dst.s6_addr));

    ipv6_addr_conv_iid_eui64(dst_eui64, hdr->ip6_dst.s6_addr + 8);
    ws_send_lowpan(dc, &pktbuf, dc->ws.rcp.eui64.u8, dst_eui64);

err:
    pktbuf_free(&pktbuf);
}
