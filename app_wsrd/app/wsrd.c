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
#include <linux/capability.h>
#include <sys/signalfd.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app_wsrd/app/commandline.h"
#include "app_wsrd/app/join_state.h"
#include "app_wsrd/app/dbus.h"
#include "app_wsrd/app/ws.h"
#include "app_wsrd/app/wsrd_storage.h"
#include "app_wsrd/ipv6/rpl.h"
#include "app_wsrd/supplicant/supplicant_storage.h"
#include "common/ws/eapol_relay.h"
#include "common/ws/ws_regdb.h"
#include "common/ipv6/icmpv6_err.h"
#include "common/ipv6/ipv6_addr.h"
#include "common/crypto/ws_keys.h"
#include "common/mbedtls_config_check.h"
#include "common/netinet_in_extra.h"
#include "common/key_value_storage.h"
#include "common/drop_privileges.h"
#include "common/rpl_lollipop.h"
#include "common/bits.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/pktbuf.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/version.h"
#include "common/dbus.h"
#include "wsrd.h"

enum {
    POLLFD_RCP,
    POLLFD_TIMER,
    POLLFD_TUN,
    POLLFD_RPL,
    POLLFD_DHCP,
    POLLFD_DHCP_RELAY,
    POLLFD_EAPOL_RELAY,
    POLLFD_DBUS,
    POLLFD_SIGNAL,
    POLLFD_COUNT,
};

static void wsrd_on_rcp_reset(struct rcp *rcp);
static void wsrd_on_etx_outdated(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx);
static void wsrd_on_etx_update(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx);
static int wsrd_ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const struct eui64 *dst);
static void wsrd_eapol_sendto_mac(struct supp_ctx *supp, uint8_t kmp_id, const void *pkt,
                                  size_t pkt_len, const struct eui64 *dst);
static struct eui64 wsrd_eapol_get_target(struct supp_ctx *supp);
static void wsrd_eapol_on_gtk_change(struct supp_ctx *supp, const uint8_t gtk[16], uint32_t frame_counter, uint8_t index);
static void wsrd_eapol_on_failure(struct supp_ctx *supp);
static void wsrd_on_pref_parent_change(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh);
static void wsrd_on_dhcp_addr_add(struct dhcp_client *client);
static void wsrd_on_dhcp_addr_del(struct dhcp_client *client);
static struct in6_addr wsrd_dhcp_get_dst(struct dhcp_client *client);

static void wsrd_on_neigh_add(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    struct wsrd *wsrd = container_of(table, struct wsrd, ws.neigh_table);

    for (int i = 0; i < ARRAY_SIZE(wsrd->supp.gtks); i++)
        neigh->frame_counter_min[i] = ws_gtk_installed(&wsrd->supp.gtks[i]) ? 0 : UINT32_MAX;
}

static void wsrd_on_dao_ack(struct ipv6_ctx *ipv6)
{
    struct wsrd *wsrd = container_of(ipv6, struct wsrd, ipv6);

    join_state_transition(wsrd, WSRD_EVENT_ROUTING_SUCCESS);
}

static void wsrd_on_dhcp_txalg_failure(struct rfc8415_txalg *txalg)
{
    struct wsrd *wsrd = container_of(txalg, struct wsrd, ipv6.dhcp.solicit_txalg);
    struct ipv6_neigh *parent = rpl_neigh_get_parent(&wsrd->ipv6, RPL_PATH_CTL_PREFERRED);

    BUG_ON(!parent);
    rpl_neigh_deny(&wsrd->ipv6, parent);
    parent = rpl_neigh_get_parent(&wsrd->ipv6, RPL_PATH_CTL_PREFERRED);
    if (parent)
        rfc8415_txalg_start(txalg);
}

static void wsrd_ipv6_on_recv(struct ipv6_ctx *ipv6, const struct in6_addr *src)
{
    struct ipv6_neigh *parent = rpl_neigh_get_parent(ipv6, RPL_PATH_CTL_PREFERRED);
    struct wsrd *wsrd = container_of(ipv6, struct wsrd, ipv6);
    struct ipv6_neigh *neigh;
    struct eui64 eui64;

    if (!parent)
        return;
    if (IN6_IS_ADDR_LINKLOCAL(src)) {
        ipv6_addr_conv_iid_eui64(eui64.u8, src->s6_addr + 8);
        neigh = ipv6_neigh_get_from_eui64(ipv6, &eui64);
        if (!neigh)
            return;
        src = &neigh->gua;
    }
    if (IN6_ARE_ADDR_EQUAL(src, &ipv6->rpl.dodag_id))
        ws_pan_timeout_update(wsrd);
}

static void *wsrd_mpl_send(struct mpl_ctx *mpl, const void *buf, size_t buf_len)
{
    struct ipv6_ctx *ipv6 = container_of(mpl, struct ipv6_ctx, mpl);
    struct pktbuf pktbuf = { };
    int handle;

    pktbuf_push_tail(&pktbuf, buf, buf_len);
    handle = ipv6_sendto_mac(ipv6, &pktbuf, NULL);
    pktbuf_free(&pktbuf);
    if (handle < 0)
        return NULL;
    return (void *)((uintptr_t)handle + 1);
}

static void wsrd_mpl_abort(struct mpl_ctx *mpl, void *tx_ctx)
{
    struct wsrd *wsrd = container_of(mpl, struct wsrd, ipv6.mpl);
    int handle = (uintptr_t)tx_ctx - 1;

    rcp_req_data_tx_abort(&wsrd->ws.rcp, handle);
}

static void wsrd_on_unregistration_timer_timeout(struct timer_group *group, struct timer_entry *timer)
{
    struct wsrd *wsrd = container_of(timer, struct wsrd, unregistration_timer);

    join_state_transition(wsrd, wsrd->last_event);
}

struct wsrd g_wsrd = {
    .ws.rcp.bus.fd = -1,
    .ws.rcp.on_reset  = wsrd_on_rcp_reset,
    .ws.rcp.on_rx_ind = ws_if_recv_ind,
    .ws.rcp.on_tx_cnf = ws_if_recv_cnf,

    .prev_pan_id = 0xffff,
    .ws.pan_id = 0xffff,
    .ws.pan_version = -1,
    .ws.neigh_table.on_add          = wsrd_on_neigh_add,
    .ws.neigh_table.ws_etx_ctx.on_etx_outdated = wsrd_on_etx_outdated,
    .ws.neigh_table.ws_etx_ctx.on_etx_update   = wsrd_on_etx_update,
    .ws.on_recv_ind                 = ws_on_recv_ind,
    .ws.on_recv_cnf                 = ws_on_recv_cnf,
    .ws.eapol_relay_fd = -1,
    .ws.duty_cycle_cfg = &g_wsrd.config.duty_cycle,
    .ipv6.sendto_mac = wsrd_ipv6_sendto_mac,
    .eapol_target_eui64 = EUI64_BC,
    .pan_timeout_timer.callback = ws_on_pan_timeout,
    .unregistration_timer.callback = wsrd_on_unregistration_timer_timeout,

    // Wi-SUN FAN 1.1v08 - 6.5.2.1.1 SUP Operation
    .supp.key_request_txalg.irt_s       =  300, //  5 * 60
    .supp.key_request_txalg.mrt_s       = 3600, // 60 * 60
    // RFC 8415 15. Reliability of Client-Initiated Message Exchanges
    .supp.key_request_txalg.rand_min    = -0.1,
    .supp.key_request_txalg.rand_max    = +0.1,
    .config.supp.gtk_max_mismatch_s = 3840, // 64 * 60
    .config.supp.timeout_ms = 60 * 1000, // Arbitrary
    // FreeRADIUS refuses an empty identity, so an arbitrary value is used.
    .config.supp.eap_identity = "Anonymous",
    .supp.cfg = &g_wsrd.config.supp,
    .supp.on_gtk_change = wsrd_eapol_on_gtk_change,
    .supp.on_failure  = wsrd_eapol_on_failure,
    .supp.sendto_mac  = wsrd_eapol_sendto_mac,
    .supp.get_target  = wsrd_eapol_get_target,

    // Arbitrary default values
    .config.rpl_compat = true,
    .config.tun_autoconf = true,
    .config.ws_domain = REG_DOMAIN_UNDEF,
    .config.ws_uc_dwell_interval_ms = 255,
    .config.ws_allowed_channels = { [0 ... sizeof(g_wsrd.config.ws_allowed_channels) - 1] = 0xff },
    .config.color_output = -1,

    // Wi-SUN FAN 1.1v09 6.3.1.1 Configuration Parameters
    .config.disc_cfg.Imin_ms = 15 * 1000,
    .config.disc_cfg.Imax_ms = TRICKLE_DOUBLINGS(15, 2) * 1000,
    .config.disc_cfg.k = 1,
    .config.pan_timeout_s = 60 * 60,
    .pas_tkl.cfg = &g_wsrd.config.disc_cfg,
    .pas_tkl.debug_name  = "pas",
    .pas_tkl.on_transmit = ws_on_send_pas,
    .pas_tkl.on_interval_done = ws_on_pas_interval_done,
    .pa_tkl.cfg = &g_wsrd.config.disc_cfg,
    .pa_tkl.debug_name  = "pa",
    .pa_tkl.on_transmit = ws_on_send_pa,
    .pcs_tkl.cfg         = &g_wsrd.config.disc_cfg,
    .pcs_tkl.debug_name  = "pcs",
    .pcs_tkl.on_transmit = ws_on_send_pcs,
    .pc_tkl.cfg         = &g_wsrd.config.disc_cfg,
    .pc_tkl.debug_name  = "pc",
    .pc_tkl.on_transmit = ws_on_send_pc,
    .pan_selection_timer.callback = ws_on_pan_selection_timer_timeout,

    // Arbitrary parameters
    .ipv6.rpl.dis_txalg.irt_s = 5,
    .ipv6.rpl.dis_txalg.mrt_s = 180,
    .ipv6.rpl.dis_txalg.rand_min = -0.1,
    .ipv6.rpl.dis_txalg.rand_max = +0.1,
    .ipv6.rpl.dis_txalg.tx = ws_on_send_dis,
    .ipv6.rpl.dio_trickle.debug_name = "dio",
    .ipv6.rpl.on_dao_ack = wsrd_on_dao_ack,
    .ipv6.rpl.fd = -1,
    .ipv6.rpl.path_seq = RPL_LOLLIPOP_INIT,
    // Wi-SUN FAN 1.1v09 6.2.1.1 Configuration Parameters
    .ipv6.rpl.dao_txalg.irt_s = 3,
    .ipv6.rpl.dao_txalg.mrc   = 3,
    .ipv6.rpl.dao_txalg.mrt_s = 0,
    .ipv6.rpl.dao_txalg.mrd_s = 0,
    .ipv6.rpl.dao_txalg.rand_min = -0.1,
    .ipv6.rpl.dao_txalg.rand_max = +0.1,
    // RFC 6719 5. MRHOF Variables and Parameters
    .ipv6.rpl.mrhof.max_link_metric         =   512, // 128 * 4
    .ipv6.rpl.mrhof.max_path_cost           = 32768, // 128 * 256
    .ipv6.rpl.mrhof.parent_switch_threshold =   192, // 128 * 1.5
    .ipv6.rpl.mrhof.ws_neigh_table = &g_wsrd.ws.neigh_table,
    .ipv6.rpl.mrhof.on_pref_parent_change = wsrd_on_pref_parent_change,

    .ipv6.mpl.send = wsrd_mpl_send,
    .ipv6.mpl.abort = wsrd_mpl_abort,
    // Wi-SUN FAN 1.1v09 6.2.1.1 Configuration Parameters
    .ipv6.mpl.tkl_data_cfg.Imin_ms = 10 * 1000,
    .ipv6.mpl.tkl_data_cfg.Imax_ms = TRICKLE_DOUBLINGS(10, 3) * 1000,
    .ipv6.mpl.tkl_data_cfg.k = 3, // Arbitrary (default DATA_MESSAGE_K of 1 not suited)
    // RFC 7731 5.4. MPL Parameters
    .ipv6.mpl.seed_lifetime_ms = 30 * 60 * 1000,
    .ipv6.mpl.tkl_data_e_max = 3,

    // Wi-SUN FAN 1.1v08 - 6.2.3.1.2.1.2 Global and Unique Local Addresses
    .ipv6.dhcp.solicit_txalg.max_delay_s = 60,
    .ipv6.dhcp.solicit_txalg.irt_s       = 60,
    .ipv6.dhcp.solicit_txalg.mrt_s       = 3600,
    // RFC 8415 18.2.1. Creation and Transmission of Solicit Messages
    .ipv6.dhcp.solicit_txalg.mrd_s       = 0,
    // RFC 8415 15. Reliability of Client-Initiated Message Exchanges
    .ipv6.dhcp.solicit_txalg.rand_min    = -0.1,
    .ipv6.dhcp.solicit_txalg.rand_max    = +0.1,
    // Arbitrary
    .ipv6.dhcp.solicit_txalg.mrc         = 3,
    .ipv6.dhcp.solicit_txalg.fail        = wsrd_on_dhcp_txalg_failure,
    .ipv6.dhcp.fd    = -1,
    .ipv6.dhcp.get_dst     = wsrd_dhcp_get_dst,
    .ipv6.dhcp.on_addr_add = wsrd_on_dhcp_addr_add,
    .ipv6.dhcp.on_addr_del = wsrd_on_dhcp_addr_del,

    // RFC 4944 5.3. Fragmentation Type and Header
    .ipv6.lowpan_frag.reasm_timeout_ms = 60 * 1000,

    .dhcp_relay.fd = -1,
    // RFC 8415 7.6. Transmission and Retransmission Parameters
    .dhcp_relay.hop_limit = 8,

    // Arbitrary, same lifetime as MAC neighbors
    .ipv6.aro_lifetime_ms = WS_NEIGHBOR_LINK_TIMEOUT * 1000,
    // Wi-SUN FAN 1.1v09 6.2.1.1 Configuration Parameters
    .ipv6.ncr_resp_window_ms = 10000,
    .ipv6.ncr_req_retries = 3,
    // Arbitrary (default RETRANS_TIMER of 1s is not suited for Wi-SUN)
    .ipv6.probe_delay_ms =  60000,
    /*
     * RFC 4861 10. Protocol Constants
     * FIXME: BaseReachableTime and RetransTimer can be overritten by Router
     * Advertisements in normal NDP, but Wi-SUN disables RAs without providing
     * any sensible default values.
     */
    .ipv6.reach_base_ms  = 30000, // REACHABLE_TIME  30,000 milliseconds
    .ipv6.on_recv = wsrd_ipv6_on_recv,
};

static void wsrd_on_rcp_reset(struct rcp *rcp)
{
    struct wsrd *wsrd = container_of(rcp, struct wsrd, ws.rcp);

    if (rcp->has_rf_list)
        FATAL(3, "unsupported RCP reset");
    INFO("Connected to RCP \"%s\" (%d.%d.%d), API %d.%d.%d", rcp->version_label,
         FIELD_GET(0xFF000000, rcp->version_fw),
         FIELD_GET(0x00FFFF00, rcp->version_fw),
         FIELD_GET(0x000000FF, rcp->version_fw),
         FIELD_GET(0xFF000000, rcp->version_api),
         FIELD_GET(0x00FFFF00, rcp->version_api),
         FIELD_GET(0x000000FF, rcp->version_api));
    if (version_older_than(rcp->version_api, 2, 8, 0))
        FATAL(3, "RCP API < 2.8.0 (too old)");
    if (version_older_than(rcp->version_api, 2, 11, 0) &&
        wsrd->config.duty_cycle.budget_ms)
        FATAL(3, "duty_cycle_budget requires RCP API >= 2.11");
    if (version_older_than(rcp->version_api, 2, 11, 0) &&
        wsrd->config.duty_cycle.chan_budget_ms)
        FATAL(3, "duty_cycle_chan_budget requires RCP API >= 2.11");
}

static void wsrd_on_etx_outdated(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx)
{
    struct wsrd *wsrd = container_of(ws_etx_ctx, struct wsrd, ws.neigh_table.ws_etx_ctx);
    struct ws_neigh *neigh = container_of(ws_etx, struct ws_neigh, ws_etx);
    struct ipv6_neigh *nce;

    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.6.1 Link Metrics
     * In the absence of other messaging, a Router SHOULD initiate NUD
     * messaging to refresh the ETX value for that neighbor.
     */
    nce = ipv6_neigh_get_from_eui64(&wsrd->ipv6, &neigh->eui64);
    if (!nce || nce->nud_state == IPV6_NUD_DELAY || nce->nud_state == IPV6_NUD_PROBE ||
        !nce->rpl || !nce->rpl->cand_pref)
        return;
    ipv6_nud_set_state(&wsrd->ipv6, nce, IPV6_NUD_DELAY);
}

static void wsrd_on_etx_update(struct ws_etx_ctx *ws_etx_ctx, struct ws_etx *ws_etx)
{
    struct wsrd *wsrd = container_of(ws_etx_ctx, struct wsrd, ws.neigh_table.ws_etx_ctx);
    struct ws_neigh *neigh = container_of(ws_etx, struct ws_neigh, ws_etx);
    struct ipv6_neigh *nce;

    nce = ipv6_neigh_get_from_eui64(&wsrd->ipv6, &neigh->eui64);
    if (!nce || !nce->rpl || wsrd->ipv6.rpl.fd < 0)
        return;
    if (rpl_can_update_parent(&wsrd->ipv6))
        rpl_update_parents(&wsrd->ipv6);
}

static int wsrd_ipv6_sendto_mac(struct ipv6_ctx *ipv6, struct pktbuf *pktbuf, const struct eui64 *dst)
{
    struct wsrd *wsrd = container_of(ipv6, struct wsrd, ipv6);

    return ws_if_send_data(&wsrd->ws, pktbuf_head(pktbuf), pktbuf_len(pktbuf), dst);
}

static void wsrd_eapol_on_gtk_change(struct supp_ctx *supp, const uint8_t gtk[16], uint32_t frame_counter, uint8_t index)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);
    struct ws_neigh *neigh;
    uint8_t gak[16];

    // TODO: handle LGTK
    if (index > 4)
        return;

    SLIST_FOREACH(neigh, &wsrd->ws.neigh_table.neigh_list, link)
        neigh->frame_counter_min[index - 1] = gtk ? 0 : UINT32_MAX;

    if (gtk) {
        ws_generate_gak(wsrd->ws.netname, gtk, gak);
        TRACE(TR_SECURITY, "sec: install %s=%s",
              tr_gakname(index - 1), tr_key(gak, sizeof(gak)));
        rcp_set_sec_key(&wsrd->ws.rcp, index, gak, frame_counter);
    } else {
        rcp_set_sec_key(&wsrd->ws.rcp, index, NULL, 0);
    }
    dbus_emit_change("Gaks");

    if (ws_gtkl(supp->gtks, WS_GTK_COUNT) == supp->auth_gtkl)
        join_state_transition(wsrd, WSRD_EVENT_AUTH_SUCCESS);
}

static void wsrd_eapol_on_failure(struct supp_ctx *supp)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);
    struct ws_neigh *ws_neigh = ws_neigh_get(&wsrd->ws.neigh_table, &wsrd->eapol_target_eui64);
    struct ipv6_neigh *parent = rpl_neigh_get_parent(&wsrd->ipv6, RPL_PATH_CTL_PREFERRED);

    BUG_ON(parent && !eui64_eq(&wsrd->eapol_target_eui64, &parent->eui64));
    BUG_ON(!ws_neigh);

    /*
     * NOTES:
     * We always emit WSRD_EVENT_AUTH_FAIL in Join State 2 (pan_version == -1).
     * It is expected that by setting the routing_cost to 0xffff and
     * transitioning to JS1, we will end up selecting another EAPOL Target.
     * Otherwise, during Key-Rotation or LGTK(s) installation, we only emit a
     * WSRD_EVENT_AUTH_FAIL if we have no-more GTKs installed or start the
     * Key-Request txalg again. See supp_start_key_request() for more details.
     */
    ws_neigh->ie_pan.routing_cost = 0xffff;
    // TODO: check LGTKL once LFN are supported
    if (wsrd->ws.pan_version != -1 && ws_gtkl(wsrd->supp.gtks, WS_GTK_COUNT))
        supp_start_key_request(&wsrd->supp);
    if (wsrd->ws.pan_version == -1 || !ws_gtkl(wsrd->supp.gtks, WS_GTK_COUNT))
        join_state_transition(wsrd, WSRD_EVENT_AUTH_FAIL);
}

static void wsrd_eapol_sendto_mac(struct supp_ctx *supp, uint8_t kmp_id, const void *pkt,
                                  size_t pkt_len, const struct eui64 *dst)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);

    ws_if_send_eapol(&wsrd->ws, kmp_id, pkt, pkt_len, dst, NULL);
}

static struct eui64 wsrd_eapol_get_target(struct supp_ctx *supp)
{
    struct wsrd *wsrd = container_of(supp, struct wsrd, supp);

    return wsrd->eapol_target_eui64;
}

static void wsrd_on_pref_parent_change(struct rpl_mrhof *mrhof, struct ipv6_neigh *neigh)
{
    struct wsrd *wsrd = container_of(mrhof, struct wsrd, ipv6.rpl.mrhof);
    struct ws_neigh *ws_neigh;

    if (neigh) {
        ws_neigh = ws_neigh_get(&wsrd->ws.neigh_table, &neigh->eui64);
        BUG_ON(!ws_neigh);
        join_state_transition(wsrd, WSRD_EVENT_RPL_NEW_PREF_PARENT);
        if (eui64_eq(&wsrd->eapol_target_eui64, &neigh->eui64))
            return;
        /*
         *   Wi-SUN FAN 1.1v08 - 6.5.2.1.1 SUP Operation
         * A Router operating as a SUP MUST direct EAPOL frames to a node designated
         * as its EAPOL target. When a Router has determined a RPL parent, it shall
         * use that parent as the EAPOL target.
         */
        wsrd->eapol_target_eui64 = neigh->eui64;
        // NOTE: See comment in ws_pan_version_update()
        ws_check_gtkhash(wsrd);
        if (!ws_neigh_has_bs(&ws_neigh->fhss)) {
            wsrd->fhss_bc_synced_to_target = false;
            return;
        }
        if (!rfc8415_txalg_stopped(&wsrd->ipv6.dhcp.solicit_txalg))
            rfc8415_txalg_start(&wsrd->ipv6.dhcp.solicit_txalg);
        if (!rfc8415_txalg_stopped(&wsrd->supp.key_request_txalg))
            rfc8415_txalg_start(&wsrd->supp.key_request_txalg);
        ws_sync_fhss_bc(wsrd, ws_neigh);
    } else {
        wsrd->eapol_target_eui64 = EUI64_BC;
        if (rpl_mrhof_has_candidates(&wsrd->ipv6))
            join_state_transition(wsrd, WSRD_EVENT_RPL_PREF_LOST);
        else
            join_state_transition(wsrd, WSRD_EVENT_RPL_NO_CANDIDATE);
    }
}

static void wsrd_on_dhcp_addr_add(struct dhcp_client *client)
{
    struct wsrd *wsrd = container_of(client, struct wsrd, ipv6.dhcp);
    struct ipv6_neigh *nce;

    // TODO: set prefix len to 128, and add default route instead
    tun_addr_add(&wsrd->ipv6.tun, &client->iaaddr.ipv6, 64);
    SLIST_FOREACH(nce, &wsrd->ipv6.neigh_cache, link)
        if (nce->rpl && nce->rpl->path_ctl)
            ipv6_nud_set_state(&wsrd->ipv6, nce, IPV6_NUD_PROBE);
}

static void wsrd_on_dhcp_addr_del(struct dhcp_client *client)
{
    struct ipv6_ctx *ipv6 = container_of(client, struct ipv6_ctx, dhcp);

    tun_addr_del(&ipv6->tun, &client->iaaddr.ipv6, 64);
    // TODO: send NS(ARO) with 0 lifetime
}

static struct in6_addr wsrd_dhcp_get_dst(struct dhcp_client *client)
{
    struct ipv6_ctx *ipv6 = container_of(client, struct ipv6_ctx, dhcp);
    struct ipv6_neigh *pref_parent = rpl_neigh_get_parent(ipv6, RPL_PATH_CTL_PREFERRED);
    struct in6_addr parent_ll = ipv6_prefix_linklocal;

    BUG_ON(!pref_parent);
    ipv6_addr_conv_iid_eui64(parent_ll.s6_addr + 8, pref_parent->eui64.u8);
    return parent_ll;
}

void sig_error_handler(int signal)
{
    __PRINT(91, "bug: %s", strsignal(signal));
    backtrace_show();
    raise(signal);
}

static void wsrd_init_radio(struct wsrd *wsrd)
{
    const struct rcp_rail_config *rail_config;
    uint8_t chan_mask[WS_CHAN_MASK_LEN] = { };
    struct chan_params *chan_params;
    int chan_fixed;

    wsrd->ws.phy.params = ws_regdb_phy_params(wsrd->config.ws_phy_mode_id,
                                              wsrd->config.ws_mode);
    BUG_ON(!wsrd->ws.phy.params);
    wsrd->ws.phy.tx_power_dbm = wsrd->config.rcp.tx_power_dbm;
    wsrd->ws.phy.tx_attempts = wsrd->config.rcp.csma.frame_retries + 1;
    wsrd->ws.fhss.chan_params = rail_get_chan_params(&wsrd->ws.rcp, wsrd->config.ws_domain,
                                                     wsrd->config.ws_chan_plan_id,
                                                     wsrd->config.ws_class,
                                                     wsrd->ws.phy.params);
    if (!wsrd->ws.fhss.chan_params) {
        chan_params = zalloc(sizeof(*chan_params));
        chan_params->reg_domain   = wsrd->config.ws_domain;
        chan_params->chan0_freq   = wsrd->config.ws_chan0_freq;
        chan_params->chan_spacing = wsrd->config.ws_chan_spacing;
        chan_params->chan_count   = wsrd->config.ws_chan_count;
        wsrd->ws.fhss.chan_params = chan_params;
        wsrd->ws.fhss.chan_plan = 1;
    } else {
        wsrd->ws.fhss.chan_plan = wsrd->config.ws_chan_plan_id ? 2 : 0;
    }
    wsrd->ws.fhss.uc_dwell_interval = wsrd->config.ws_uc_dwell_interval_ms;
    ws_chan_mask_calc_reg(wsrd->ws.fhss.uc_chan_mask, wsrd->ws.fhss.chan_params);
    if (memzcmp(wsrd->config.ws_custom_allowed_channels, sizeof(wsrd->config.ws_custom_allowed_channels)))
        bitand(wsrd->ws.fhss.uc_chan_mask, wsrd->config.ws_custom_allowed_channels, 256);
    bitand(wsrd->ws.fhss.uc_chan_mask, wsrd->config.ws_allowed_channels, 256);
    if (!memzcmp(wsrd->ws.fhss.uc_chan_mask, sizeof(wsrd->ws.fhss.uc_chan_mask)))
        FATAL(1, "combination of allowed_channels and regulatory/custom_allowed_channels constraints results in no valid channel (see --list-rf-configs)");

    for (rail_config = wsrd->ws.rcp.rail_config_list; rail_config->chan0_freq; rail_config++)
        if (rail_config->rail_phy_mode_id == wsrd->ws.phy.params->rail_phy_mode_id   &&
            rail_config->chan0_freq       == wsrd->ws.fhss.chan_params->chan0_freq   &&
            rail_config->chan_spacing     == wsrd->ws.fhss.chan_params->chan_spacing &&
            rail_config->chan_count       == wsrd->ws.fhss.chan_params->chan_count)
            break;
    if (!rail_config->chan0_freq)
        FATAL(2, "unsupported radio configuration (check --list-rf-configs)");

    wsrd->ws.phy.enable_apc = wsrd->config.enable_apc;
    if (!version_older_than(wsrd->ws.rcp.version_api, 2, 13, 0))
        rcp_set_radio_apc(&wsrd->ws.rcp, wsrd->ws.phy.enable_apc);
    else
        WARN("enable_apc requires RCP API >= 2.13 for ack frames");

    rail_fill_pom(&wsrd->ws.rcp, &wsrd->ws.fhss, &wsrd->ws.phy, wsrd->config.ws_phy_op_modes);
    rcp_set_radio(&wsrd->ws.rcp, rail_config->index, wsrd->ws.phy.params->ofdm_mcs, wsrd->ws.phy.phy_op_modes[0] != 0);
    wsrd->ws.phy.rcp_rail_config_index = rail_config->index;

    /*
     *   Wi-SUN FAN 1.1v10 6.3.4.6.2 Join Usage of Asynchronous Frame Transmission
     * When operating in fixed channel mode on a specific channel, ChannelList
     * MUST contain a single entry for that specific channel.
     *   Wi-SUN FAN 1.1v10 6.3.4.6.2.1 FFN Usage of MLME-WS-ASYNC-FRAME
     * The MLME-WS-ASYNC-FRAME.request mechanism MUST be performed over All
     * Regulatory Channels.
     */
    chan_fixed = ws_chan_mask_get_fixed(wsrd->ws.fhss.uc_chan_mask);
    if (chan_fixed >= 0) {
        bitset(chan_mask, chan_fixed);
    } else {
        ws_chan_mask_calc_reg(chan_mask, wsrd->ws.fhss.chan_params);
        if (memzcmp(wsrd->config.ws_custom_allowed_channels, sizeof(wsrd->config.ws_custom_allowed_channels)))
            bitand(chan_mask, wsrd->config.ws_custom_allowed_channels, 256);
        if (!memzcmp(chan_mask, sizeof(chan_mask)))
            FATAL(1, "regulatory/custom_allowed_channels constraints results in no valid channel (see --list-rf-configs)");
    }
    rcp_set_fhss_async(&wsrd->ws.rcp, 500, chan_mask);
    ws_fhss_uc_use_default(wsrd);
    rcp_req_radio_enable(&wsrd->ws.rcp);
}

static void wsrd_init_ipv6(struct wsrd *wsrd)
{
    struct in6_addr addr_linklocal = ipv6_prefix_linklocal;
    BUG_ON(!wsrd->ipv6.sendto_mac);

    strcpy(wsrd->ipv6.tun.ifname, wsrd->config.tun_dev);
    tun_init(&wsrd->ipv6.tun, wsrd->config.tun_autoconf);
    tun_sysctl_set("/proc/sys/net/ipv6/conf", wsrd->ipv6.tun.ifname, "accept_ra", '0');

    ipv6_addr_conv_iid_eui64(addr_linklocal.s6_addr + 8, wsrd->ws.rcp.eui64.u8);
    tun_addr_add(&wsrd->ipv6.tun, &addr_linklocal, 64);

    timer_group_init(&wsrd->ipv6.timer_group);
    lowpan_frag_init(&wsrd->ipv6.lowpan_frag);

    wsrd->ipv6.rpl.compat = wsrd->config.rpl_compat;
    wsrd->ipv6.rpl.mrhof.device_min_sens_dbm =
        wsrd->ws.rcp.rail_config_list[wsrd->ws.phy.rcp_rail_config_index].sensitivity_dbm;
    dhcp_client_init(&wsrd->ipv6.dhcp, &wsrd->ipv6.tun, wsrd->ws.rcp.eui64.u8);
    tun_addr_add_mc(&wsrd->ipv6.tun, &ipv6_addr_all_nodes_link);     // ff02::1
    tun_addr_add_mc(&wsrd->ipv6.tun, &ipv6_addr_all_routers_link);   // ff02::2
    tun_addr_add_mc(&wsrd->ipv6.tun, &ipv6_addr_all_rpl_nodes_link); // ff02::1a
    tun_addr_add_mc(&wsrd->ipv6.tun, &ipv6_addr_all_nodes_realm);    // ff03::1
    tun_addr_add_mc(&wsrd->ipv6.tun, &ipv6_addr_all_routers_realm);  // ff03::2
    tun_addr_add_mc(&wsrd->ipv6.tun, &ipv6_addr_all_mpl_fwd_realm);  // ff03::fc

    icmpv6_err_init(&wsrd->ipv6.icmp_err, wsrd->ipv6.tun.ifname);
    mpl_init(&wsrd->ipv6.mpl);
}

static void wsrd_init_ws(struct wsrd *wsrd)
{
    uint8_t chan_mask[WS_CHAN_MASK_LEN];
    uint64_t pc_duration_ms;
    uint16_t chan_count;

    strcpy(wsrd->ws.netname, wsrd->config.ws_netname);

    // Average PC frame length with LFN IEs: 130 bytes
    pc_duration_ms = ws_regdb_frame_duration_ms(wsrd->ws.phy.params, 130);
    ws_chan_mask_calc_reg(chan_mask, wsrd->ws.fhss.chan_params);
    chan_count = ws_chan_mask_count(chan_mask);
    /*
     * NOTE: DIS transmission is typically started right after receiving a PC
     * frame. Delay at least until the PC async transmission sequence has ended
     * to avoid collisions.
     */
    wsrd->ipv6.rpl.dis_txalg.min_delay_s = divup(pc_duration_ms * chan_count, 1000);
    wsrd->ipv6.rpl.dis_txalg.max_delay_s = wsrd->ipv6.rpl.dis_txalg.min_delay_s + 5; // Arbitrary

    timer_group_init(&wsrd->ws.neigh_table.timer_group);
    timer_group_init(&wsrd->ws.neigh_table.ws_etx_ctx.timer_group);
    trickle_init(&wsrd->pas_tkl);
    trickle_init(&wsrd->pa_tkl);
    trickle_init(&wsrd->pcs_tkl);
    trickle_init(&wsrd->pc_tkl);
    supp_init(&wsrd->supp);
    supp_reset(&wsrd->supp);
    if (!wsrd_storage_load(wsrd) || !supp_storage_load(&wsrd->supp) ||
        !ws_gtkl(wsrd->supp.gtks, ARRAY_SIZE(wsrd->supp.gtks))) {
        join_state_1_enter(wsrd);
        return;
    }

    wsrd->state = WSRD_STATE_RECONNECT;
    wsrd->supp.running = true;
    join_state_3_reconnect_enter(wsrd);
}

static void wsrd_eapol_relay_recv(struct wsrd *wsrd)
{
    struct eui64 supp_eui64;
    uint8_t buf[1500];
    ssize_t buf_len;
    uint8_t kmp_id;

    buf_len = eapol_relay_recv(wsrd->ws.eapol_relay_fd, buf, sizeof(buf),
                               NULL, &supp_eui64, &kmp_id);
    if (buf_len < 0)
        return;
    ws_if_send_eapol(&wsrd->ws, kmp_id, buf, buf_len, &supp_eui64, &wsrd->supp.auth_eui64);
}

static void wsrd_handle_signal(struct wsrd *wsrd, int signal_fd)
{
    struct signalfd_siginfo fdsi;
    ssize_t read_size;

    read_size = read(signal_fd, &fdsi, sizeof(fdsi));
    FATAL_ON(read_size != sizeof(fdsi), 2);
    switch (fdsi.ssi_signo) {
        case SIGTERM:
            join_state_transition(wsrd, WSRD_EVENT_DISCONNECT);
            break;
        case SIGINT:
        case SIGHUP:
            // Exit cleanly to dump coverage.
            exit(EXIT_SUCCESS);
        default:
            break;
    }
}

static void wsrd_poll(struct wsrd *wsrd, struct pollfd *pfd, const sigset_t *sig_mask)
{
    int ret;

    pfd[POLLFD_RPL].fd = wsrd->ipv6.rpl.fd;
    pfd[POLLFD_DHCP_RELAY].fd  = wsrd->dhcp_relay.fd;
    pfd[POLLFD_EAPOL_RELAY].fd = wsrd->ws.eapol_relay_fd;
    pfd[POLLFD_TUN].events = ws_if_active_tx_count(&wsrd->ws) >= WS_IF_FRAME_MAX - 1 ? 0 : POLLIN;
    ret = poll(pfd, POLLFD_COUNT, wsrd->ws.rcp.bus.uart.data_ready ? 0 : -1);
    FATAL_ON(ret < 0, 2, "poll: %m");
    if (wsrd->ws.rcp.bus.uart.data_ready ||
        pfd[POLLFD_RCP].revents & POLLIN)
        rcp_rx(&wsrd->ws.rcp);
    if (pfd[POLLFD_TIMER].revents & POLLIN)
        timer_process();
    if (pfd[POLLFD_TUN].revents & POLLIN)
        ipv6_recvfrom_tun(&wsrd->ipv6);
    if (pfd[POLLFD_RPL].revents & POLLIN)
        rpl_recv(&wsrd->ipv6);
    if (pfd[POLLFD_DHCP].revents & POLLIN)
        dhcp_client_recv(&wsrd->ipv6.dhcp);
    if (pfd[POLLFD_DHCP_RELAY].revents & POLLIN)
        dhcp_relay_recv(&wsrd->dhcp_relay);
    if (pfd[POLLFD_EAPOL_RELAY].revents & POLLIN)
        wsrd_eapol_relay_recv(wsrd);
    if (pfd[POLLFD_DBUS].revents & POLLIN)
        dbus_process();
    if (pfd[POLLFD_SIGNAL].revents & POLLIN) {
        wsrd_handle_signal(wsrd, pfd[POLLFD_SIGNAL].fd);
        // Unblock signals so they are delivered normally if needed
        sigprocmask(SIG_UNBLOCK, sig_mask, NULL);
        close(pfd[POLLFD_SIGNAL].fd);
        pfd[POLLFD_SIGNAL].fd = -1;
    }
}

int wsrd_main(int argc, char *argv[])
{
    struct pollfd pfd[POLLFD_COUNT] = { };
    static const char *files[] = {
        "counter-*:*:*:*:*:*:*:*",
        "network-config",
        "network-keys",
        "mpl",
        NULL,
    };
    struct sigaction sigact = { };
    struct wsrd *wsrd = &g_wsrd;
    sigset_t sig_mask;

    INFO("Silicon Labs Wi-SUN router %s", version_daemon_str);
    sigact.sa_flags = SA_RESETHAND;
    sigact.sa_handler = sig_error_handler;
    sigaction(SIGILL, &sigact, NULL);
    sigaction(SIGSEGV, &sigact, NULL);
    sigaction(SIGBUS, &sigact, NULL);
    sigaction(SIGFPE, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);

    parse_commandline(&wsrd->config, argc, argv);
    if (wsrd->config.color_output != -1)
        g_enable_color_traces = wsrd->config.color_output;

    check_mbedtls_features();

    if (wsrd->config.storage_delete) {
        INFO("deleting storage");
        storage_delete(files);
    }

    rcp_init(&wsrd->ws.rcp, &wsrd->config.rcp);
    if (wsrd->config.list_rf_configs) {
        rail_print_config_list(&wsrd->ws.rcp);
        exit(0);
    }

    wsrd->ipv6.eui64 = wsrd->ws.rcp.eui64;
    wsrd->config.supp.eui64 = wsrd->ws.rcp.eui64;

    wsrd_init_radio(wsrd);
    wsrd_init_ws(wsrd);
    wsrd_init_ipv6(wsrd);
    dbus_register("com.silabs.Wisun.Router",
                  "/com/silabs/Wisun/Router",
                  "com.silabs.Wisun.Router",
                  wsrd_dbus_vtable, wsrd);

    // keep privileges to manage interface later
    if (wsrd->config.user[0] && wsrd->config.group[0])
        drop_privileges(wsrd->config.user, wsrd->config.group,
                        (int[]){ CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW }, 3);

    INFO("Wi-SUN Router successfully started");

    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGINT);
    sigaddset(&sig_mask, SIGHUP);
    sigaddset(&sig_mask, SIGTERM);
    // Block signals so they are delivered via signalfd, not asynchronously
    sigprocmask(SIG_BLOCK, &sig_mask, NULL);
    pfd[POLLFD_SIGNAL].events = POLLIN;
    pfd[POLLFD_SIGNAL].fd = signalfd(-1, &sig_mask, 0);
    FATAL_ON(pfd[POLLFD_SIGNAL].fd < 0, 2, "signalfd: %m");

    pfd[POLLFD_RCP].fd = wsrd->ws.rcp.bus.fd;
    pfd[POLLFD_RCP].events = POLLIN;
    pfd[POLLFD_TIMER].fd = timer_fd();
    pfd[POLLFD_TIMER].events = POLLIN;
    pfd[POLLFD_TUN].fd = wsrd->ipv6.tun.fd;
    pfd[POLLFD_TUN].events = POLLIN;
    pfd[POLLFD_RPL].events = POLLIN;
    pfd[POLLFD_DHCP].fd = wsrd->ipv6.dhcp.fd;
    pfd[POLLFD_DHCP].events = POLLIN;
    pfd[POLLFD_DHCP_RELAY].events = POLLIN;
    pfd[POLLFD_DBUS].fd = dbus_get_fd();
    pfd[POLLFD_DBUS].events = POLLIN;
    pfd[POLLFD_EAPOL_RELAY].events = POLLIN;
    wsrd->running = true;
    while (wsrd->running)
        wsrd_poll(wsrd, pfd, &sig_mask);
    return EXIT_SUCCESS;
}
