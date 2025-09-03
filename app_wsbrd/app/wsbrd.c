/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#define _GNU_SOURCE
#include <linux/capability.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "common/specs/mpl.h"
#include "common/ws/eapol_relay.h"
#include "common/ws/ws_regdb.h"
#include "common/mbedtls_config_check.h"
#include "common/bus_uart.h"
#include "common/bus_cpc.h"
#include "common/capture.h"
#include "common/dbus.h"
#include "common/dhcp_server.h"
#include "common/bus.h"
#include "common/log.h"
#include "common/bits.h"
#include "common/mathutils.h"
#include "common/version.h"
#include "common/key_value_storage.h"
#include "common/drop_privileges.h"
#include "common/rpl_lollipop.h"
#include "common/string_extra.h"
#include "common/rail_config.h"
#include "common/specs/ws.h"
#include "common/rand.h"
#include "common/rcp_api.h"

#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "ws/ws_pan_info_storage.h"
#include "ws/ws_auth.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_bootstrap_6lbr.h"
#include "ws/ws_common.h"
#include "ws/ws_llc.h"
#include "ws/ws_config.h"
#include "net/timers.h"
#include "net/ns_address_internal.h"
#include "net/netaddr_types.h"
#include "net/protocol.h"
#include "rpl/rpl_glue.h"
#include "rpl/rpl_storage.h"
#include "rpl/rpl.h"
#include "common/ipv6/mpl.h"
#include "net/ns_buffer.h"
#include "ipv6/ipv6.h"

#include "commandline_values.h"
#include "commandline.h"
#include "wsbr_cfg.h"
#include "wsbr_mac.h"
#include "wsbr_pcapng.h"
#include "libwsbrd.h"
#include "wsbrd.h"
#include "dbus.h"
#include "tun.h"

static void wsbr_handle_reset(struct rcp *rcp);
static void wsbr_rpl_target_add(struct rpl_root *root, struct rpl_target *target);
static void wsbr_rpl_target_del(struct rpl_root *root, struct rpl_target *target);
static void wsbr_rpl_target_update(struct rpl_root *root, struct rpl_target *target);

static void wsbr_on_gtk_change(struct auth_ctx *auth, uint8_t removed_mask, uint8_t installed_mask,
                               uint8_t activated_mask)
{
    struct wsbr_ctxt *ctxt = container_of(auth, struct wsbr_ctxt, auth);
    bool increase_pan_version = false;
    bool increase_lfn_version = false;
    uint8_t gak[16];

    for (int slot = 0; slot < ARRAY_SIZE(auth->gtks); slot++) {
        if (!((removed_mask | installed_mask | activated_mask) & BIT(slot)))
            continue;
        if (removed_mask & BIT(slot))
            ws_bootstrap_nw_key_set(&ctxt->net_if, slot + 1, NULL, 0);
        if (installed_mask & BIT(slot)) {
            ws_generate_gak(ctxt->net_if.ws_info.network_name, auth->gtks[slot].key, gak);
            TRACE(TR_SECURITY, "sec: install %s=%s",
                  tr_gakname(slot), tr_key(gak, sizeof(gak)));
            ws_bootstrap_nw_key_set(&ctxt->net_if, slot + 1, gak, auth->gtks[slot].frame_counter);
        }
        if (activated_mask & BIT(slot))
            ws_bootstrap_nw_key_index_set(&ctxt->net_if, slot);
        increase_pan_version |= slot < WS_GTK_COUNT;
        increase_lfn_version |= slot >= WS_GTK_COUNT;
    }
    /*
     * During reboot, the authenticator installs GTKs and LGTKs loaded from
     * storage.
     * We do not want to increase the version numbers in this case, so we rely
     * on the status of the PC trickle that is started in ws_bootstrap_6lbr_init().
     */
    if (trickle_stopped(&ctxt->net_if.ws_info.mngt.trickle_pc))
        return;
    // LFN version increase already increases PAN version
    if (increase_pan_version && !increase_lfn_version)
        ws_mngt_pan_version_increase(&ctxt->net_if.ws_info);
    if (increase_lfn_version)
        ws_mngt_lfn_version_increase(&ctxt->net_if.ws_info);
}

static void *wsbr_mpl_send(struct mpl_ctx *mpl, const void *buf, size_t buf_len)
{
    struct net_if *net_if = container_of(mpl, struct net_if, mpl);
    const struct ip6_hdr *ip6_hdr = buf;
    buffer_t *buffer = buffer_get_minimal(buf_len);

    buffer_data_add(buffer, buf, buf_len);
    buffer->src_sa.addr_type = ADDR_IPV6;
    memcpy(buffer->src_sa.address, &ip6_hdr->ip6_src, 16);
    buffer->dst_sa.addr_type = ADDR_IPV6;
    memcpy(buffer->dst_sa.address, &ip6_hdr->ip6_dst, 16);
    buffer->options.hop_limit = ip6_hdr->ip6_hlim;
    buffer->interface = net_if;
    buffer->info = (buffer_info_t)(B_DIR_DOWN | B_FROM_IPV6_FWD | B_TO_IPV6_TXRX);

    if (!ipv6_buffer_route(buffer)) {
        buffer_free(buffer);
        TRACE(TR_TX_ABORT, "tx-abort: no route to %s", tr_ipv6(buffer->dst_sa.address));
        return NULL;
    }
    protocol_push(buffer);
    return buffer;
}

static void wsbr_mpl_abort(struct mpl_ctx *mpl, void *tx_ctx)
{
    struct net_if *net_if = container_of(mpl, struct net_if, mpl);
    struct buffer *buf = tx_ctx;

    lowpan_adaptation_abort_buffer_tx(net_if, buf);
}

// See warning in wsbrd.h
struct wsbr_ctxt g_ctxt = {
    .rcp.on_reset = wsbr_handle_reset,
    .rcp.on_tx_cnf = wsbr_tx_cnf,
    .rcp.on_rx_ind = wsbr_rx_ind,

    // avoid initializating to 0 = STDIN_FILENO
    .tun.fd = -1,
    .pcapng_fd = -1,
    .rcp.bus.fd = -1,
    .dhcp_server.fd = -1,
    .net_if.rpl_root.sockfd = -1,

    .net_if.auth = &g_ctxt.auth,
    .auth.cfg = &g_ctxt.config.auth_cfg,
    .auth.radius_fd = -1,
    .auth.timeout_ms = 30 * 1000, // Arbitrary
    .auth.sendto_mac    = ws_llc_auth_sendto_mac,
    .auth.on_gtk_change = wsbr_on_gtk_change,

    .dhcp_relay.fd = -1,
    // RFC 8415 7.6. Transmission and Retransmission Parameters
    .dhcp_relay.hop_limit = 8,

    // Defined by Wi-SUN FAN 1.1v06 - 6.2.1.1 Configuration Parameters
    .net_if.rpl_root.dio_i_min        = 19,
    .net_if.rpl_root.dio_i_doublings  = 1,
    .net_if.rpl_root.dio_redundancy   = 0,
    .net_if.rpl_root.lifetime_unit_s  = 1200,
    .net_if.rpl_root.lifetime_s = 1200 * 6,
    .net_if.rpl_root.min_hop_rank_inc = 128,
    .net_if.rpl_root.dio_trickle.cfg  = &g_ctxt.net_if.rpl_root.dio_trickle_cfg,
    .net_if.rpl_root.dio_trickle.debug_name = "dio",
    // Defined by Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
    .net_if.rpl_root.pcs              = 7,

    .net_if.rpl_root.dodag_version_number = RPL_LOLLIPOP_INIT,
    .net_if.rpl_root.instance_id      = 0,
    .net_if.rpl_root.on_target_add    = wsbr_rpl_target_add,
    .net_if.rpl_root.on_target_del    = wsbr_rpl_target_del,
    .net_if.rpl_root.on_target_update = wsbr_rpl_target_update,

    .net_if.llc_random_early_detection.weight = RED_AVERAGE_WEIGHT_EIGHTH,
    .net_if.llc_random_early_detection.threshold_min = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN,
    .net_if.llc_random_early_detection.threshold_max = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX,
    .net_if.llc_random_early_detection.drop_max_probability = 100,

    .net_if.llc_eapol_random_early_detection.weight = RED_AVERAGE_WEIGHT_EIGHTH,
    .net_if.llc_eapol_random_early_detection.threshold_min = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN,
    .net_if.llc_eapol_random_early_detection.threshold_max = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX,
    .net_if.llc_eapol_random_early_detection.drop_max_probability = 100,

    .net_if.pae_random_early_detection.weight = RED_AVERAGE_WEIGHT_DISABLED,
    .net_if.pae_random_early_detection.threshold_min = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN,
    .net_if.pae_random_early_detection.threshold_max = MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX,
    .net_if.pae_random_early_detection.drop_max_probability = 100,

    .net_if.ws_info.neighbor_storage.on_add = ws_bootstrap_neighbor_add_cb,
    .net_if.ws_info.neighbor_storage.on_del = ws_bootstrap_neighbor_del_cb,
    .net_if.ws_info.pan_information.pan_id = -1,
    .net_if.ws_info.fhss_config.bsi = -1,

    .net_if.mpl.send = wsbr_mpl_send,
    .net_if.mpl.abort = wsbr_mpl_abort,

    .net_if.ws_info.mngt.trickle_pa.debug_name = "pa",
    .net_if.ws_info.mngt.trickle_pa.on_transmit = ws_mngt_pa_send,
    .net_if.ws_info.mngt.trickle_pc.debug_name = "pc",
    .net_if.ws_info.mngt.trickle_pc.on_transmit = ws_mngt_pc_send,
};

static void wsbr_rpl_target_add(struct rpl_root *root, struct rpl_target *target)
{
    struct wsbr_ctxt *ctxt = container_of(root, struct wsbr_ctxt, net_if.rpl_root);

    ipv6_route_add_with_info(target->prefix,      // prefix
                             128,                 // prefix length
                             ctxt->net_if.id,     // interface id
                             in6addr_any.s6_addr, // next hop
                             ROUTE_RPL_DAO_SR,    // source
                             (void *)root,        // info
                             0,                   // source id
                             0xffffffff,          // lifetime
                             0);                  // pref
    tun_add_node_to_proxy_neightbl(&ctxt->net_if, target->prefix);
    tun_add_ipv6_direct_route(&ctxt->net_if, target->prefix);
}

static void wsbr_rpl_target_del(struct rpl_root *root, struct rpl_target *target)
{
    struct wsbr_ctxt *ctxt = container_of(root, struct wsbr_ctxt, net_if.rpl_root);

    ipv6_route_delete_with_info(target->prefix,      // prefix
                                128,                 // prefix length
                                ctxt->net_if.id,     // interface id
                                in6addr_any.s6_addr, // next hop
                                ROUTE_RPL_DAO_SR,    // source
                                (void *)root,        // info
                                0);                  // source id
    dbus_emit_change("Nodes");
    dbus_emit_change("RoutingGraph");
}

static void wsbr_rpl_target_update(struct rpl_root *root, struct rpl_target *target)
{
    struct wsbr_ctxt *ctxt = container_of(root, struct wsbr_ctxt, net_if.rpl_root);
    struct ipv6_neighbour *neigh;
    bool is_neigh = false;

    dbus_emit_change("Nodes");
    dbus_emit_change("RoutingGraph");

    /*
     * HACK: Delete the neighbor cache entry in case the node did not
     * remove itself. Otherwise routing will choose an "ARO route" instead
     * of a "DAO route", which will fail until ARO expiration.
     */
    for (uint8_t i = 0; i < root->pcs + 1; i++)
        if (IN6_ARE_ADDR_EQUAL(target->transits[i].parent, root->dodag_id))
            is_neigh = true;
    if (!is_neigh) {
        neigh = ipv6_neighbour_lookup(&ctxt->net_if.ipv6_neighbour_cache, target->prefix);
        if (neigh)
            ipv6_neighbour_entry_remove(&ctxt->net_if.ipv6_neighbour_cache, neigh);
    }
}

static void ws_enable_mac_filtering(struct wsbr_ctxt *ctxt)
{
    BUG_ON(ctxt->config.ws_allowed_mac_address_count && ctxt->config.ws_denied_mac_address_count);
    if (!ctxt->config.ws_allowed_mac_address_count && !ctxt->config.ws_denied_mac_address_count)
        return;
    if (ctxt->config.ws_allowed_mac_address_count)
        rcp_set_filter_src64(&ctxt->rcp,
                             ctxt->config.ws_allowed_mac_addresses,
                             ctxt->config.ws_allowed_mac_address_count,
                             true);
    else
        rcp_set_filter_src64(&ctxt->rcp,
                             ctxt->config.ws_denied_mac_addresses,
                             ctxt->config.ws_denied_mac_address_count,
                             false);
}

static uint16_t wsbr_get_max_pan_size(uint8_t network_size)
{
    switch (network_size) {
    case WS_NETWORK_SIZE_CERTIFICATION:
    case WS_NETWORK_SIZE_SMALL:
        return 100;
    case WS_NETWORK_SIZE_MEDIUM:
        return 1000;
    case WS_NETWORK_SIZE_LARGE:
        return 10000;
    case WS_NETWORK_SIZE_XLARGE:
        return UINT16_MAX;
    default:
        BUG();
    }
}

static void wsbr_configure_ws(struct wsbr_ctxt *ctxt)
{
    struct ws_info *ws_info = &ctxt->net_if.ws_info;
    struct ws_fhss_config *fhss = &ws_info->fhss_config;
    struct chan_params *chan_params;

    ws_info->phy_config.params = ws_regdb_phy_params(ctxt->config.ws_phy_mode_id,
                                                     ctxt->config.ws_mode);
    BUG_ON(!ws_info->phy_config.params);

    if (ctxt->config.ws_join_metrics & BIT(WS_JM_PLF)) {
        ws_info->pan_information.jm.metrics[0].hdr |= FIELD_PREP(WS_MASK_JM_ID,  WS_JM_PLF);
        ws_info->pan_information.jm.metrics[0].hdr |= FIELD_PREP(WS_MASK_JM_LEN, 1);
    }

    fhss->chan_params = ws_regdb_chan_params(ctxt->config.ws_domain,
                                             ctxt->config.ws_chan_plan_id,
                                             ctxt->config.ws_class);
    if (!fhss->chan_params) {
        chan_params = zalloc(sizeof(*fhss->chan_params));
        chan_params->reg_domain   = ctxt->config.ws_domain;
        chan_params->chan0_freq   = ctxt->config.ws_chan0_freq;
        chan_params->chan_spacing = ctxt->config.ws_chan_spacing;
        chan_params->chan_count   = ctxt->config.ws_chan_count;
        fhss->chan_params = chan_params;
        fhss->chan_plan = 1;
    } else if (ctxt->config.ws_chan_plan_id) {
        fhss->chan_plan = 2;
    } else {
        fhss->chan_plan = 0;
    }

    fhss->uc_dwell_interval  = ctxt->config.uc_dwell_interval;
    fhss->bc_dwell_interval  = ctxt->config.bc_dwell_interval;
    fhss->bc_interval        = ctxt->config.bc_interval;
    fhss->lfn_bc_interval    = ctxt->config.lfn_bc_interval;
    fhss->lfn_bc_sync_period = ctxt->config.lfn_bc_sync_period;

    if (ctxt->config.ws_regional_regulation) {
        fhss->regional_regulation = ctxt->config.ws_regional_regulation;
        rcp_set_radio_regulation(&ctxt->rcp, ctxt->config.ws_regional_regulation);
    }
    ws_info->phy_config.enable_apc = ctxt->config.enable_apc;
    if (ctxt->config.ws_regional_regulation == HIF_REG_ETSI ||
        ctxt->config.ws_regional_regulation == HIF_REG_WPC)
        ws_info->phy_config.enable_apc = true;
    if (!version_older_than(ctxt->rcp.version_api, 2, 13, 0))
        rcp_set_radio_apc(&ctxt->rcp, ws_info->phy_config.enable_apc);
    else if (ctxt->config.enable_apc)
        WARN("enable_apc requires RCP API >= 2.13.0 for ack frames");

    if (!version_older_than(ctxt->rcp.version_api, 2, 15, 0))
        rcp_set_data_edfe(&ctxt->rcp, true,
                          ctxt->config.enable_ffn10 ? WS_FAN_VERSION_1_0 : WS_FAN_VERSION_1_1);
    else if (ctxt->config.enable_ffn10)
        WARN("enable_ffn10 requires RCP API >= 2.14.0 for edfe frames");

    ws_chan_mask_calc_reg(fhss->uc_chan_mask, fhss->chan_params);
    ws_chan_mask_calc_reg(fhss->bc_chan_mask, fhss->chan_params);
    bitand(fhss->uc_chan_mask, ctxt->config.ws_allowed_channels, 256);
    bitand(fhss->bc_chan_mask, ctxt->config.ws_allowed_channels, 256);
    if (!memzcmp(fhss->uc_chan_mask, sizeof(fhss->uc_chan_mask)))
        FATAL(1, "combination of allowed_channels and regulatory constraints results in no valid channel (see --list-rf-configs)");

    rail_fill_pom(&ctxt->rcp, &ws_info->fhss_config, &ws_info->phy_config, ctxt->config.ws_phy_op_modes);

    ws_info->mngt.lts_timer.callback = ws_mngt_lts_timeout;
    ws_info->mngt.lts_timer.period_ms = ctxt->config.lfn_bc_interval * ctxt->config.lfn_bc_sync_period;
    fhss->async_frag_duration_ms = ctxt->config.ws_async_frag_duration;

    ws_pan_info_storage_read(&fhss->bsi, &ws_info->pan_information.pan_id,
                             &ws_info->pan_information.pan_version,
                             &ws_info->pan_information.lfn_version,
                             ws_info->network_name);

    if (memzcmp(ws_info->network_name, sizeof(ws_info->network_name)) &&
        strcmp(ws_info->network_name, ctxt->config.ws_name))
        FATAL(1, "Network Name out-of-date in storage (see -D)");
    strlcpy(ws_info->network_name, ctxt->config.ws_name, sizeof(ws_info->network_name));

    if (ctxt->config.ws_pan_id != -1 && ws_info->pan_information.pan_id != -1 &&
        ws_info->pan_information.pan_id != ctxt->config.ws_pan_id)
        FATAL(1, "PAN_ID out-of-date in storage (see -D)");
    if (ws_info->pan_information.pan_id == -1)
        ws_info->pan_information.pan_id = ctxt->config.ws_pan_id;
    if (ws_info->pan_information.pan_id == -1)
        ws_info->pan_information.pan_id = rand_get_random_in_range(0, 0xfffe);
    if (fhss->bsi == -1)
        fhss->bsi = rand_get_random_in_range(0, 0xffff);

    BUG_ON(ctxt->config.ws_size >= ARRAY_SIZE(size_params));
    /*
     *   Wi-SUN FAN 1.1v08 6.2.3.1.8 Multicast Forwarding
     * For networks operating only with FAN 1.1 nodes, it is RECOMMENDED to set
     * the S field to 0 and elide the seed-id field (source address is the FFN
     * seed address). Otherwise by default, the S field value MUST be set to 3
     * with the seed-id field set to the GUA\ULA of the FFN seed (this for
     * backwards compatibility with FAN 1.0).
     */
    addr_add_group(&ctxt->net_if, ADDR_ALL_MPL_FORWARDERS);
    ctxt->net_if.mpl.seed_lifetime_ms = size_params[ctxt->config.ws_size].mpl_seed_set_entry_lifetime * 1000;
    ctxt->net_if.mpl.tkl_data_cfg = size_params[ctxt->config.ws_size].trickle_mpl;
    ctxt->net_if.mpl.tkl_data_e_max = size_params[ctxt->config.ws_size].trickle_mpl_e_max;
    ctxt->net_if.mpl.s = ctxt->config.enable_ffn10 ? MPL_S_128 : MPL_S_SRC;
    mpl_init(&ctxt->net_if.mpl);

    ws_info->mngt.trickle_pa.cfg = &size_params[ctxt->config.ws_size].trickle_discovery;
    ws_info->mngt.trickle_pc.cfg = &size_params[ctxt->config.ws_size].trickle_discovery;
    trickle_init(&ws_info->mngt.trickle_pa);
    trickle_init(&ws_info->mngt.trickle_pc);

    ws_info->pan_information.version = ctxt->config.ws_fan_version;
    ws_info->pan_information.max_pan_size = wsbr_get_max_pan_size(ctxt->config.ws_size);
    ws_info->pan_information.test_pan_size = ctxt->config.pan_size;
    ws_info->enable_lfn   = ctxt->config.enable_lfn;
    ws_info->enable_ffn10 = ctxt->config.enable_ffn10;

    rcp_set_radio_tx_power(&ctxt->rcp, ctxt->config.tx_power);
    ws_info->phy_config.tx_power_dbm = ctxt->config.tx_power;

    if (!version_older_than(ctxt->rcp.version_api, 2, 12, 0))
        rcp_set_radio_csma(&ctxt->rcp, &ctxt->config.csma);
    else if (memcmp(&ctxt->config.csma, &rcp_csma_default, sizeof(struct rcp_csma_cfg)))
        WARN("csma_* parameters require RCP API >= 2.12.0");
    ws_info->phy_config.tx_attempts = ctxt->config.csma.frame_retries + 1;

    ws_enable_mac_filtering(ctxt);

    timer_group_init(&ws_info->neighbor_storage.timer_group);
}

static void wsbr_check_link_local_addr(struct wsbr_ctxt *ctxt)
{
    struct in6_addr addr_tun;
    uint8_t addr_ws0[16];
    int ret;
    bool cmp;

    ret = tun_addr_get_linklocal(&ctxt->tun, &addr_tun);
    FATAL_ON(ret < 0, 1, "no link-local address found on %s", ctxt->tun.ifname);

    addr_interface_get_ll_address(&ctxt->net_if, addr_ws0, 0);

    cmp = memcmp(addr_ws0, addr_tun.s6_addr, 16);
    FATAL_ON(cmp, 1, "address mismatch: expected %s but found %s on %s",
             tr_ipv6(addr_ws0), tr_ipv6(addr_tun.s6_addr), ctxt->tun.ifname);
}

static void wsbr_network_init(struct wsbr_ctxt *ctxt)
{
    struct in6_addr gua;
    int ret;

    protocol_core_init();
    address_module_init();
    protocol_init(&ctxt->net_if, &ctxt->rcp, ctxt->config.lowpan_mtu);
    ws_bootstrap_init(ctxt->net_if.id);

    wsbr_configure_ws(ctxt);
    ret = tun_addr_get_uc_global(&ctxt->tun, &gua);
    FATAL_ON(ret < 0, 1, "no GUA found on %s", ctxt->tun.ifname);

    ws_bootstrap_up(&ctxt->net_if, gua.s6_addr);
    wsbr_check_link_local_addr(ctxt);
    if (IN6_IS_ADDR_UNSPECIFIED(&ctxt->config.dhcp_server.sin6_addr)) {
        dhcp_start(&ctxt->dhcp_server, ctxt->tun.ifname, ctxt->rcp.eui64.u8, gua.s6_addr);
    } else if (!IN6_IS_ADDR_LOOPBACK(&ctxt->config.dhcp_server.sin6_addr)) {
        ctxt->dhcp_relay.server_addr = ctxt->config.dhcp_server.sin6_addr;
        ctxt->dhcp_relay.link_addr = gua;
        dhcp_relay_start(&ctxt->dhcp_relay);
    }

    ctxt->net_if.rpl_root.compat = ctxt->config.rpl_compat;
    ctxt->net_if.rpl_root.rpi_ignorable = ctxt->config.rpl_rpi_ignorable;
    if (ctxt->config.ws_size == WS_NETWORK_SIZE_SMALL ||
        ctxt->config.ws_size == WS_NETWORK_SIZE_CERTIFICATION) {
        ctxt->net_if.rpl_root.dio_i_min       = 15; // min interval 32s
        ctxt->net_if.rpl_root.dio_i_doublings = 2;  // max interval 131s with default large Imin
    }
    rpl_glue_init(&ctxt->net_if);
    rpl_start(&ctxt->net_if.rpl_root, ctxt->tun.ifname, &gua);
}

static void wsbr_handle_reset(struct rcp *rcp)
{
    struct wsbr_ctxt *ctxt = container_of(rcp, struct wsbr_ctxt, rcp);

    if (ctxt->rcp.has_rf_list)
        FATAL(3, "unsupported RCP reset");
    INFO("Connected to RCP \"%s\" (%d.%d.%d), API %d.%d.%d", ctxt->rcp.version_label,
          FIELD_GET(0xFF000000, ctxt->rcp.version_fw),
          FIELD_GET(0x00FFFF00, ctxt->rcp.version_fw),
          FIELD_GET(0x000000FF, ctxt->rcp.version_fw),
          FIELD_GET(0xFF000000, ctxt->rcp.version_api),
          FIELD_GET(0x00FFFF00, ctxt->rcp.version_api),
          FIELD_GET(0x000000FF, ctxt->rcp.version_api));
    if (version_older_than(ctxt->rcp.version_api, 2, 0, 0))
        FATAL(3, "RCP API < 2.0.0 (too old)");
    if (version_older_than(rcp->version_api, 2, 11, 0) &&
        ctxt->config.duty_cycle.budget_ms)
        FATAL(3, "duty_cycle_budget requires RCP API >= 2.11.0");
    if (version_older_than(rcp->version_api, 2, 11, 0) &&
        ctxt->config.duty_cycle.chan_budget_ms)
        FATAL(3, "duty_cycle_chan_budget requires RCP API >= 2.11.0");
}

void kill_handler(int signal)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    if (ctxt->config.rcp_cfg.uart_dev[0])
        uart_tx_flush(&ctxt->rcp.bus);
    exit(0);
}

void sig_error_handler(int signal)
{
     __PRINT(91, "bug: %s", strsignal(signal));
    backtrace_show();
    raise(signal);
}

static void wsbr_recv_eapol_relay(struct auth_ctx *auth)
{
    struct in6_addr eapol_target;
    struct auth_supp_ctx *supp;
    struct eui64 supp_eui64;
    uint8_t buf[1500];
    ssize_t buf_len;
    uint8_t kmp_id;

    buf_len = eapol_relay_recv(auth->eapol_relay_fd, buf, sizeof(buf),
                               &eapol_target, &supp_eui64, &kmp_id);
    if (buf_len < 0)
        return;
    supp = auth_fetch_supp(auth, &supp_eui64);
    supp->eapol_target = eapol_target;
    auth_recv_eapol(auth, kmp_id, &supp_eui64, buf, buf_len);
}

static void wsbr_fds_init(struct wsbr_ctxt *ctxt)
{
    ctxt->fds[POLLFD_DBUS].fd = dbus_get_fd();
    ctxt->fds[POLLFD_DBUS].events = POLLIN;
    ctxt->fds[POLLFD_RCP].fd = ctxt->rcp.bus.fd;
    ctxt->fds[POLLFD_RCP].events = POLLIN;
    ctxt->fds[POLLFD_TUN].fd = ctxt->tun.fd;
    ctxt->fds[POLLFD_TUN].events = 0;
    ctxt->fds[POLLFD_TIMER].fd = timer_fd();
    ctxt->fds[POLLFD_TIMER].events = POLLIN;
    ctxt->fds[POLLFD_DHCP].fd = IN6_IS_ADDR_UNSPECIFIED(&ctxt->config.dhcp_server.sin6_addr) ?
                                ctxt->dhcp_server.fd : ctxt->dhcp_relay.fd;
    ctxt->fds[POLLFD_DHCP].events = POLLIN;
    ctxt->fds[POLLFD_RPL].fd = ctxt->net_if.rpl_root.sockfd;
    ctxt->fds[POLLFD_RPL].events = POLLIN;
    ctxt->fds[POLLFD_EAPOL_RELAY].fd = ctxt->auth.eapol_relay_fd;
    ctxt->fds[POLLFD_EAPOL_RELAY].events = POLLIN;
    ctxt->fds[POLLFD_RADIUS].fd = ctxt->auth.radius_fd;
    ctxt->fds[POLLFD_RADIUS].events = POLLIN;
}

static void wsbr_poll(struct wsbr_ctxt *ctxt)
{
    int ret;

    if (lowpan_adaptation_queue_size(ctxt->net_if.id) > 2)
        ctxt->fds[POLLFD_TUN].events = 0;
    else
        ctxt->fds[POLLFD_TUN].events = POLLIN;

    if (ctxt->rcp.bus.uart.data_ready)
        ret = poll(ctxt->fds, POLLFD_COUNT, 0);
    else
        ret = poll(ctxt->fds, POLLFD_COUNT, -1);
    FATAL_ON(ret < 0, 2, "poll: %m");

    if (ctxt->fds[POLLFD_DBUS].revents & POLLIN)
        dbus_process();
    if (ctxt->fds[POLLFD_DHCP].revents & POLLIN) {
        if (IN6_IS_ADDR_UNSPECIFIED(&ctxt->config.dhcp_server.sin6_addr))
            dhcp_recv(&ctxt->dhcp_server);
        else
            dhcp_relay_recv(&ctxt->dhcp_relay);
    }
    if (ctxt->fds[POLLFD_RPL].revents & POLLIN)
        rpl_recv(&ctxt->net_if.rpl_root);
    if (ctxt->fds[POLLFD_EAPOL_RELAY].revents & POLLIN)
        wsbr_recv_eapol_relay(&ctxt->auth);
    if (ctxt->fds[POLLFD_RADIUS].revents & POLLIN)
        ws_auth_recv_radius(&ctxt->net_if);
    if (ctxt->fds[POLLFD_TUN].revents & POLLIN)
        wsbr_tun_read(ctxt);
    if (ctxt->fds[POLLFD_RCP].revents & POLLIN ||
        ctxt->fds[POLLFD_RCP].revents & POLLERR ||
        ctxt->rcp.bus.uart.data_ready)
        rcp_rx(&ctxt->rcp);
    if (ctxt->fds[POLLFD_TIMER].revents & POLLIN)
        timer_process();
    if (ctxt->fds[POLLFD_PCAP].revents & POLLERR)
        wsbr_pcapng_closed(ctxt);
}

int wsbr_main(int argc, char *argv[])
{
    struct sigaction sigact = { };
    static const char *files[] = {
        "neighbor-*:*:*:*:*:*:*:*",
        "keys-*:*:*:*:*:*:*:*",
        "network-keys",
        "br-info",
        "supp-*",
        "rpl-*",
        NULL,
    };
    struct wsbr_ctxt *ctxt = &g_ctxt;

    INFO("Silicon Labs Wi-SUN border router %s", version_daemon_str);
    sigact.sa_flags = SA_RESETHAND;
    sigact.sa_handler = kill_handler;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigact.sa_handler = sig_error_handler;
    sigaction(SIGILL, &sigact, NULL);
    sigaction(SIGSEGV, &sigact, NULL);
    sigaction(SIGBUS, &sigact, NULL);
    sigaction(SIGFPE, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);
    sigact.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sigact, NULL); // Handle writing to unread FIFO for pcapng capture
    parse_commandline(&ctxt->config, argc, argv, print_help_br);
    if (ctxt->config.color_output != -1)
        g_enable_color_traces = ctxt->config.color_output;
    check_mbedtls_features();
    g_storage_prefix = ctxt->config.storage_prefix;
    if (ctxt->config.storage_delete) {
        INFO("deleting storage");
        storage_delete(files);
    }
    if (ctxt->config.storage_exit)
        exit(0);
    if (ctxt->config.pcap_file[0])
        wsbr_pcapng_init(ctxt);
    if (ctxt->config.capture[0])
        capture_start(ctxt->config.capture);

    rcp_init(&ctxt->rcp, &ctxt->config.rcp_cfg);
    if (ctxt->config.list_rf_configs) {
        rail_print_config_list(&ctxt->rcp);
        exit(0);
    }
    // NOTE: destination address filtering is enabled by default with the
    // native EUI-64.
    if (memcmp(ctxt->config.ws_mac_address, &EUI64_BC, 8))
        rcp_set_filter_dst64(&ctxt->rcp, ctxt->config.ws_mac_address);

    wsbr_tun_init(ctxt);
    ctxt->timer_legacy.period_ms = WS_TIMER_GLOBAL_PERIOD_MS;
    ctxt->timer_legacy.callback  = ws_timer_cb;
    timer_start_rel(NULL, &ctxt->timer_legacy, WS_TIMER_GLOBAL_PERIOD_MS);
    wsbr_network_init(ctxt);
    dbus_register("com.silabs.Wisun.BorderRouter",
                  "/com/silabs/Wisun/BorderRouter",
                  "com.silabs.Wisun.BorderRouter",
                  wsbrd_dbus_vtable, ctxt);
    if (ctxt->config.user[0] && ctxt->config.group[0]) {
        if (ctxt->config.neighbor_proxy[0])
            drop_privileges(ctxt->config.user, ctxt->config.group, (int[]){ CAP_NET_ADMIN }, 1);
        else
            drop_privileges(ctxt->config.user, ctxt->config.group, NULL, 0);
    }
    // FIXME: This call should be made in wsbr_configure_ws() but we cannot do
    // so because of privileges
    ws_pan_info_storage_write(ctxt->net_if.ws_info.fhss_config.bsi, ctxt->net_if.ws_info.pan_information.pan_id,
                              ctxt->net_if.ws_info.pan_information.pan_version,
                              ctxt->net_if.ws_info.pan_information.lfn_version, ctxt->net_if.ws_info.network_name);
    ctxt->auth.eapol_relay_fd = eapol_relay_start(ctxt->tun.ifname);
    auth_start(&ctxt->auth, &ctxt->rcp.eui64, ctxt->config.enable_lfn);
    /*
     * WARNING: do not move this function call before auth_start().
     * See comment in wsbr_on_gtk_change().
     */
    ws_bootstrap_6lbr_init(&ctxt->net_if);
    wsbr_fds_init(ctxt);

    INFO("Wi-SUN Border Router is ready");

    while (true)
        wsbr_poll(ctxt);
}
