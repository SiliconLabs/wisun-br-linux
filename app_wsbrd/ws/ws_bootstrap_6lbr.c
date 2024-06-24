/*
 * Copyright (c) 2021, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/rand.h"
#include "common/mathutils.h"
#include "common/ws_regdb.h"
#include "common/trickle_legacy.h"
#include "common/named_values.h"
#include "common/endian.h"
#include "common/events_scheduler.h"
#include "common/version.h"
#include "common/specs/ws.h"
#include "common/specs/ipv6.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ip.h"
#include "common/random_early_detection.h"
#include "common/ws_neigh.h"
#include "common/ws_ie.h"

#include "app/rcp_api_legacy.h"
#include "app/commandline_values.h"
#include "net/protocol.h"
#include "ipv6/ipv6_neigh_storage.h"
#include "ipv6/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"

#include "ws/ws_config.h"
#include "ws/ws_common.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_llc.h"
#include "ws/ws_pae_controller.h"
#include "ws/ws_eapol_pdu.h"
#include "ws/ws_eapol_auth_relay.h"
#include "ws/ws_eapol_relay.h"
#include "ws/ws_mngt.h"

#define EAPOL_RELAY_SOCKET_PORT               10253
#define BR_EAPOL_RELAY_SOCKET_PORT            10255
#define PAE_AUTH_SOCKET_PORT                  10254

static int8_t ws_bootstrap_6lbr_fhss_configure(struct net_if *cur)
{
    const struct ws_fhss_config *fhss = &cur->ws_info.fhss_config;
    uint8_t chan_mask_async[WS_CHAN_MASK_LEN];

    rcp_set_fhss_uc(cur->rcp,
                    fhss->uc_dwell_interval,
                    fhss->uc_chan_mask);
    rcp_set_fhss_ffn_bc(cur->rcp,
                        fhss->bc_interval,
                        fhss->bsi,
                        fhss->bc_dwell_interval,
                        fhss->bc_chan_mask,
                        0, 0, 0, NULL, NULL);
    // FIXME: Some parameters are shared with FFN broadcast
    rcp_set_fhss_lfn_bc(cur->rcp,
                        fhss->lfn_bc_interval,
                        fhss->bsi,
                        fhss->bc_chan_mask);

    BUG_ON(!fhss->chan_params);
    ws_chan_mask_calc_reg(chan_mask_async, fhss->chan_params, fhss->regional_regulation);
    rcp_set_fhss_async(cur->rcp, fhss->async_frag_duration_ms, chan_mask_async);

    return 0;
}

static int8_t ws_bootstrap_6lbr_backbone_ip_addr_get(struct net_if *interface_ptr, uint8_t *address)
{
    const uint8_t *addr;

    addr = addr_select_with_prefix(interface_ptr, NULL, 0, SOCKET_IPV6_PREFER_SRC_PUBLIC | SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT);
    if (!addr)
        return -1;

    memcpy(address, addr, 16);
    return 0;
}

static void ws_bootstrap_6lbr_eapol_congestion_init(struct net_if *cur)
{
    red_init(&cur->llc_random_early_detection);
    red_init(&cur->llc_eapol_random_early_detection);
    red_init(&cur->pae_random_early_detection);
}

static const char *tr_channel_mask(const uint8_t *chan_mask, int num_chans)
{
    int num_bytes = roundup(num_chans, 8) / 8;
    uint8_t tmp[WS_CHAN_MASK_LEN] = { };
    int i;

    bitcpy(tmp, chan_mask, num_chans);
    for (i = 0; i < num_bytes; i++)
        tmp[i] ^= 0xFF;
    return tr_bytes(tmp, num_bytes, NULL, 96, DELIM_COLON);
}

static const char *tr_excl_channel_mask(const uint8_t *chan_mask, int num_chans)
{
    int num_bytes = roundup(num_chans, 8) / 8;

    if (bitcmp0(chan_mask, num_chans))
        return "--";
    return tr_bytes(chan_mask, num_bytes, NULL, 96, DELIM_COLON);
}

static void ws_bootstrap_6lbr_print_config(struct net_if *cur)
{
    struct ws_phy_config *phy_config = &cur->ws_info.phy_config;
    const struct ws_fhss_config *fhss_config = &cur->ws_info.fhss_config;
    uint8_t chan_mask_excl[WS_CHAN_MASK_LEN];
    uint8_t chan_mask_reg[WS_CHAN_MASK_LEN];
    uint8_t chan_func;
    int fixed_channel;
    int length;

    BUG_ON(!phy_config->params);
    BUG_ON(!fhss_config->chan_params);
    if (fhss_config->chan_params->reg_domain == REG_DOMAIN_UNDEF)
        INFO("  domain: custom");
    else
        INFO("  domain: %s", val_to_str(fhss_config->chan_params->reg_domain, valid_ws_domains, "??"));

    if (fhss_config->chan_params->chan_plan_id && fhss_config->chan_params->chan_plan_id != 255)
        INFO("  channel plan id: %d", fhss_config->chan_params->chan_plan_id);
    else
        INFO("  class: 0x%x", fhss_config->chan_params->op_class);

    if (phy_config->params->phy_mode_id && phy_config->params->phy_mode_id != 255)
        INFO("  phy mode id: 0x%02x", phy_config->params->phy_mode_id);
    else
        INFO("  mode: 0x%x", phy_config->params->op_mode);

    if (!phy_config->phy_op_modes[0])
        INFO("  phy operating modes: disabled");
    else
        INFO("  phy operating modes: %s", tr_bytes(phy_config->phy_op_modes,
                                                   strlen((char *)phy_config->phy_op_modes),
                                                   NULL, 80, FMT_DEC | DELIM_COMMA | ELLIPSIS_ABRT));
    if (phy_config->rcp_rail_config_index < 0)
        INFO("  RCP configuration index: not supported");
    else
        INFO("  RCP configuration index: %d", phy_config->rcp_rail_config_index);


    INFO("  channel 0 frequency: %.1fMHz", fhss_config->chan_params->chan0_freq / 1000000.);
    INFO("  channel spacing: %dkHz", fhss_config->chan_params->chan_spacing / 1000);
    INFO("  channel count: %d", fhss_config->chan_params->chan_count);
    INFO("  channel masks:");

    length = -roundup(fhss_config->chan_params->chan_count, 8) / 8 * 3;
    INFO("               %*s %*s", length, "advertised", length, "effective");

    ws_chan_mask_calc_reg(chan_mask_reg, fhss_config->chan_params, fhss_config->regional_regulation);

    fixed_channel = ws_chan_mask_get_fixed(fhss_config->uc_chan_mask);
    chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    if (!chan_func) {
        BUG_ON(fixed_channel < 0);
        INFO("     unicast   %*s BIT(%d)", length, "--", fixed_channel);
    } else {
        ws_chan_mask_calc_excl(chan_mask_excl, chan_mask_reg, fhss_config->uc_chan_mask);
        INFO("     unicast   %*s %*s",
             length, tr_excl_channel_mask(chan_mask_excl, fhss_config->chan_params->chan_count),
             length, tr_channel_mask(fhss_config->uc_chan_mask, fhss_config->chan_params->chan_count));
    }

    fixed_channel = ws_chan_mask_get_fixed(fhss_config->bc_chan_mask);
    chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    if (!chan_func) {
        BUG_ON(fixed_channel < 0);
        INFO("     broadcast %*s BIT(%d)", length, "--", fixed_channel);
    } else {
        ws_chan_mask_calc_excl(chan_mask_excl, chan_mask_reg, fhss_config->bc_chan_mask);
        INFO("     broadcast %*s %*s",
             length, tr_excl_channel_mask(chan_mask_excl, fhss_config->chan_params->chan_count),
             length, tr_channel_mask(fhss_config->bc_chan_mask, fhss_config->chan_params->chan_count));
    }

    INFO("     async     %*s %*s", length, "--",
            length, tr_channel_mask(chan_mask_reg, fhss_config->chan_params->chan_count));
}

static void ws_bootstrap_6lbr_print_interop(struct net_if *cur)
{
    uint8_t chan_plan_id;
    char ffn10[7], lfn[7];
    int i;

    INFO("Nodes join ability:");
    INFO("  rank    FFN1.0    FFN1.1    LFN");

    chan_plan_id = cur->ws_info.fhss_config.chan_params->chan_plan_id;
    if (chan_plan_id && chan_plan_id != 255) {
        sprintf(ffn10, "no");
        sprintf(lfn, cur->ws_info.enable_lfn ? "yes" : "no");
    } else {
        sprintf(ffn10, cur->ws_info.enable_ffn10 ? "yes" : "no");
        sprintf(lfn, "no");
    }
    INFO("    1     %-6s    %-6s    %-6s", ffn10, "yes", lfn);

    i = 1;
    if (cur->ws_info.enable_ffn10)
        sprintf(ffn10, "can[%i]", i++);
    else
        sprintf(ffn10, "no");
    if (cur->ws_info.enable_lfn)
        sprintf(lfn, "can[%i]", i++);
    else
        sprintf(lfn, "no");
    INFO("   >1     %-6s    %-6s    %-6s", ffn10, "yes", lfn);

    i = 1;
    if (cur->ws_info.enable_ffn10) {
        INFO("  [%i]: neighboring routers must use a channel plan 0 (reg. domain & op. class)", i++);
        INFO("       or 1 (custom)");
    }
    if (cur->ws_info.enable_lfn) {
        INFO("  [%i]: neighboring routers must use a channel plan 2 (reg. domain & ChanPlanId)", i);
        if (cur->ws_info.enable_ffn10) {
            INFO("       FFN1.0 prevent propagation of LFN IEs, and compromise network security");
        }
    }
}

void ws_bootstrap_6lbr_init(struct net_if *cur)
{
    ws_llc_reset(cur);
    lowpan_adaptation_interface_reset(cur->id);
    //Clear Pending Key Index State
    cur->ws_info.ffn_gtk_index = 0;
    cur->ws_info.lfn_gtk_index = 0;

    ipv6_destination_cache_clean(cur->id);

    // All trickle timers stopped to allow entry from any state
    ws_mngt_async_trickle_stop(&cur->ws_info);
    //Init Packet congestion
    ws_bootstrap_packet_congestion_init(cur);

    ws_bootstrap_ip_stack_reset(cur);
    ws_pae_controller_auth_init(cur);

    cur->ws_info.pan_information.jm.plf = 0;
    cur->ws_info.pan_information.routing_cost = 0;

    ws_mngt_pan_version_increase(&cur->ws_info);

    // Set default parameters for FHSS when starting a discovery
    ws_bootstrap_6lbr_fhss_configure(cur);
    ws_bootstrap_set_domain_rf_config(cur);
    ws_bootstrap_fhss_activate(cur);

    ws_bootstrap_6lbr_print_config(cur);
    INFO("");
    ws_bootstrap_6lbr_print_interop(cur);
    INFO("");

    uint8_t ll_addr[16];
    addr_interface_get_ll_address(cur, ll_addr, 1);

    // Set EAPOL relay to port 10255 and authenticator relay to 10253 (and to own ll address)
    ws_eapol_relay_start(cur, BR_EAPOL_RELAY_SOCKET_PORT, ll_addr, EAPOL_RELAY_SOCKET_PORT);

    // Set authenticator relay to port 10253 and PAE to 10254 (and to own ll address)
    ws_eapol_auth_relay_start(cur, EAPOL_RELAY_SOCKET_PORT, ll_addr, PAE_AUTH_SOCKET_PORT);

    // Send network name to controller
    ws_pae_controller_network_name_set(cur, cur->ws_info.network_name);

    // Set backbone IP address get callback
    ws_pae_controller_auth_cb_register(cur, ws_bootstrap_6lbr_backbone_ip_addr_get);

    // Set PAE port to 10254 and authenticator relay to 10253 (and to own ll address)
    ws_pae_controller_authenticator_start(cur, PAE_AUTH_SOCKET_PORT, ll_addr, EAPOL_RELAY_SOCKET_PORT);

    // Initialize eapol congestion tracking
    ws_bootstrap_6lbr_eapol_congestion_init(cur);
    // Advertisements stopped during the RPL scan
    ws_mngt_async_trickle_stop(&cur->ws_info);
    // Activate RPL
    // Activate IPv6 stack
    ws_bootstrap_ip_stack_activate(cur);
    addr_add_router_groups(cur);
    // stopped all to make sure we can enter here from any state
    ws_mngt_async_trickle_stop(&cur->ws_info);

    ws_mngt_async_trickle_start(&cur->ws_info);
    ipv6_neigh_storage_load(&cur->ipv6_neighbour_cache);
    // Sending async frames to trigger trickle timers of devices in our range.
    // Doing so allows to get back to an operational network faster.
    ws_mngt_pa_send(&cur->ws_info);
    ws_mngt_pc_send(&cur->ws_info);
}
