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
#include "common/trickle.h"
#include "common/named_values.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/events_scheduler.h"
#include "common/version.h"
#include "common/specs/ws.h"
#include "common/specs/ipv6.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ip.h"

#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/random_early_detection/random_early_detection.h"
#include "6lowpan/ws/ws_management_api.h"

#include "app_wsbrd/rcp_api_legacy.h"
#include "app_wsbrd/commandline_values.h"
#include "nwk_interface/protocol.h"
#include "ipv6_stack/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"

#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_bbr_api.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_neighbor_class.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_stats.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_eapol_pdu.h"
#include "6lowpan/ws/ws_eapol_auth_relay.h"
#include "6lowpan/ws/ws_eapol_relay.h"
#include "6lowpan/ws/ws_mngt.h"

#define TRACE_GROUP "wsbs"

static int8_t ws_bootstrap_6lbr_fhss_configure(struct net_if *cur)
{
    //GET BSI from BBR module
    cur->ws_info.fhss_conf.bsi = ws_bbr_bsi_generate(cur);
    ws_bootstrap_fhss_configure_channel_masks(cur, &cur->ws_info.fhss_conf);
    // Randomize fixed channels. Only used if channel plan is fixed.
    cur->ws_info.cfg->fhss.fhss_uc_fixed_channel = ws_bootstrap_randomize_fixed_channel(cur->ws_info.cfg->fhss.fhss_uc_fixed_channel,
                                                                                         cur->ws_info.hopping_schedule.number_of_channels,
                                                                                         cur->ws_info.fhss_conf.domain_channel_mask);
    cur->ws_info.cfg->fhss.fhss_bc_fixed_channel = ws_bootstrap_randomize_fixed_channel(cur->ws_info.cfg->fhss.fhss_bc_fixed_channel,
                                                                                         cur->ws_info.hopping_schedule.number_of_channels,
                                                                                         cur->ws_info.fhss_conf.domain_channel_mask);
    ws_bootstrap_fhss_set_defaults(cur, &cur->ws_info.fhss_conf);
    rcp_legacy_set_fhss_timings(&cur->ws_info.fhss_conf);
    ws_bootstrap_llc_hopping_update(cur, &cur->ws_info.fhss_conf);

    return 0;
}

static int8_t ws_bootstrap_6lbr_backbone_ip_addr_get(struct net_if *interface_ptr, uint8_t *address)
{
    if (ws_bbr_backbone_address_get(interface_ptr, address)) {
        return 0;
    }

    return -1;
}

static void ws_bootstrap_6lbr_eapol_congestion_init(struct net_if *cur)
{
    random_early_detection_free(cur->llc_random_early_detection);
    cur->llc_random_early_detection = NULL;

    if (cur->llc_random_early_detection == NULL) {
        cur->llc_random_early_detection = random_early_detection_create(
                                              cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_min,
                                              cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_max,
                                              100, RED_AVERAGE_WEIGHT_EIGHTH);
    }

    random_early_detection_free(cur->llc_eapol_random_early_detection);
    cur->llc_eapol_random_early_detection = NULL;

    if (cur->llc_eapol_random_early_detection == NULL) {
        cur->llc_eapol_random_early_detection = random_early_detection_create(
                                                    cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_min,
                                                    cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_max,
                                                    100, RED_AVERAGE_WEIGHT_EIGHTH);
    }
}

int ws_bootstrap_6lbr_eapol_relay_get_socket_fd()
{
    return ws_eapol_relay_get_socket_fd();
}

int ws_bootstrap_6lbr_eapol_auth_relay_get_socket_fd()
{
    return ws_eapol_auth_relay_get_socket_fd();
}

void ws_bootstrap_6lbr_eapol_relay_socket_cb(int fd)
{
    ws_eapol_relay_socket_cb(fd);
}

void ws_bootstrap_6lbr_eapol_auth_relay_socket_cb(int fd)
{
    ws_eapol_auth_relay_socket_cb(fd);
}

void ws_bootstrap_6lbr_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ind_ie_list *ie_ext, uint8_t message_type)
{
    // Store weakest heard packet RSSI
    if (cur->ws_info.weakest_received_rssi > data->signal_dbm) {
        cur->ws_info.weakest_received_rssi = data->signal_dbm;
    }

    if (data->SrcAddrMode != MAC_ADDR_MODE_64_BIT) {
        // Not from long address
        return;
    }
    ws_stats_update(cur, STATS_WS_ASYNCH_RX, 1);

    //Handle Message's
    switch (message_type) {
        case WS_FT_PA:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PA, 1);
            ws_mngt_pa_analyze(cur, data, ie_ext);
            break;
        case WS_FT_PAS:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PAS, 1);
            ws_mngt_pas_analyze(cur, data, ie_ext);
            break;
        case WS_FT_PC:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PC, 1);
            ws_mngt_pc_analyze(cur, data, ie_ext);
            break;
        case WS_FT_PCS:
            ws_stats_update(cur, STATS_WS_ASYNCH_RX_PCS, 1);
            ws_mngt_pcs_analyze(cur, data, ie_ext);
            break;
        case WS_FT_LPAS:
            ws_mngt_lpas_analyze(cur, data, ie_ext);
            break;
        case WS_FT_LPCS:
            ws_mngt_lpcs_analyze(cur, data, ie_ext);
            break;
        case WS_FT_LPA:
        case WS_FT_LPC:
            tr_warn("LFN messages are not yet supported");
        default:
            // Unknown message do not process
            break;
    }
}

void ws_bootstrap_6lbr_asynch_confirm(struct net_if *interface, uint8_t asynch_message)
{
    if (asynch_message == WS_FT_PA)
        interface->pan_advert_running = false;
    else if (asynch_message == WS_FT_PC)
        interface->pan_config_running = false;
    ws_stats_update(interface, STATS_WS_ASYNCH_TX, 1);
    if (asynch_message == WS_FT_PC && interface->ws_info.pending_key_index_info.state == PENDING_KEY_INDEX_ACTIVATE) {
        interface->ws_info.pending_key_index_info.state = NO_PENDING_PROCESS;
        tr_info("Activate new default key %u", interface->ws_info.pending_key_index_info.index);
        /* Deprecated: Unused by the RCP. */
        interface->mac_parameters.mac_default_ffn_key_index = interface->ws_info.pending_key_index_info.index + 1;
    }
}

static const char *tr_channel_mask(const uint8_t *chan_mask, int num_chans)
{
    uint8_t tmp[32] = { };
    int num_bytes = roundup(num_chans, 8) / 8;
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
    ws_hopping_schedule_t *hopping_schedule = &cur->ws_info.hopping_schedule;
    const struct fhss_ws_configuration *fhss_configuration = &cur->ws_info.fhss_conf;
    uint8_t async_chan_mask[32];
    int length;

    if (hopping_schedule->regulatory_domain == REG_DOMAIN_UNDEF)
        INFO("  domain: custom");
    else
        INFO("  domain: %s", val_to_str(hopping_schedule->regulatory_domain, valid_ws_domains, "??"));

    if (hopping_schedule->channel_plan_id && hopping_schedule->channel_plan_id != 255)
        INFO("  channel plan id: %d", hopping_schedule->channel_plan_id);
    else
        INFO("  class: 0x%x", hopping_schedule->operating_class);

    if (hopping_schedule->phy_mode_id && hopping_schedule->phy_mode_id != 255)
        INFO("  phy mode id: 0x%02x", hopping_schedule->phy_mode_id);
    else
        INFO("  mode: 0x%x", hopping_schedule->operating_mode);

    if (!hopping_schedule->phy_op_modes[0])
        INFO("  phy operating modes: disabled");
    else
        INFO("  phy operating modes: %s", tr_bytes(hopping_schedule->phy_op_modes,
                                                   strlen((char *)hopping_schedule->phy_op_modes),
                                                   NULL, 80, FMT_DEC | DELIM_COMMA | ELLIPSIS_ABRT));
    if (hopping_schedule->rcp_rail_config_index < 0)
        INFO("  RCP configuration index: not supported");
    else
        INFO("  RCP configuration index: %d", hopping_schedule->rcp_rail_config_index);


    INFO("  channel 0 frequency: %.1fMHz", hopping_schedule->ch0_freq / 1000000.);
    INFO("  channel spacing: %dkHz", hopping_schedule->channel_spacing / 1000);
    INFO("  channel count: %d", hopping_schedule->number_of_channels);
    INFO("  channel masks:");

    length = -roundup(hopping_schedule->number_of_channels, 8) / 8 * 3;
    INFO("               %*s %*s", length, "advertised", length, "effective");

    if (!hopping_schedule->uc_channel_function)
        INFO("     unicast   %*s BIT(%d)", length, "--", hopping_schedule->uc_fixed_channel);
    else
        INFO("     unicast   %*s %*s",
             length, tr_excl_channel_mask(hopping_schedule->uc_excluded_channels.channel_mask, hopping_schedule->number_of_channels),
             length, tr_channel_mask(fhss_configuration->unicast_channel_mask, hopping_schedule->number_of_channels));

    if (!hopping_schedule->bc_channel_function)
        INFO("     broadcast %*s BIT(%d)", length, "--", hopping_schedule->bc_fixed_channel);
    else
        INFO("     broadcast %*s %*s",
             length, tr_excl_channel_mask(hopping_schedule->bc_excluded_channels.channel_mask, hopping_schedule->number_of_channels),
             length, tr_channel_mask(fhss_configuration->broadcast_channel_mask, hopping_schedule->number_of_channels));

    if (!hopping_schedule->uc_channel_function) {
        INFO("     async     %*s BIT(%d)", length, "--", hopping_schedule->uc_fixed_channel);
    } else {
        ws_common_generate_channel_list(cur, async_chan_mask,
                                        hopping_schedule->number_of_channels,
                                        hopping_schedule->regulatory_domain,
                                        hopping_schedule->operating_class,
                                        hopping_schedule->channel_plan_id);
        INFO("     async     %*s %*s", length, "--",
             length, tr_channel_mask(async_chan_mask, hopping_schedule->number_of_channels));
    }
}

static void ws_bootstrap_6lbr_print_interop(struct net_if *cur)
{
    uint8_t chan_plan_id;
    char ffn10[7], lfn[7];
    int i;

    INFO("Nodes join ability:");
    INFO("  rank    FFN1.0    FFN1.1    LFN");

    chan_plan_id = cur->ws_info.hopping_schedule.channel_plan_id;
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
    rcp_legacy_reset_stack();
    ws_llc_reset(cur);
    lowpan_adaptation_interface_reset(cur->id);
    //Clear Pending Key Index State
    cur->ws_info.pending_key_index_info.state = NO_PENDING_PROCESS;
    cur->mac_parameters.mac_default_ffn_key_index = 0;
    cur->mac_parameters.mac_default_lfn_key_index = 0;

    ipv6_destination_cache_clean(cur->id);

    // All trickle timers stopped to allow entry from any state
    ws_bootstrap_asynch_trickle_stop(cur);
    //Init Packet congestion
    ws_bootstrap_packet_congestion_init(cur);

    // Clear Old information from stack
    cur->ws_info.network_pan_id = 0xffff;
    cur->ws_info.pan_information.pan_version_set = false;
    ws_bootstrap_ip_stack_reset(cur);
    ws_pae_controller_auth_init(cur);

    uint16_t pan_id = ws_bbr_pan_id_get(cur);
    if (pan_id != 0xffff) {
        cur->ws_info.network_pan_id = pan_id;
    } else {
        if (cur->ws_info.network_pan_id == 0xffff) {
            cur->ws_info.network_pan_id = rand_get_random_in_range(0, 0xfffd);
        }
    }
    if (!cur->ws_info.pan_information.pan_version_set) {
        cur->ws_info.pan_information.pan_version = rand_get_random_in_range(0, 0xffff);
        cur->ws_info.pan_information.pan_version_set = true;
    }
    cur->ws_info.pan_information.pan_size = 0;
    cur->ws_info.pan_information.jm.plf = ws_common_calc_plf(0, cur->ws_info.cfg->gen.network_size);
    if (cur->ws_info.pan_information.jm.plf == UINT8_MAX)
        cur->ws_info.pan_information.jm.mask &= ~(1 << WS_JM_PLF);
    cur->ws_info.pan_information.routing_cost = 0;
    cur->ws_info.pan_information.rpl_routing_method = true;
    cur->ws_info.pan_information.use_parent_bs = true;
    // initialize for FAN 1.1 defaults
    if (cur->ws_info.enable_lfn &&
        !cur->ws_info.pan_information.lfn_version_set) {
        cur->ws_info.pan_information.lfn_version = rand_get_random_in_range(0, 0xffff);
        cur->ws_info.pan_information.lfn_version_set = true;
    }

    ws_bbr_pan_version_increase(cur);
    ws_bbr_lfn_version_increase(cur);

    // Set default parameters for FHSS when starting a discovery
    ws_common_regulatory_domain_config(cur, &cur->ws_info.hopping_schedule);
    ws_bootstrap_6lbr_fhss_configure(cur);
    ws_bootstrap_set_domain_rf_config(cur);
    ws_bootstrap_fhss_activate(cur);
    rcp_legacy_set_fhss_hop_count(0);

    ws_bootstrap_6lbr_print_config(cur);
    INFO("");
    ws_bootstrap_6lbr_print_interop(cur);
    INFO("");

    uint8_t ll_addr[16];
    addr_interface_get_ll_address(cur, ll_addr, 1);

    //SET EAPOL authenticator EUI64
    ws_pae_controller_border_router_addr_write(cur, cur->mac);

    // Set EAPOL relay to port 10255 and authenticator relay to 10253 (and to own ll address)
    ws_eapol_relay_start(cur, BR_EAPOL_RELAY_SOCKET_PORT, ll_addr, EAPOL_RELAY_SOCKET_PORT);

    // Set authenticator relay to port 10253 and PAE to 10254 (and to own ll address)
    ws_eapol_auth_relay_start(cur, EAPOL_RELAY_SOCKET_PORT, ll_addr, PAE_AUTH_SOCKET_PORT);

    // Set PAN ID and network name to controller
    ws_pae_controller_network_name_set(cur, cur->ws_info.cfg->gen.network_name);
    ws_pae_controller_pan_id_set(cur, cur->ws_info.network_pan_id);

    // Set backbone IP address get callback
    ws_pae_controller_auth_cb_register(cur, ws_bootstrap_6lbr_backbone_ip_addr_get);

    // Set PAE port to 10254 and authenticator relay to 10253 (and to own ll address)
    ws_pae_controller_authenticator_start(cur, PAE_AUTH_SOCKET_PORT, ll_addr, EAPOL_RELAY_SOCKET_PORT);

    // Initialize eapol congestion tracking
    ws_bootstrap_6lbr_eapol_congestion_init(cur);

    if (version_older_than(cur->rcp->version_api, 2, 0, 0)) {
        rcp_legacy_set_max_mac_retry(WS_MAX_FRAME_RETRIES);
        rcp_legacy_set_max_rf_retry(WS_CCA_REQUEST_RESTART_MAX,
                                    WS_TX_REQUEST_RESTART_MAX,
                                    WS_REQUEST_RESTART_BLACKLIST_MIN,
                                    WS_REQUEST_RESTART_BLACKLIST_MAX);
        rcp_legacy_set_max_csma_backoffs(WS_MAX_CSMA_BACKOFFS);
        rcp_legacy_set_min_be(WS_MAC_MIN_BE);
        rcp_legacy_set_max_be(WS_MAC_MAX_BE);
    }
    // Advertisements stopped during the RPL scan
    ws_bootstrap_asynch_trickle_stop(cur);
    // Activate RPL
    // Activate IPv6 stack
    ws_bootstrap_ip_stack_activate(cur);
    addr_add_router_groups(cur);
    // stopped all to make sure we can enter here from any state
    ws_bootstrap_asynch_trickle_stop(cur);

    ws_bootstrap_advertise_start(cur);
    ws_bootstrap_state_change(cur, ER_BOOTSTRAP_DONE);
}

void ws_bootstrap_6lbr_state_machine(struct net_if *cur)
{

    switch (cur->nwk_bootstrap_state) {
        case ER_BOOTSTRAP_DONE:
            tr_info("WS SM:Bootstrap Done");
            cur->lowpan_info &= ~INTERFACE_NWK_BOOTSTRAP_ACTIVE;
            cur->bootstrap_state_machine_cnt = 0;
            break;
        default:
            tr_warn("WS SM:Invalid state %d", cur->nwk_bootstrap_state);
    }
}
