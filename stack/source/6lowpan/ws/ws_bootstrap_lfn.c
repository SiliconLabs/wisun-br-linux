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
#include "common/rand.h"
#include "common/trickle.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "service_libs/utils/ns_time.h"
#include "service_libs/etx/etx.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/blacklist/blacklist.h"
#include "service_libs/random_early_detection/random_early_detection_api.h"
#include "common/events_scheduler.h"
#include "stack/net_interface.h"
#include "stack/ws_management_api.h"
#include "stack/net_rpl.h"
#include "stack/mac/platform/topo_trace.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/sw_mac.h"
#include "stack/mac/mac_api.h"

#include "nwk_interface/protocol.h"
#include "ipv6_stack/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "rpl/rpl_protocol.h"
#include "rpl/rpl_control.h"
#include "rpl/rpl_data.h"
#include "rpl/rpl_policy.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/ip.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/mac/mac_ie_lib.h"

#include "6lowpan/ws/ws_bbr_api_internal.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_eapol_auth_relay.h"
#include "6lowpan/ws/ws_eapol_pdu.h"
#include "6lowpan/ws/ws_eapol_relay.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_neighbor_class.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_stats.h"

#define TRACE_GROUP "wsbs"

void ws_bootstrap_lfn_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type)
{
    (void)ie_ext;
    // Store weakest heard packet RSSI
    if (cur->ws_info.weakest_received_rssi > data->signal_dbm) {
        cur->ws_info.weakest_received_rssi = data->signal_dbm;
    }

    if (data->SrcAddrMode != MAC_ADDR_MODE_64_BIT) {
        // Not from long address
        return;
    }
    ws_stats_update(cur, STATS_WS_ASYNCH_RX, 1);
    tr_warn("Wi-SUN LFN Mode received message id: %x", message_type);
}

void ws_bootstrap_lfn_asynch_confirm(struct net_if *interface, uint8_t asynch_message)
{
    (void)asynch_message;
    ws_stats_update(interface, STATS_WS_ASYNCH_TX, 1);
}

void ws_bootstrap_lfn_event_handler(struct net_if *cur, struct event_payload *event)
{
    (void)cur;
    ws_bootstrap_event_type_e event_type;
    event_type = (ws_bootstrap_event_type_e)event->event_type;

    switch (event_type) {
        case WS_INIT_EVENT:
            tr_debug("Tasklet init");
            break;
        /*       case WS_DISCOVERY_START:
                 case WS_CONFIGURATION_START:
                 case WS_OPERATION_START:
                 case WS_ROUTING_READY:
                 case WS_FAST_DISCONNECT:
                 case WS_NORMAL_DISCONNECT:
         */
        default:
            tr_error("Invalid event received");
            break;
    }
}

void ws_bootstrap_lfn_state_machine(struct net_if *cur)
{

    switch (cur->nwk_bootstrap_state) {
        case ER_WAIT_RESTART:
            tr_debug("WS SM:Wait for startup");
            break;
        case ER_ACTIVE_SCAN:
            tr_debug("WS SM:Active Scan");
            break;
        case ER_SCAN:
            tr_debug("WS SM:configuration Scan");
            break;
        case ER_PANA_AUTH:
            tr_info("authentication start");
            // Advertisements stopped during the EAPOL
            break;
        case ER_RPL_SCAN:
            tr_debug("WS SM:Wait RPL to contact DODAG root");
            break;
        case ER_BOOTSTRAP_DONE:
            tr_info("WS SM:Bootstrap Done");
            // Bootstrap_done event to application
            break;
        case ER_RPL_NETWORK_LEAVING:
            tr_debug("WS SM:RPL Leaving ready trigger discovery");
            break;
        default:
            tr_warn("WS SM:Invalid state %d", cur->nwk_bootstrap_state);
    }
}

void ws_bootstrap_lfn_seconds_timer(struct net_if *cur, uint32_t seconds)
{
    (void)cur;
    (void)seconds;
}
