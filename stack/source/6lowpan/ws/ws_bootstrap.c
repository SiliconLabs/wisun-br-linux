/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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
#include <inttypes.h>
#include "common/bits.h"
#include "common/log.h"
#include "common/rand.h"
#include "common/ws_regdb.h"
#include "common/trickle.h"
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/utils.h"
#include "common/version.h"
#include "common/events_scheduler.h"
#include "service_libs/etx/etx.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/blacklist/blacklist.h"
#include "service_libs/random_early_detection/random_early_detection.h"

#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/rcp_api.h"
#include "core/net_interface.h"
#include "core/timers.h"
#include "nwk_interface/protocol.h"
#include "ipv6_stack/ipv6_routing_table.h"
#include "mpl/mpl.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/ip.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/mac/mac_common_defines.h"

#include "6lowpan/ws/ws_bbr_api.h"
#include "6lowpan/ws/ws_bootstrap_6lbr.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_eapol_auth_relay.h"
#include "6lowpan/ws/ws_eapol_pdu.h"
#include "6lowpan/ws/ws_eapol_relay.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_llc.h"
#include "6lowpan/ws/ws_management_api.h"
#include "6lowpan/ws/ws_neighbor_class.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_stats.h"

#include "6lowpan/ws/ws_bootstrap.h"

#define TRACE_GROUP "wsbs"

static void ws_bootstrap_event_handler(struct event_payload *event);
static int8_t ws_bootstrap_event_trig(ws_bootstrap_event_type_e event_type, int8_t interface_id, enum event_priority priority, void *event_data);
static void ws_bootstrap_mac_security_enable(struct net_if *cur);
static void ws_bootstrap_nw_key_set(struct net_if *cur, uint8_t operation, uint8_t index, uint8_t *key);
static void ws_bootstrap_nw_key_clear(struct net_if *cur, uint8_t slot);
static void ws_bootstrap_nw_key_index_set(struct net_if *cur, uint8_t index);
static void ws_bootstrap_nw_frame_counter_set(struct net_if *cur, uint32_t counter, uint8_t slot);
static void ws_bootstrap_nw_frame_counter_read(struct net_if *cur, uint32_t *counter, uint8_t slot);
static void ws_bootstrap_nw_info_updated(struct net_if *interface_ptr, uint16_t pan_id, uint16_t pan_version, uint16_t lpan_version, char *network_name);
static bool ws_bootstrap_eapol_congestion_get(struct net_if *interface_ptr, uint16_t active_supp);
static void ws_bootstrap_pan_version_increment(struct net_if *cur);
static void ws_bootstrap_lpan_version_increment(struct net_if *cur);
static ws_nud_table_entry_t *ws_nud_entry_discover(struct net_if *cur, void *neighbor);
static void ws_nud_entry_remove(struct net_if *cur, mac_neighbor_table_entry_t *entry_ptr);
static bool ws_neighbor_entry_nud_notify(mac_neighbor_table_entry_t *entry_ptr, void *user_data);

static mac_neighbor_table_entry_t *ws_bootstrap_mac_neighbor_allocate(struct net_if *interface, const uint8_t *mac64, uint8_t role)
{
    mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_entry_allocate(interface->mac_parameters.mac_neighbor_table, mac64);

    if (!neighbor)
        return NULL;
    neighbor->node_role = role;
    neighbor->lifetime = ws_cfg_neighbour_temporary_lifetime_get(role);
    neighbor->link_lifetime = ws_cfg_neighbour_temporary_lifetime_get(role);
    rcp_set_neighbor(neighbor->index, mac_helper_panid_get(interface), neighbor->mac16, neighbor->mac64, 0);
    tr_debug("neighbor[%d] = %s, lifetime=%d (new)", neighbor->index, tr_eui64(neighbor->mac64), neighbor->lifetime);
    return neighbor;
}

static mac_neighbor_table_entry_t *ws_bootstrap_mac_neighbor_add(struct net_if *interface, const uint8_t *src64, uint8_t role)
{
    mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_address_discover(interface->mac_parameters.mac_neighbor_table, src64, MAC_ADDR_MODE_64_BIT);
    if (neighbor) {
        return neighbor;
    }

    return ws_bootstrap_mac_neighbor_allocate(interface, src64, role);
}

void ws_bootstrap_neighbor_set_stable(struct net_if *interface, const uint8_t *src64)
{
    mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_address_discover(interface->mac_parameters.mac_neighbor_table, src64, MAC_ADDR_MODE_64_BIT);

    if (neighbor && neighbor->link_lifetime != WS_NEIGHBOR_LINK_TIMEOUT) {
        neighbor->lifetime = WS_NEIGHBOR_LINK_TIMEOUT;
        neighbor->link_lifetime = WS_NEIGHBOR_LINK_TIMEOUT;
        tr_debug("neighbor[%d] = %s, lifetime=%d", neighbor->index, tr_eui64(neighbor->mac64), neighbor->lifetime);
    }
}

void ws_bootstrap_mac_neighbor_short_time_set(struct net_if *interface, const uint8_t *src64, uint32_t valid_time)
{
    mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_address_discover(interface->mac_parameters.mac_neighbor_table, src64, MAC_ADDR_MODE_64_BIT);

    if (neighbor && neighbor->link_lifetime <= valid_time) {
        //mlme_device_descriptor_t device_desc;
        neighbor->lifetime = valid_time;
        neighbor->link_lifetime = valid_time;
        tr_debug("neighbor[%d] = %s, lifetime=%d", neighbor->index, tr_eui64(neighbor->mac64), neighbor->lifetime);
    }
}

static void ws_bootstrap_neighbor_delete(struct net_if *interface, mac_neighbor_table_entry_t *neighbor)
{
    tr_debug("neighbor[%d] = %s, removed", neighbor->index, tr_eui64(neighbor->mac64));
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_drop_fhss_neighbor(neighbor->mac64);
    rcp_set_neighbor(neighbor->index, 0, 0, NULL, 0);
    etx_neighbor_remove(interface->id, neighbor->index, neighbor->mac64);
    ws_neighbor_class_entry_remove(&interface->ws_info.neighbor_storage, neighbor->index);
    if (!mac_neighbor_lfn_count(interface->mac_parameters.mac_neighbor_table))
        ws_timer_stop(WS_TIMER_LTS);
}

void ws_bootstrap_neighbor_list_clean(struct net_if *interface)
{

    mac_neighbor_table_neighbor_list_clean(interface->mac_parameters.mac_neighbor_table);
}

static void ws_bootstrap_address_notification_cb(struct net_if *interface, const struct if_address_entry *addr, if_address_callback_e reason)
{
    /* No need for LL address registration */
    if (addr->source == ADDR_SOURCE_UNKNOWN)
        return;

    if (reason == ADDR_CALLBACK_DAD_COMPLETE) {
        if (addr_ipv6_scope(addr->address, interface) > IPV6_SCOPE_LINK_LOCAL) {
            // at least ula address available inside mesh.
            interface->global_address_available = true;
        }
    } else if (reason == ADDR_CALLBACK_DELETED) {
        //Discover prefix policy
        addr_policy_remove_by_label(WS_NON_PREFFRED_LABEL);

        interface->global_address_available = false;
        ns_list_foreach(if_address_entry_t, addr_str, &interface->ip_addresses) {
            if (addr_ipv6_scope(addr_str->address, interface) > IPV6_SCOPE_LINK_LOCAL) {
                // at least ula address available inside mesh.
                interface->global_address_available = true;
                break;
            }
        }
    }

    // Addressing in Wi-SUN interface was changed for Border router send new event so Application can update the state
    if (interface->nwk_bootstrap_state == ER_BOOTSTRAP_DONE &&
        interface->bootstrap_state_machine_cnt == 0)
            interface->bootstrap_state_machine_cnt = 10; //Re trigger state check
}

static int ws_bootstrap_tasklet_init(struct net_if *cur)
{
    if (cur->bootStrapId < 0)
        cur->bootStrapId = event_handler_create(&ws_bootstrap_event_handler, WS_INIT_EVENT);

    if (cur->bootStrapId < 0) {
        tr_error("tasklet init failed");
        return -1;
    }


    return 0;
}

static int8_t ws_bootstrap_event_trig(ws_bootstrap_event_type_e event_type, int8_t interface_id, enum event_priority priority, void *event_data)
{
    struct event_payload event = {
        .receiver = interface_id,
        .sender = 0,
        .event_type = event_type,
        .priority = priority,
        .data_ptr = event_data,
    };
    return event_send(&event);
}

void ws_nud_table_reset(struct net_if *cur)
{
    //Empty active list
    ns_list_foreach_safe(ws_nud_table_entry_t, entry, &cur->ws_info.active_nud_process) {
        ns_list_remove(&cur->ws_info.active_nud_process, entry);
    }

    //Empty free list
    ns_list_foreach_safe(ws_nud_table_entry_t, entry, &cur->ws_info.free_nud_entries) {
        ns_list_remove(&cur->ws_info.free_nud_entries, entry);
    }
    //Add to free list to full
    for (int i = 0; i < ACTIVE_NUD_PROCESS_MAX; i++) {
        ns_list_add_to_end(&cur->ws_info.free_nud_entries, &cur->ws_info.nud_table_entrys[i]);
    }
}

static ws_nud_table_entry_t *ws_nud_entry_get_free(struct net_if *cur)
{
    ws_nud_table_entry_t *entry = ns_list_get_first(&cur->ws_info.free_nud_entries);
    if (entry) {
        entry->wait_response = false;
        entry->retry_count = 0;
        entry->nud_process = false;
        entry->timer = rand_get_random_in_range(1, 900);
        entry->neighbor_info = NULL;
        ns_list_remove(&cur->ws_info.free_nud_entries, entry);
        ns_list_add_to_end(&cur->ws_info.active_nud_process, entry);
    }
    return entry;
}

void ws_nud_entry_remove_active(struct net_if *cur, void *neighbor)
{
    ws_nud_table_entry_t *entry = ws_nud_entry_discover(cur, neighbor);

    if (entry) {
        mac_neighbor_table_entry_t *mac_neighbor = neighbor;
        ns_list_remove(&cur->ws_info.active_nud_process, entry);
        ns_list_add_to_end(&cur->ws_info.free_nud_entries, entry);
        if (mac_neighbor->nud_active) {
            mac_neighbor_table_neighbor_refresh(cur->mac_parameters.mac_neighbor_table, mac_neighbor, mac_neighbor->link_lifetime);
        }

        mac_neighbor_table_neighbor_connected(cur->mac_parameters.mac_neighbor_table, mac_neighbor);
    }
}

static ws_nud_table_entry_t *ws_nud_entry_discover(struct net_if *cur, void *neighbor)
{
    ns_list_foreach(ws_nud_table_entry_t, entry, &cur->ws_info.active_nud_process) {
        if (entry->neighbor_info == neighbor) {
            return entry;
        }
    }
    return NULL;
}

static void ws_nud_state_clean(struct net_if *cur, ws_nud_table_entry_t *entry)
{
    mac_neighbor_table_entry_t *neighbor = entry->neighbor_info;
    ns_list_remove(&cur->ws_info.active_nud_process, entry);
    ns_list_add_to_end(&cur->ws_info.free_nud_entries, entry);
    if (neighbor->nud_active) {
        neighbor->nud_active = false;
        cur->mac_parameters.mac_neighbor_table->active_nud_process--;
    }
}

static void ws_nud_entry_remove(struct net_if *cur, mac_neighbor_table_entry_t *entry_ptr)
{
    ws_nud_table_entry_t *nud_entry = ws_nud_entry_discover(cur, entry_ptr);
    if (nud_entry) {
        ws_nud_state_clean(cur, nud_entry);
    }
}

if_address_entry_t *ws_probe_aro_address(struct net_if *interface)
{
    if (interface->global_address_available) {
        ns_list_foreach(if_address_entry_t, address, &interface->ip_addresses) {
            if (addr_ipv6_scope(address->address, interface) > IPV6_SCOPE_LINK_LOCAL) {
                return address;
            }
        }
    }
    return NULL;
}

static bool ws_nud_message_build(struct net_if *cur, mac_neighbor_table_entry_t *neighbor, bool nud_process)
{
    //Send NS
    uint8_t ll_target[16];
    struct ipv6_nd_opt_earo aro_temp;
    //SET ARO and src address pointer to NULL by default
    struct ipv6_nd_opt_earo *aro_ptr = NULL;
    uint8_t *src_address_ptr = NULL;

    ws_common_create_ll_address(ll_target, neighbor->mac64);
    if (!nud_process) {
        if_address_entry_t *gp_address = ws_probe_aro_address(cur);
        if (gp_address) {
            src_address_ptr = gp_address->address;
            aro_temp.status = ARO_SUCCESS;
            aro_temp.present = true;
            memcpy(aro_temp.eui64, cur->mac, 8);
            //Just Short Test
            aro_temp.lifetime = 1;
            aro_ptr = &aro_temp;
        }
    }
    buffer_t *buffer = icmpv6_build_ns(cur, ll_target, src_address_ptr, true, false, aro_ptr);
    if (buffer) {
        buffer->options.traffic_class = IP_DSCP_CS6 << IP_TCLASS_DSCP_SHIFT;
        protocol_push(buffer);
        return true;
    }
    return false;
}

void ws_nud_active_timer(struct net_if *cur, uint16_t ticks)
{
    //Convert TICKS to real milliseconds
    if (ticks > 0xffff / 100) {
        ticks = 0xffff;
    } else if (ticks == 0) {
        ticks = 1;
    } else {
        ticks *= 100;
    }

    ns_list_foreach_safe(ws_nud_table_entry_t, entry, &cur->ws_info.active_nud_process) {
        if (entry->timer <= ticks) {
            //TX Process or timeout
            if (entry->wait_response) {
                //Timeout for NUD or Probe
                if (entry->nud_process) {
                    tr_debug("NUD NA timeout");
                    if (entry->retry_count < 2) {
                        entry->timer = rand_get_random_in_range(1, 900);
                        entry->wait_response = false;
                    } else {
                        //Clear entry from active list
                        ws_nud_state_clean(cur, entry);
                        //Remove whole entry
                        mac_neighbor_table_neighbor_remove(cur->mac_parameters.mac_neighbor_table, entry->neighbor_info);
                    }
                } else {
                    ws_nud_state_clean(cur, entry);
                }

            } else {
                //Random TX wait period is over
                entry->wait_response = ws_nud_message_build(cur, entry->neighbor_info, entry->nud_process);
                if (!entry->wait_response) {
                    if (entry->nud_process && entry->retry_count < 2) {
                        entry->timer = rand_get_random_in_range(1, 900);
                    } else {
                        //Clear entry from active list
                        //Remove and try again later on
                        ws_nud_state_clean(cur, entry);
                    }
                } else {
                    entry->retry_count++;
                    entry->timer = 5001;
                }
            }
        } else {
            entry->timer -= ticks;
        }
    }
}

void ws_bootstrap_llc_hopping_update(struct net_if *cur, const fhss_ws_configuration_t *fhss_configuration)
{
    cur->ws_info.hopping_schedule.uc_fixed_channel = fhss_configuration->unicast_fixed_channel;
    cur->ws_info.hopping_schedule.bc_fixed_channel = fhss_configuration->broadcast_fixed_channel;
    // Read UC channel function from WS info because FHSS might be temporarily configured to fixed channel during discovery.
    cur->ws_info.hopping_schedule.uc_channel_function = cur->ws_info.cfg->fhss.fhss_uc_channel_function;
    cur->ws_info.hopping_schedule.bc_channel_function = fhss_configuration->ws_bc_channel_function;
    cur->ws_info.hopping_schedule.fhss_bc_dwell_interval = fhss_configuration->fhss_bc_dwell_interval;
    cur->ws_info.hopping_schedule.fhss_broadcast_interval = fhss_configuration->fhss_broadcast_interval;
    cur->ws_info.hopping_schedule.fhss_uc_dwell_interval = fhss_configuration->fhss_uc_dwell_interval;
    cur->ws_info.hopping_schedule.fhss_bsi = fhss_configuration->bsi;
}

/**
 * @param chan_excl is filled with a list of excluded channels to be advertised
 *   in a schedule IE (US,BS,LCP)
 * @param chan_mask_custom is a user provided list of channels to use, ones not
 *   allowed by the regulation are ignored
 * @param chan_mask_reg is the list of active channels defined by the Wi-SUN
 *   PHY specification based on the configuration parameters (regulatory domain
 *   and class/ChanPlanId)
 */
static void ws_bootstrap_calc_chan_excl(ws_excluded_channel_data_t *chan_excl, const uint8_t chan_mask_custom[],
                                        const uint8_t chan_mask_reg[], uint16_t chan_count)
{
    bool in_range = false;
    int range_cnt = 0;

    memset(chan_excl, 0, sizeof(ws_excluded_channel_data_t));
    for (uint16_t i = 0; i < chan_count; i++) {
        if (!bittest(chan_mask_reg, i) || bittest(chan_mask_custom, i)) {
            if (in_range)
                in_range = false;
            continue;
        }

        bitset(chan_excl->channel_mask, i);
        chan_excl->excluded_channel_count++;

        if (!in_range) {
            in_range = true;
            range_cnt++;
            if (range_cnt < WS_EXCLUDED_MAX_RANGE_TO_SEND) {
                chan_excl->excluded_range[range_cnt - 1].range_start = i;
                chan_excl->excluded_range_length = range_cnt;
            }
        }
        if (range_cnt <= WS_EXCLUDED_MAX_RANGE_TO_SEND)
            chan_excl->excluded_range[range_cnt - 1].range_end = i;
    }
    chan_excl->channel_mask_bytes_inline = roundup(chan_count, 8) / 8;

    if (!range_cnt)
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_NONE;
    else if (range_cnt <= WS_EXCLUDED_MAX_RANGE_TO_SEND &&
             1 + range_cnt * 4 < chan_excl->channel_mask_bytes_inline)
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_RANGE;
    else
        chan_excl->excluded_channel_ctrl = WS_EXC_CHAN_CTRL_BITMASK;
}

void ws_bootstrap_fhss_configure_channel_masks(struct net_if *cur, fhss_ws_configuration_t *fhss_configuration)
{
    fhss_configuration->channel_mask_size = cur->ws_info.hopping_schedule.number_of_channels;
    ws_common_generate_channel_list(cur, fhss_configuration->domain_channel_mask, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.hopping_schedule.regulatory_domain, cur->ws_info.hopping_schedule.operating_class, cur->ws_info.hopping_schedule.channel_plan_id);
    ws_common_generate_channel_list(cur, fhss_configuration->unicast_channel_mask, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.hopping_schedule.regulatory_domain, cur->ws_info.hopping_schedule.operating_class, cur->ws_info.hopping_schedule.channel_plan_id);
    // using bitwise AND operation for user set channel mask to remove channels not allowed in this device
    bitand(fhss_configuration->unicast_channel_mask, cur->ws_info.cfg->fhss.fhss_channel_mask, 256);
    ws_bootstrap_calc_chan_excl(&cur->ws_info.hopping_schedule.uc_excluded_channels,
                                fhss_configuration->unicast_channel_mask,
                                fhss_configuration->domain_channel_mask,
                                cur->ws_info.hopping_schedule.number_of_channels);
    ws_common_generate_channel_list(cur, fhss_configuration->broadcast_channel_mask, cur->ws_info.hopping_schedule.number_of_channels, cur->ws_info.hopping_schedule.regulatory_domain, cur->ws_info.hopping_schedule.operating_class, cur->ws_info.hopping_schedule.channel_plan_id);
    bitand(fhss_configuration->broadcast_channel_mask, cur->ws_info.cfg->fhss.fhss_channel_mask, 256);
    ws_bootstrap_calc_chan_excl(&cur->ws_info.hopping_schedule.bc_excluded_channels,
                                fhss_configuration->broadcast_channel_mask,
                                fhss_configuration->domain_channel_mask,
                                cur->ws_info.hopping_schedule.number_of_channels);
}

static int8_t ws_bootstrap_fhss_initialize(struct net_if *cur)
{
    memset(&cur->ws_info.fhss_conf, 0, sizeof(fhss_ws_configuration_t));
    // When FHSS doesn't exist yet, create one
    ws_bootstrap_fhss_configure_channel_masks(cur, &cur->ws_info.fhss_conf);
    ws_bootstrap_fhss_set_defaults(cur, &cur->ws_info.fhss_conf);
    rcp_allocate_fhss(&cur->ws_info.fhss_conf);
    rcp_register_fhss();
    rcp_set_tx_allowance_level(WS_TX_AND_RX_SLOT, WS_TX_AND_RX_SLOT);
    return 0;
}

int8_t ws_bootstrap_fhss_set_defaults(struct net_if *cur, fhss_ws_configuration_t *fhss_configuration)
{
    fhss_configuration->fhss_uc_dwell_interval = cur->ws_info.cfg->fhss.fhss_uc_dwell_interval;
    fhss_configuration->ws_uc_channel_function = (fhss_ws_channel_functions_e)cur->ws_info.cfg->fhss.fhss_uc_channel_function;
    fhss_configuration->ws_bc_channel_function = (fhss_ws_channel_functions_e)cur->ws_info.cfg->fhss.fhss_bc_channel_function;
    fhss_configuration->fhss_bc_dwell_interval = cur->ws_info.cfg->fhss.fhss_bc_dwell_interval;
    fhss_configuration->fhss_broadcast_interval = cur->ws_info.cfg->fhss.fhss_bc_interval;
    fhss_configuration->lfn_bc_interval         = cur->ws_info.cfg->fhss.lfn_bc_interval;
    if (cur->ws_info.cfg->fhss.fhss_uc_fixed_channel != 0xffff) {
        fhss_configuration->unicast_fixed_channel = cur->ws_info.cfg->fhss.fhss_uc_fixed_channel;
    }
    fhss_configuration->broadcast_fixed_channel = cur->ws_info.cfg->fhss.fhss_bc_fixed_channel;
    return 0;
}

uint16_t ws_bootstrap_randomize_fixed_channel(uint16_t configured_fixed_channel, uint8_t number_of_channels, uint8_t *channel_mask)
{
    if (configured_fixed_channel == 0xFFFF) {
        uint16_t random_channel = rand_get_random_in_range(0, number_of_channels - 1);
        while (!bittest(channel_mask, random_channel))
            random_channel = rand_get_random_in_range(0, number_of_channels - 1);
        return random_channel;
    } else {
        return configured_fixed_channel;
    }
}

static int8_t ws_bootstrap_fhss_enable(struct net_if *cur)
{
    // Set the LLC information to follow the actual fhss settings
    ws_bootstrap_llc_hopping_update(cur, &cur->ws_info.fhss_conf);

    return 0;
}

static void ws_bootstrap_ll_address_validate(struct net_if *cur)
{
    BUG_ON(!cur->rcp);
    BUG_ON(memcmp(cur->rcp->eui64, ADDR_UNSPECIFIED, 8) == 0);
    memcpy(cur->mac, cur->rcp->eui64, 8);
    memcpy(cur->iid_eui64, cur->rcp->eui64, 8);
    memcpy(cur->iid_slaac, cur->rcp->eui64, 8);
    /* RFC4291 2.5.1: invert the "u" bit */
    cur->iid_eui64[0] ^= 2;
    cur->iid_slaac[0] ^= 2;
}

/* \return 0x0100 to 0xFFFF ETX value (8 bit fraction)
 * \return 0xFFFF address not associated
 * \return 0x0000 address unknown or other error
 * \return 0x0001 no ETX statistics on this interface
 */
uint16_t ws_local_etx_read(struct net_if *interface, addrtype_e addr_type, const uint8_t *mac_adddress)
{
    uint16_t etx;

    if (!mac_adddress || !interface) {
        return 0;
    }

    uint8_t attribute_index;

    mac_neighbor_table_entry_t *mac_neighbor = mac_neighbor_table_address_discover(interface->mac_parameters.mac_neighbor_table, mac_adddress, addr_type);
    if (!mac_neighbor) {
        return 0xffff;
    }
    attribute_index = mac_neighbor->index;
    ws_neighbor_class_entry_t *ws_neighbour = ws_neighbor_class_entry_get(&interface->ws_info.neighbor_storage, attribute_index);
    etx_storage_t *etx_entry = etx_storage_entry_get(interface->id, attribute_index);

    if (!ws_neighbour || !etx_entry) {
        return 0xffff;
    }

    etx = etx_local_etx_read(interface->id, attribute_index);

    // if we have a measurement ready then we will check the RSL validity
    if (etx != 0xffff && !ws_neighbour->candidate_parent) {
        // RSL value measured is lower than acceptable ETX will be given as MAX
        return WS_ETX_MAX << 1; // We use 8 bit fraction and ETX is usually 7 bit fraction
    }

    // If we dont have valid ETX for children we assume good ETX.
    // After enough packets is sent to children real calculated ETX is given.
    // This might result in ICMP source route errors returned to Border router causing secondary route uses
    if (etx == 0xffff && ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, mac_neighbor->mac64)) {
        return 0x100;
    }

    return etx;
}

uint16_t ws_etx_read(struct net_if *interface, addrtype_e addr_type, const uint8_t *addr_ptr)
{
    if (!addr_ptr || !interface) {
        return 0;
    }
    return ws_local_etx_read(interface, addr_type, addr_ptr + PAN_ID_LEN);
}

bool ws_bootstrap_nd_ns_transmit(struct net_if *cur, ipv6_neighbour_t *entry,  bool unicast, uint8_t seq)
{
    (void)cur;
    (void)seq;

    if (unicast) {
        // Unicast NS is OK
        return false;
    }
    // Fail the resolution
    tr_warn("Link address lost for %s", tr_ipv6(entry->ip_address));
    ipv6_neighbour_entry_remove(&cur->ipv6_neighbour_cache, entry);
    // True means we skip the message sending
    return true;
}

static int8_t ws_bootstrap_up(struct net_if *cur, const uint8_t *ipv6_address)
{
    int8_t ret_val = -1;

    if (!cur) {
        return -1;
    }

    if ((cur->configure_flags & INTERFACE_SETUP_MASK) != INTERFACE_SETUP_READY) {
        tr_error("Interface not yet fully configured");
        return -2;
    }
    if (ws_bootstrap_fhss_initialize(cur) != 0) {
        tr_error("fhss initialization failed");
        return -3;
    }
    ws_bbr_init(cur);

    ws_bootstrap_ll_address_validate(cur);

    addr_interface_set_ll64(cur, NULL);
    // Trigger discovery for bootstrap
    ret_val = nwk_6lowpan_up(cur);
    if (ret_val) {
        goto cleanup;
    }

    /* Wi-sun will trig event for stamechine this timer must be zero on init */
    cur->bootstrap_state_machine_cnt = 0;
    /* Disable SLLAO send/mandatory receive with the ARO */
    cur->ipv6_neighbour_cache.use_eui64_as_slla_in_aro = true;
    /* Omit sending of NA if ARO SUCCESS */
    cur->ipv6_neighbour_cache.omit_na_aro_success = true;
    /* Omit sending of NA and consider ACK to be success */
    cur->ipv6_neighbour_cache.omit_na = true;
    /* Disable NUD Probes */
    cur->ipv6_neighbour_cache.send_nud_probes = false;
    cur->ipv6_neighbour_cache.probe_avoided_routers = true;
    /*Replace NS handler to disable multicast address queries */
    cur->if_ns_transmit = ws_bootstrap_nd_ns_transmit;

    if(ipv6_address) {
        addr_add(cur, ipv6_address, 64, ADDR_SOURCE_STATIC, 0xffffffff, 0xffffffff);
        tr_debug("global unicast address of interface ws0 is %s", tr_ipv6(ipv6_address));
        memcpy(cur->ipv6_configure.static_prefix64, ipv6_address, 8);
    } else {
        WARN();
    }

    ws_nud_table_reset(cur);

    // Zero uptime counters
    cur->ws_info.uptime = 0;
    cur->ws_info.authentication_time = 0;
    cur->ws_info.connected_time = 0;

    blacklist_params_set(
        WS_BLACKLIST_ENTRY_LIFETIME,
        WS_BLACKLIST_TIMER_MAX_TIMEOUT,
        WS_BLACKLIST_TIMER_TIMEOUT,
        WS_BLACKLIST_ENTRY_MAX_NBR,
        WS_BLACKLIST_PURGE_NBR,
        WS_BLACKLIST_PURGE_TIMER_TIMEOUT);

    ws_bootstrap_event_discovery_start(cur);

    return 0;
cleanup:
    return ret_val;
}

static int8_t ws_bootstrap_down(struct net_if *cur)
{
    if (!cur || !(cur->lowpan_info & INTERFACE_NWK_ACTIVE)) {
        return -1;
    }

    tr_info("Wi-SUN ifdown");
    // Reset MAC for safe upper layer memory free
    rcp_reset_stack();
    rcp_unregister_fhss();
    rcp_release_fhss();
    // Reset WS information
    ws_bootstrap_asynch_trickle_stop(cur);
    ws_llc_reset(cur);
    ws_nud_table_reset(cur);
    ws_eapol_relay_delete(cur);
    ws_eapol_auth_relay_delete(cur);
    ws_pae_controller_stop(cur);
    blacklist_clear();
    cur->if_common_forwarding_out_cb = NULL;

    return nwk_6lowpan_down(cur);
}

void ws_bootstrap_configuration_reset(struct net_if *cur)
{
    // Configure IP stack to operate as Wi-SUN node

    cur->mac_parameters.mac_security_level = 0;

    // Set default parameters to interface
    cur->configure_flags = INTERFACE_BOOTSTRAP_DEFINED;
    cur->configure_flags |= INTERFACE_SECURITY_DEFINED;
    cur->lowpan_info = 0;
    cur->lowpan_info |= INTERFACE_NWK_ROUTER_DEVICE;

    cur->nwk_bootstrap_state = ER_ACTIVE_SCAN;
    cur->ws_info.network_pan_id = 0xffff;
    ws_bootstrap_asynch_trickle_stop(cur);

    //cur->mac_security_key_usage_update_cb = ws_management_mac_security_key_update_cb;
    return;
}

static void ws_bootstrap_neighbor_table_clean(struct net_if *interface)
{
    uint8_t ll_target[16];
    struct timespec current_time_stamp;

    if (interface->mac_parameters.mac_neighbor_table->neighbour_list_size <= interface->mac_parameters.mac_neighbor_table->list_total_size - ws_common_temporary_entry_size(interface->mac_parameters.mac_neighbor_table->list_total_size)) {
        // Enough neighbor entries
        return;
    }
    uint32_t temp_link_min_timeout;
    if (interface->mac_parameters.mac_neighbor_table->neighbour_list_size == interface->mac_parameters.mac_neighbor_table->list_total_size) {
        temp_link_min_timeout = 1; //Accept 1 second time from last
    } else {
        temp_link_min_timeout = interface->ws_info.cfg->timing.temp_link_min_timeout;
    }

    memcpy(ll_target, ADDR_LINK_LOCAL_PREFIX, 8);

    clock_gettime(CLOCK_MONOTONIC, &current_time_stamp);

    mac_neighbor_table_entry_t *neighbor_entry_ptr = NULL;
    ns_list_foreach_safe(mac_neighbor_table_entry_t, cur, &interface->mac_parameters.mac_neighbor_table->neighbour_list) {
        ws_neighbor_class_entry_t *ws_neighbor = ws_neighbor_class_entry_get(&interface->ws_info.neighbor_storage, cur->index);

        if (cur->link_role == PRIORITY_PARENT_NEIGHBOUR) {
            //This is our primary parent we cannot delete
            continue;
        }

        if (cur->nud_active) {
            //If NUD process is active do not trig
            // or Negative ARO is active
            continue;
        }

        if (neighbor_entry_ptr && neighbor_entry_ptr->lifetime < cur->lifetime) {
            // We have already shorter link entry found this cannot replace it
            continue;
        }

        if (cur->link_lifetime > WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME && cur->link_lifetime <= WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME) {
            //Do not permit to remove configured temp life time
            continue;
        }

        if (cur->trusted_device) {

            if (ipv6_neighbour_has_registered_by_eui64(&interface->ipv6_neighbour_cache, cur->mac64)) {
                // We have registered entry so we have been selected as parent
                continue;
            }

            memcpy(ll_target + 8, cur->mac64, 8);
            ll_target[8] ^= 2;
        }

        //Read current timestamp
        uint32_t time_from_last_unicast_schedule = current_time_stamp.tv_sec - ws_neighbor->host_rx_timestamp.tv_sec;
        if (time_from_last_unicast_schedule >= temp_link_min_timeout) {
            //Accept only Enough Old Device
            if (!neighbor_entry_ptr) {
                //Accept first compare
                neighbor_entry_ptr = cur;
            } else {
                uint32_t compare_neigh_time = current_time_stamp.tv_sec - ws_neighbor_class_entry_get(&interface->ws_info.neighbor_storage, neighbor_entry_ptr->index)->host_rx_timestamp.tv_sec;
                if (compare_neigh_time < time_from_last_unicast_schedule)  {
                    //Accept older RX timeout always
                    neighbor_entry_ptr = cur;
                }
            }
        }
    }
    if (neighbor_entry_ptr) {
        tr_info("dropped oldest neighbour %s", tr_eui64(neighbor_entry_ptr->mac64));
        mac_neighbor_table_neighbor_remove(interface->mac_parameters.mac_neighbor_table, neighbor_entry_ptr);
    }

}

bool ws_bootstrap_neighbor_get(struct net_if *net_if, const uint8_t eui64[8], struct llc_neighbour_req *neighbor)
{
    neighbor->ws_neighbor = NULL;
    neighbor->neighbor = mac_neighbor_table_address_discover(net_if->mac_parameters.mac_neighbor_table, eui64, ADDR_802_15_4_LONG);
    if (!neighbor->neighbor)
        return false;
    neighbor->ws_neighbor = ws_neighbor_class_entry_get(&net_if->ws_info.neighbor_storage, neighbor->neighbor->index);
    if (!neighbor->ws_neighbor)
        return false;
    return true;
}

bool ws_bootstrap_neighbor_add(struct net_if *net_if, const uint8_t eui64[8], struct llc_neighbour_req *neighbor, uint8_t role)
{
    ws_bootstrap_neighbor_table_clean(net_if);

    neighbor->ws_neighbor = NULL;
    neighbor->neighbor = ws_bootstrap_mac_neighbor_add(net_if, eui64, role);
    if (!neighbor->neighbor)
        return false;

    neighbor->ws_neighbor = ws_neighbor_class_entry_get(&net_if->ws_info.neighbor_storage, neighbor->neighbor->index);
    if (!neighbor->ws_neighbor) {
        mac_neighbor_table_neighbor_remove(net_if->mac_parameters.mac_neighbor_table, neighbor->neighbor);
        return false;
    }
    if (role == WS_NR_ROLE_LFN && !g_timers[WS_TIMER_LTS].timeout)
        ws_timer_start(WS_TIMER_LTS);
    ws_stats_update(net_if, STATS_WS_NEIGHBOUR_ADD, 1);
    return true;
}

static void ws_neighbor_entry_remove_notify(mac_neighbor_table_entry_t *entry_ptr, void *user_data)
{

    struct net_if *cur = user_data;
    lowpan_adaptation_neigh_remove_free_tx_tables(cur, entry_ptr);

    //TODO State machine check here

    if (ipv6_neighbour_has_registered_by_eui64(&cur->ipv6_neighbour_cache, entry_ptr->mac64)) {
        // Child entry deleted
        ws_stats_update(cur, STATS_WS_CHILD_REMOVE, 1);
    }

    protocol_6lowpan_release_short_link_address_from_neighcache(cur, entry_ptr->mac16);
    protocol_6lowpan_release_long_link_address_from_neighcache(cur, entry_ptr->mac64);

    //NUD Process Clear Here
    ws_nud_entry_remove(cur, entry_ptr);

    ws_bootstrap_neighbor_delete(cur, entry_ptr);
    ws_stats_update(cur, STATS_WS_NEIGHBOUR_REMOVE, 1);

}

static bool ws_neighbor_entry_nud_notify(mac_neighbor_table_entry_t *entry_ptr, void *user_data)
{
    uint32_t time_from_start = entry_ptr->link_lifetime - entry_ptr->lifetime;
    uint8_t ll_address[16];
    bool nud_proces = false;
    bool activate_nud = false;
    bool child;
    struct net_if *cur = user_data;

    ws_neighbor_class_entry_t *ws_neighbor = ws_neighbor_class_entry_get(&cur->ws_info.neighbor_storage, entry_ptr->index);
    etx_storage_t *etx_entry = etx_storage_entry_get(cur->id, entry_ptr->index);

    if (!entry_ptr->trusted_device || !ws_neighbor || !etx_entry || entry_ptr->link_lifetime <= WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME) {
        return false;
    }

    if (lowpan_adaptation_expedite_forward_state_get(cur)) {
        //Do not send any probe or NUD when Expedite forward state is enabled
        return false;
    }

    ws_common_create_ll_address(ll_address, entry_ptr->mac64);

    if (time_from_start > WS_NEIGHBOR_NUD_TIMEOUT) {

        child = ipv6_neighbour_has_registered_by_eui64(&cur->ipv6_neighbour_cache, entry_ptr->mac64);
        /* For parents ARO registration is sent in link timeout times
         * For candidate parents NUD is needed
         * For children NUD is sent only at very close to end
         */
        if (!child) {
            // No need for keep alive
            return false;
        }
        if (child && (time_from_start < WS_NEIGHBOR_NUD_TIMEOUT * 1.8)) {
            /* This is our child with valid ARO registration send NUD if we are close to delete
             *
             * if ARO was received link is considered active so this is only in case of very long ARO registration times
             *
             * 1.8 means with link timeout of 30 minutes that NUD is sent 6 minutes before timeout
             *
             */
            return false;
        }

        if (time_from_start > WS_NEIGHBOR_NUD_TIMEOUT * 1.5) {
            activate_nud = true;
        } else {
            uint16_t switch_prob = rand_get_random_in_range(0, WS_NUD_RANDOM_SAMPLE_LENGTH - 1);
            //Take Random from time WS_NEIGHBOR_NUD_TIMEOUT - WS_NEIGHBOR_NUD_TIMEOUT*1.5
            if (switch_prob < WS_NUD_RANDOM_COMPARE) {
                activate_nud = true;
            }
        }
        nud_proces = activate_nud;
    }

    if (!activate_nud) {
        return false;
    }

    ws_nud_table_entry_t *entry = ws_nud_entry_get_free(cur);
    if (!entry) {
        return false;
    }
    entry->neighbor_info = entry_ptr;

    entry->nud_process = nud_proces;

    return true;
}

int ws_bootstrap_init(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    ws_neighbor_class_t neigh_info;
    uint32_t neighbors_table_size;
    int ret_val = 0;

    if (!cur)
        return -1;

    neigh_info.neigh_info_list = NULL;
    neigh_info.list_size = 0;
    neighbors_table_size = cur->rcp->neighbors_table_size - MAX_NEIGH_TEMPORARY_EAPOL_SIZE;
    rcp_set_frame_counter_per_key(true);

    if (!etx_storage_list_allocate(cur->id, neighbors_table_size)) {
        return -1;
    }
    if (!etx_cached_etx_parameter_set(WS_ETX_MIN_WAIT_TIME, WS_ETX_MIN_SAMPLE_COUNT, WS_NEIGHBOR_FIRST_ETX_SAMPLE_MIN_COUNT)) {
        etx_storage_list_allocate(cur->id, 0);
        return -1;
    }

    if (!etx_allow_drop_for_poor_measurements(WS_ETX_BAD_INIT_LINK_LEVEL, WS_ETX_MAX_BAD_LINK_DROP)) {
        etx_storage_list_allocate(cur->id, 0);
        return -1;
    }

    etx_max_update_set(WS_ETX_MAX_UPDATE);
    etx_max_set(WS_ETX_MAX);

    if (blacklist_init() != 0) {
        tr_error("MLE blacklist init failed.");
        return -1;
    }

    if (!ws_neighbor_class_alloc(&neigh_info, neighbors_table_size)) {
        ret_val = -1;
        goto init_fail;
    }

    //Disable always by default
    lowpan_adaptation_interface_mpx_register(interface_id, NULL, 0);

    mac_neighbor_table_delete(cur->mac_parameters.mac_neighbor_table);
    cur->mac_parameters.mac_neighbor_table = mac_neighbor_table_create(neighbors_table_size,
                                                                       ws_neighbor_entry_remove_notify,
                                                                       ws_neighbor_entry_nud_notify, cur);
    if (!cur->mac_parameters.mac_neighbor_table) {
        ret_val = -1;
        goto init_fail;
    }

    ws_llc_create(cur, &ws_bootstrap_6lbr_mngt_ind, &ws_bootstrap_6lbr_asynch_confirm);

    mpx_api_t *mpx_api = ws_llc_mpx_api_get(cur);
    if (!mpx_api) {
        ret_val =  -4;
        goto init_fail;
    }

    if (ws_common_allocate_and_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    if (ws_cfg_settings_interface_set(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    if (ws_bootstrap_tasklet_init(cur) != 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Register MPXUser to adapatation layer
    if (lowpan_adaptation_interface_mpx_register(interface_id, mpx_api, MPX_LOWPAN_ENC_USER_ID) != 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Init PAE controller and set callback
    if (ws_pae_controller_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_pae_controller_cb_register(cur,
                                      ws_bootstrap_nw_key_set,
                                      ws_bootstrap_nw_key_clear,
                                      ws_bootstrap_nw_key_index_set,
                                      ws_bootstrap_nw_frame_counter_set,
                                      ws_bootstrap_nw_frame_counter_read,
                                      ws_bootstrap_pan_version_increment,
                                      ws_bootstrap_lpan_version_increment,
                                      ws_bootstrap_nw_info_updated,
                                      ws_bootstrap_eapol_congestion_get) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_pae_controller_configure(cur, &cur->ws_info.cfg->sec_timer, &cur->ws_info.cfg->sec_prot, &cur->ws_info.cfg->timing) < 0) {
        ret_val =  -4;
        goto init_fail;
    }

    //Init EAPOL PDU handler and register it to MPX
    if (ws_eapol_pdu_init(cur) < 0) {
        ret_val =  -4;
        goto init_fail;
    }
    if (ws_eapol_pdu_mpx_register(cur, mpx_api, MPX_KEY_MANAGEMENT_ENC_USER_ID != 0)) {
        ret_val =  -4;
        // add deallocs
        goto init_fail;
    }

    cur->ipv6_neighbour_cache.link_mtu = cur->max_link_mtu = WS_MPX_MAX_MTU;

    cur->if_up = ws_bootstrap_up;
    cur->if_down = ws_bootstrap_down;
    cur->ws_info.neighbor_storage = neigh_info;
    cur->etx_read_override = ws_etx_read;

    ws_bootstrap_configuration_reset(cur);
    addr_notification_register(ws_bootstrap_address_notification_cb);
    rcp_set_accept_unknown_secured_frames(true);

    // Specification is ruling out the compression mode, but we are now doing it.
    cur->mpl_seed = true;
    cur->mpl_seed_id_mode = MULTICAST_MPL_SEED_ID_IPV6_SRC_FOR_DOMAIN;

    cur->mpl_domain = mpl_domain_create(cur, ADDR_ALL_MPL_FORWARDERS, NULL, MULTICAST_MPL_SEED_ID_DEFAULT, 0, NULL);
    addr_add_group(cur, ADDR_REALM_LOCAL_ALL_NODES);
    addr_add_group(cur, ADDR_REALM_LOCAL_ALL_ROUTERS);

    return 0;

    //Error handling and free memory
init_fail:
    lowpan_adaptation_interface_mpx_register(interface_id, NULL, 0);
    ws_eapol_pdu_mpx_register(cur, NULL, 0);
    mac_neighbor_table_delete(cur->mac_parameters.mac_neighbor_table);
    etx_storage_list_allocate(cur->id, 0);
    ws_neighbor_class_dealloc(&neigh_info);
    ws_llc_delete(cur);
    ws_eapol_pdu_delete(cur);
    ws_pae_controller_delete(cur);
    return ret_val;
}

int ws_bootstrap_restart(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur)
        return -1;
    ws_bootstrap_event_discovery_start(cur);
    return 0;
}

int ws_bootstrap_restart_delayed(int8_t interface_id)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur)
        return -1;
    ws_bootstrap_state_change(cur, ER_WAIT_RESTART);
    cur->bootstrap_state_machine_cnt = 3;
    return 0;
}

static int ws_bootstrap_set_rf_config(struct net_if *cur, phy_rf_channel_configuration_t rf_configs)
{
    unsigned int ack_wait_symbols;

    ack_wait_symbols = WS_TACK_MAX_MS * (rf_configs.datarate / 1000);
    if (rf_configs.modulation == MODULATION_OFDM)
        ack_wait_symbols /= 4;
    ack_wait_symbols += WS_ACK_WAIT_SYMBOLS;
    rcp_set_802154_mode(IEEE_802_15_4G_2012);
    if (version_older_than(cur->rcp->version_api, 0, 25, 1))
        rcp_set_rf_config_legacy(&rf_configs);
    else
        rcp_set_rf_config(&rf_configs);
    rcp_set_ack_wait_duration(ack_wait_symbols);
    rcp_set_cca_threshold(cur->ws_info.hopping_schedule.number_of_channels, CCA_DEFAULT_DBM, CCA_HIGH_LIMIT, CCA_LOW_LIMIT);
    rcp_get_rx_sensitivity();
    return 0;
}

int ws_bootstrap_neighbor_remove(struct net_if *cur, const uint8_t *ll_address)
{
    mac_neighbor_table_entry_t *mac_neighbor = mac_neighbor_entry_get_by_ll64(cur->mac_parameters.mac_neighbor_table, ll_address, false, NULL);

    if (mac_neighbor) {
        mac_neighbor_table_neighbor_remove(cur->mac_parameters.mac_neighbor_table, mac_neighbor);
    }
    return 0;
}

int ws_bootstrap_aro_failure(struct net_if *cur, const uint8_t *ll_address)
{
    ws_bootstrap_neighbor_remove(cur, ll_address);
    return 0;
}

int ws_bootstrap_set_domain_rf_config(struct net_if *cur)
{
    const struct chan_params *chan_params;
    const struct phy_params *phy_params;
    ws_hopping_schedule_t *hopping_schedule = &cur->ws_info.hopping_schedule;
    phy_rf_channel_configuration_t rf_config = { };

    phy_params = ws_regdb_phy_params(hopping_schedule->phy_mode_id, hopping_schedule->operating_mode);
    chan_params = ws_regdb_chan_params(hopping_schedule->regulatory_domain, hopping_schedule->channel_plan_id,
                                       hopping_schedule->operating_class);

    rf_config.rcp_config_index = hopping_schedule->rcp_rail_config_index;
    if (hopping_schedule->phy_op_modes[0])
        rf_config.use_phy_op_modes = true;
    // We don't worry of the case where phy_params == NULL, the RCP will return
    // an error anyway.
    if (phy_params) {
        rf_config.datarate = phy_params->datarate;
        rf_config.modulation = phy_params->modulation;
        rf_config.modulation_index = phy_params->fsk_modulation_index;
        rf_config.fec = phy_params->fec;
        rf_config.ofdm_option = phy_params->ofdm_option;
        rf_config.ofdm_mcs = phy_params->ofdm_mcs;
    }

    if (!chan_params) {
        rf_config.channel_0_center_frequency = hopping_schedule->ch0_freq;
        rf_config.channel_spacing = ws_regdb_chan_spacing_value(hopping_schedule->channel_spacing);
        rf_config.number_of_channels = hopping_schedule->number_of_channels;
    } else {
        WARN_ON(!ws_regdb_check_phy_chan_compat(phy_params, chan_params),
                "non standard RF configuration in use");
        rf_config.channel_0_center_frequency = chan_params->chan0_freq;
        rf_config.channel_spacing = chan_params->chan_spacing;
        rf_config.number_of_channels = chan_params->chan_count;
    }

    hopping_schedule->phy_mode_id_ms_base = phy_params ? phy_params->phy_mode_id : 0;
    ws_bootstrap_set_rf_config(cur, rf_config);
    return 0;
}

static void ws_bootstrap_mac_activate(struct net_if *cur, uint16_t channel, uint16_t panid, bool coordinator)
{
    cur->mac_parameters.pan_id = panid;
    cur->mac_parameters.mac_channel = channel;
    rcp_start(channel, panid, coordinator);
}

void ws_bootstrap_fhss_activate(struct net_if *cur)
{
    ws_bootstrap_fhss_enable(cur);
    // Only supporting fixed channel

    cur->lowpan_info &=  ~INTERFACE_NWK_CONF_MAC_RX_OFF_IDLE;
    cur->mac_parameters.RxOnWhenIdle = true;
    rcp_set_rx_on_idle(true);
    ws_bootstrap_mac_security_enable(cur);
    ws_bootstrap_mac_activate(cur, cur->ws_info.cfg->fhss.fhss_uc_fixed_channel, cur->ws_info.network_pan_id, true);
    return;
}

void ws_bootstrap_ip_stack_reset(struct net_if *cur)
{
    // Delete all temporary cached information
    ipv6_neighbour_cache_flush(&cur->ipv6_neighbour_cache);
    lowpan_context_list_free(&cur->lowpan_contexts);
}

void ws_bootstrap_ip_stack_activate(struct net_if *cur)
{
    clear_power_state(ICMP_ACTIVE);
    cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ACTIVE;
    ws_bootstrap_ip_stack_reset(cur);
}

void ws_bootstrap_advertise_start(struct net_if *cur)
{
    cur->ws_info.mngt.trickle_pa_running = true;
    trickle_start(&cur->ws_info.mngt.trickle_pa, "ADV", &cur->ws_info.mngt.trickle_params);
    cur->ws_info.mngt.trickle_pc_running = true;
    trickle_start(&cur->ws_info.mngt.trickle_pc, "CFG", &cur->ws_info.mngt.trickle_params);
}

static void ws_bootstrap_pan_version_increment(struct net_if *cur)
{
    (void)cur;
    ws_bbr_pan_version_increase(cur);
}

static void ws_bootstrap_lpan_version_increment(struct net_if *cur)
{
    (void)cur;
    ws_bbr_lpan_version_increase(cur);
}

static void ws_bootstrap_mac_security_enable(struct net_if *cur)
{
    cur->mac_parameters.mac_key_id_mode = MAC_KEY_ID_MODE_IDX;
    cur->mac_parameters.mac_security_level = SEC_ENC_MIC64;
    cur->mac_parameters.SecurityEnabled = true;
    rcp_set_security(true);
}

static void ws_bootstrap_nw_key_set(struct net_if *cur, uint8_t slot, uint8_t index, uint8_t *key)
{
    // Firmware API < 0.15 crashes if slots > 3 are accessed
    if (!cur->ws_info.enable_lfn && slot > 3)
        return;
    mac_helper_security_key_to_descriptor_set(cur, key, index + 1, slot);
}

static void ws_bootstrap_nw_key_clear(struct net_if *cur, uint8_t slot)
{
    // Firmware API < 0.15 crashes if slots > 3 are accessed
    if (!cur->ws_info.enable_lfn && slot > 3)
        return;
    mac_helper_security_key_descriptor_clear(cur, slot);
}

static void ws_bootstrap_nw_key_index_set(struct net_if *cur, uint8_t index)
{
    if (cur->mac_parameters.mac_default_ffn_key_index != 0 &&
        cur->mac_parameters.mac_default_ffn_key_index != index + 1 &&
        index < 4) {
        /* Update the active key in the PAN Configs */
        tr_info("New Pending key Request %u", index);
        cur->ws_info.pending_key_index_info.state = PENDING_KEY_INDEX_ADVERTISMENT;
        cur->ws_info.pending_key_index_info.index = index;
        return;
    }
    if (cur->mac_parameters.mac_default_lfn_key_index != 0 &&
        cur->mac_parameters.mac_default_lfn_key_index != index + 1 &&
        index >= 4 && index < 7)
        // Notify LFNs that a new LGTK has been activated.
        ws_mngt_lpc_pae_cb(cur);

    /* Deprecated: Unused by the RCP. */
    if (index < 4)
        cur->mac_parameters.mac_default_ffn_key_index = index + 1;
    else if (index >= 4 && index < 7)
        cur->mac_parameters.mac_default_lfn_key_index = index + 1;
}

static void ws_bootstrap_nw_frame_counter_set(struct net_if *cur, uint32_t counter, uint8_t slot)
{
    rcp_set_frame_counter(slot, counter);
}

static void ws_bootstrap_nw_frame_counter_read(struct net_if *cur, uint32_t *counter, uint8_t slot)
{
    // Read frame counter
    mac_helper_key_link_frame_counter_read(cur->id, counter, slot);
}

static void ws_bootstrap_nw_info_updated(struct net_if *cur, uint16_t pan_id, uint16_t pan_version, uint16_t lpan_version, char *network_name)
{
    /* For border router, the PAE controller reads PAN ID, PAN version and network name from storage.
     * If they are set, takes them into use here.
     */
    // Get network name
    ws_gen_cfg_t gen_cfg;
    if (ws_cfg_gen_get(&gen_cfg) < 0) {
        return;
    }

    // If PAN ID has not been set, set it
    if (cur->ws_info.network_pan_id == 0xffff) {
        cur->ws_info.network_pan_id = pan_id;
        // Sets PAN version
        cur->ws_info.pan_information.pan_version = pan_version;
        cur->ws_info.pan_information.pan_version_set = true;
        cur->ws_info.pan_information.lpan_version = lpan_version;
        cur->ws_info.pan_information.lpan_version_set = true;
    }

    // If network name has not been set, set it
    if (strlen(gen_cfg.network_name) == 0) {
        strncpy(gen_cfg.network_name, network_name, 32);
    }

    // Stores the settings
    ws_cfg_gen_set(cur, &gen_cfg, 0);
}

static bool ws_bootstrap_eapol_congestion_get(struct net_if *cur, uint16_t active_supp)
{
    if (cur == NULL || cur->random_early_detection == NULL || cur->llc_random_early_detection == NULL || cur->llc_eapol_random_early_detection == NULL) {
        return false;
    }

    bool return_value = false;
    static struct red_info *red_info = NULL;
    uint16_t adaptation_average = 0;
    uint16_t llc_average = 0;
    uint16_t llc_eapol_average = 0;
    uint16_t average_sum = 0;
    uint8_t active_max = 0;
    uint32_t heap_size = UINT32_MAX;

    /*
      * For different memory sizes the max simultaneous authentications will be
      * 32k:    (32k / 50k) * 2 + 1 = 1
      * 65k:    (65k / 50k) * 2 + 1 = 3
      * 250k:   (250k / 50k) * 2 + 1 = 11
      * 1000k:  (1000k / 50k) * 2 + 1 = 41
      * 2000k:  (2000k / 50k) * 2 + 1 = 50 (upper limit)
      */
    active_max = (heap_size / 50000) * 2 + 1;
    if (active_max > 50) {
        active_max = 50;
    }

    // Read the values for adaptation and LLC queues
    adaptation_average = random_early_detection_aq_read(cur->random_early_detection);
    llc_average = random_early_detection_aq_read(cur->llc_random_early_detection);
    llc_eapol_average  = random_early_detection_aq_read(cur->llc_eapol_random_early_detection);
    // Calculate combined average
    average_sum = adaptation_average + llc_average + llc_eapol_average;

    // Maximum for active supplicants based on memory reached, fail
    if (active_supp >= active_max) {
        return_value = true;
        goto congestion_get_end;
    }

    // Always allow at least five negotiations (if memory does not limit)
    if (active_supp < 5) {
        goto congestion_get_end;
    }

    if (red_info == NULL) {
        red_info = random_early_detection_create(
                       cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_min,
                       cur->ws_info.cfg->sec_prot.max_simult_sec_neg_tx_queue_max,
                       100, RED_AVERAGE_WEIGHT_DISABLED);
    }
    if (red_info == NULL) {
        goto congestion_get_end;
    }

    // Check drop probability
    average_sum = random_early_detection_aq_calc(red_info, average_sum);
    return_value = random_early_detection_congestion_check(red_info);

congestion_get_end:
    tr_info("Active supplicant limit, active: %i max: %i summed averageQ: %i adapt averageQ: %i LLC averageQ: %i LLC EAPOL averageQ: %i drop: %s", active_supp, active_max, average_sum, adaptation_average, llc_average, llc_eapol_average, return_value ? "T" : "F");

    return return_value;
}

/*
 * Event transitions
 *
 * */
void ws_bootstrap_event_discovery_start(struct net_if *cur)
{
    ws_bootstrap_event_trig(WS_DISCOVERY_START, cur->bootStrapId, ARM_LIB_LOW_PRIORITY_EVENT, NULL);
}

void ws_bootstrap_event_operation_start(struct net_if *cur)
{
    ws_bootstrap_event_trig(WS_OPERATION_START, cur->bootStrapId, ARM_LIB_LOW_PRIORITY_EVENT, NULL);
}
void ws_bootstrap_event_routing_ready(struct net_if *cur)
{
    ws_bootstrap_event_trig(WS_ROUTING_READY, cur->bootStrapId, ARM_LIB_LOW_PRIORITY_EVENT, NULL);
}

void ws_bootstrap_configuration_trickle_reset(struct net_if *cur)
{
    trickle_inconsistent_heard(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params);
}

static void ws_bootstrap_pan_advert(struct net_if *cur)
{
    const struct ws_hopping_schedule *schedule = &cur->ws_info.hopping_schedule;
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PA,
        .wh_ies.utt     = true,
        .wp_ies.us      = true,
        .wp_ies.pan     = true,
        .wp_ies.netname = true,
        .wp_ies.pom     = schedule->phy_op_modes[0] && schedule->phy_op_modes[1],
        .wp_ies.jm      = cur->ws_info.pan_information.jm.mask,
    };
    uint8_t plf;

    // FIXME: we would like to compute these in ws_llc before including the
    // relevant IEs, but it is inconvenient since we are still supporting
    // FFNs for simulation.
    // Border routers write the NW size
    cur->ws_info.pan_information.pan_size = ws_bbr_pan_size(cur);
    if (cur->ws_info.pan_information.jm.mask & (1 << WS_JM_PLF)) {
        plf = ws_common_calc_plf(cur->ws_info.pan_information.pan_size,
                                    cur->ws_info.cfg->gen.network_size);
        if (plf != cur->ws_info.pan_information.jm.plf) {
            cur->ws_info.pan_information.jm.plf = plf;
            cur->ws_info.pan_information.jm.version++;
        }
    }
    cur->ws_info.pan_information.routing_cost = 0;

    ws_stats_update(cur, STATS_WS_ASYNCH_TX_PA, 1);
    ws_llc_asynch_request(cur, &req);
}

static void ws_bootstrap_pan_config(struct net_if *cur)
{
    struct ws_llc_mngt_req req = {
        .frame_type = WS_FT_PC,
        .wh_ies.utt      = true,
        .wh_ies.bt       = true,
        .wh_ies.lbc      = cur->ws_info.pan_information.lpan_version_set,
        .wp_ies.us       = true,
        .wp_ies.bs       = true,
        .wp_ies.panver   = true,
        .wp_ies.gtkhash  = true,
        .wp_ies.lgtkhash = cur->ws_info.pan_information.lpan_version_set,
        .wp_ies.lfnver   = cur->ws_info.pan_information.lpan_version_set,
        .security.SecurityLevel = cur->mac_parameters.mac_security_level,
        .security.KeyIdMode     = cur->mac_parameters.mac_key_id_mode,
    };

    if (cur->ws_info.pending_key_index_info.state == PENDING_KEY_INDEX_ADVERTISMENT) {
        req.security.KeyIndex =  cur->ws_info.pending_key_index_info.index + 1;
        cur->ws_info.pending_key_index_info.state = PENDING_KEY_INDEX_ACTIVATE;
    } else {
        req.security.KeyIndex = cur->mac_parameters.mac_default_ffn_key_index;
    }

    ws_stats_update(cur, STATS_WS_ASYNCH_TX_PC, 1);
    ws_llc_asynch_request(cur, &req);
}

static void ws_bootstrap_event_handler(struct event_payload *event)
{
    struct net_if *cur;
    cur = protocol_stack_interface_info_get_by_bootstrap_id(event->receiver);
    if (!cur) {
        return;
    }

    ws_bootstrap_6lbr_event_handler(cur, event);
}

/*
 * State machine
 *
 * */
bool ws_bootstrap_state_discovery(struct net_if *cur)
{
    if (cur->nwk_bootstrap_state == ER_ACTIVE_SCAN) {
        return true;
    }
    return false;
}

bool ws_bootstrap_state_configure(struct net_if *cur)
{
    // Think about the state value
    if (cur->nwk_bootstrap_state == ER_SCAN) {
        return true;
    }
    return false;
}

bool ws_bootstrap_state_wait_rpl(struct net_if *cur)
{
    // Think about the state value
    if (cur->nwk_bootstrap_state == ER_RPL_SCAN) {
        return true;
    }
    return false;
}

bool ws_bootstrap_state_active(struct net_if *cur)
{
    if (cur->nwk_bootstrap_state == ER_BOOTSTRAP_DONE) {
        return true;
    }
    return false;
}

void ws_bootstrap_state_change(struct net_if *cur, icmp_state_e nwk_bootstrap_state)
{
    cur->bootstrap_state_machine_cnt = 1;
    cur->nwk_bootstrap_state = nwk_bootstrap_state;
}

void ws_bootstrap_trickle_timer(struct net_if *cur, uint16_t ticks)
{
    if (cur->ws_info.mngt.trickle_pa_running &&
            trickle_timer(&cur->ws_info.mngt.trickle_pa, &cur->ws_info.mngt.trickle_params, ticks)) {
        // send PAN advertisement
        ws_bootstrap_pan_advert(cur);
    }
    if (cur->ws_info.mngt.trickle_pc_running) {
        if (trickle_timer(&cur->ws_info.mngt.trickle_pc, &cur->ws_info.mngt.trickle_params, ticks)) {
            // send PAN Configuration
            ws_bootstrap_pan_config(cur);
        }
    }
}

void ws_bootstrap_asynch_trickle_stop(struct net_if *cur)
{
    cur->ws_info.mngt.trickle_pa_running = false;
    cur->ws_info.mngt.trickle_pc_running = false;
}


void ws_bootstrap_seconds_timer(struct net_if *cur, uint32_t seconds)
{
    /*Update join state statistics*/
    if (ws_bootstrap_state_discovery(cur)) {
        ws_stats_update(cur, STATS_WS_STATE_1, 1);
    } else if (ws_bootstrap_state_configure(cur)) {
        ws_stats_update(cur, STATS_WS_STATE_3, 1);
    } else if (ws_bootstrap_state_wait_rpl(cur)) {
        ws_stats_update(cur, STATS_WS_STATE_4, 1);
    } else if (ws_bootstrap_state_active(cur)) {
        ws_stats_update(cur, STATS_WS_STATE_5, 1);
    }
    cur->ws_info.uptime++;

    ws_llc_timer_seconds(cur, seconds);
}

int ws_bootstrap_stack_info_get(struct net_if *cur, struct ws_stack_info *info_ptr)
{

    ws_neighbor_class_entry_t *ws_neighbour = NULL;

    memset(info_ptr, 0, sizeof(struct ws_stack_info));
    mac_neighbor_table_entry_t *mac_parent = mac_neighbor_entry_get_priority(cur->mac_parameters.mac_neighbor_table);

    if (mac_parent) {
        ws_neighbour = ws_neighbor_class_entry_get(&cur->ws_info.neighbor_storage, mac_parent->index);
        ws_common_create_ll_address(info_ptr->parent, mac_parent->mac64);
    }
    if (ws_neighbour) {
        info_ptr->rsl_in = ws_neighbor_class_rsl_in_get(ws_neighbour);
        info_ptr->rsl_out = ws_neighbor_class_rsl_out_get(ws_neighbour);
        info_ptr->routing_cost = ws_neighbour->routing_cost;
    }
    info_ptr->device_min_sens = DEVICE_MIN_SENS;
    if (ws_bootstrap_state_discovery(cur)) {
        info_ptr->join_state = 1;
    } else if (ws_bootstrap_state_configure(cur)) {
        info_ptr->join_state = 3;
    } else if (ws_bootstrap_state_wait_rpl(cur)) {
        info_ptr->join_state = 4;
    } else if (ws_bootstrap_state_active(cur)) {
        info_ptr->join_state = 5;
    }
    info_ptr->pan_id = cur->ws_info.network_pan_id;

    return 0;
}
int ws_bootstrap_neighbor_info_get(struct net_if *cur, ws_neighbour_info_t *neighbor_ptr, uint16_t table_max)
{
    uint8_t count = 0;
    if (!neighbor_ptr) {
        // Return the aount of neighbors.
        for (int n = 0; n < cur->mac_parameters.mac_neighbor_table->list_total_size; n++) {
            mac_neighbor_table_entry_t *mac_entry = mac_neighbor_table_attribute_discover(cur->mac_parameters.mac_neighbor_table, n);
            if (mac_entry && mac_entry->lifetime && mac_entry->lifetime != 0xffffffff) {
                count++;
            }
        }
        return count;
    }

    if (table_max > cur->mac_parameters.mac_neighbor_table->list_total_size) {
        table_max = cur->mac_parameters.mac_neighbor_table->list_total_size;
    }

    for (int n = 0; n < cur->mac_parameters.mac_neighbor_table->list_total_size; n++) {
        if (count > table_max) {
            break;
        }

        mac_neighbor_table_entry_t *mac_entry = mac_neighbor_table_attribute_discover(cur->mac_parameters.mac_neighbor_table, n);
        ws_neighbor_class_entry_t *ws_neighbor =  ws_neighbor_class_entry_get(&cur->ws_info.neighbor_storage, n);
        if (mac_entry && ws_neighbor && mac_entry->lifetime && mac_entry->lifetime != 0xffffffff) {
            // Active neighbor entry
            uint8_t ll_address[16];
            memset(neighbor_ptr + count, 0, sizeof(ws_neighbour_info_t));
            neighbor_ptr[count].lifetime = mac_entry->lifetime;

            neighbor_ptr[count].rsl_in = ws_neighbor_class_rsl_in_get(ws_neighbor);
            neighbor_ptr[count].rsl_out = ws_neighbor_class_rsl_out_get(ws_neighbor);

            // ETX is shown calculated as 8 bit integer, but more common way is to use 7 bit such that 128 means ETX:1.0
            neighbor_ptr[count].etx = ws_local_etx_read(cur, ADDR_802_15_4_LONG, mac_entry->mac64);
            if (neighbor_ptr[count].etx != 0xffff) {
                neighbor_ptr[count].etx = neighbor_ptr[count].etx >> 1;
            }
            ws_common_create_ll_address(ll_address, mac_entry->mac64);
            memcpy(neighbor_ptr[count].link_local_address, ll_address, 16);

            if (mac_entry->link_role == PRIORITY_PARENT_NEIGHBOUR) {
                neighbor_ptr[count].type = WS_PRIMARY_PARENT;
            }
            if (mac_entry->link_role == SECONDARY_PARENT_NEIGHBOUR) {
                neighbor_ptr[count].type = WS_SECONDARY_PARENT;
            }
            if (mac_entry->link_role == CHILD_NEIGHBOUR) {
                neighbor_ptr[count].type = WS_CHILD;
            }

            ipv6_neighbour_t *IPv6_neighbor = ipv6_neighbour_get_registered_by_eui64(&cur->ipv6_neighbour_cache, mac_entry->mac64);
            if (IPv6_neighbor) {
                //This is a child
                neighbor_ptr[count].type = WS_CHILD;
                memcpy(neighbor_ptr[count].global_address, IPv6_neighbor->ip_address, 16);
                // Child lifetimes are based on Registration times not a link time
                neighbor_ptr[count].lifetime = IPv6_neighbor->lifetime;
            }
            count++;
        }
    }

    // Go through list
    return count;
}

//Calculate max_packet queue size
static uint16_t ws_bootstrap_define_congestin_max_threshold(uint32_t heap_total_size, uint16_t packet_size, uint16_t packet_per_seconds, uint32_t max_delay, uint16_t min_packet_queue_size, uint16_t max_packet_queue_size)
{
    uint32_t max_packet_count = 0;
    if (heap_total_size) {
        //Claculate how many packet can be max queue to half of heap
        max_packet_count = (heap_total_size / 2) / packet_size;
    }

    //Calculate how many packet is possible to queue for guarantee given max delay
    uint32_t max_delayded_queue_size = max_delay * packet_per_seconds;

    if (max_packet_count > max_delayded_queue_size) {
        //Limit queue size by MAX delay
        max_packet_count = max_delayded_queue_size;
    }

    if (max_packet_count > max_packet_queue_size) {
        //Limit queue size by Max
        max_packet_count = max_packet_queue_size;
    } else if (max_packet_count < min_packet_queue_size) {
        //Limit queue size by Min
        max_packet_count = min_packet_queue_size;
    }
    return (uint16_t)max_packet_count;
}

static uint16_t ws_bootstrap_packet_per_seconds(struct net_if *cur, uint16_t packet_size)
{
    uint32_t data_rate = ws_common_datarate_get(cur);

    //calculate how many packet is possible send in paper
    data_rate /= 8 * packet_size;

    //Divide optimal  by / 5 because we split TX / RX slots and BC schedule
    //With Packet size 500 it should return
    //Return 15 for 300kBits
    //Return 7 for 150kBits
    //Return 2 for 50kBits
    return data_rate / 5;
}

void ws_bootstrap_packet_congestion_init(struct net_if *cur)
{
    random_early_detection_free(cur->random_early_detection);
    cur->random_early_detection = NULL;

    uint32_t heap_size = UINT32_MAX;

    uint16_t packet_per_seconds = ws_bootstrap_packet_per_seconds(cur, WS_CONGESTION_PACKET_SIZE);

    uint16_t min_th, max_th;

    max_th = ws_bootstrap_define_congestin_max_threshold(heap_size,
                                                         WS_CONGESTION_PACKET_SIZE,
                                                         packet_per_seconds,
                                                         WS_CONGESTION_QUEUE_DELAY,
                                                         WS_CONGESTION_BR_MIN_QUEUE_SIZE,
                                                         WS_CONGESTION_BR_MAX_QUEUE_SIZE);
    min_th = max_th / 2;
    tr_info("Wi-SUN packet congestion minTh %u, maxTh %u, drop probability %u weight %u, Packet/Seconds %u", min_th, max_th, WS_CONGESTION_RED_DROP_PROBABILITY, RED_AVERAGE_WEIGHT_EIGHTH, packet_per_seconds);
    cur->random_early_detection = random_early_detection_create(min_th, max_th, WS_CONGESTION_RED_DROP_PROBABILITY, RED_AVERAGE_WEIGHT_EIGHTH);

}
