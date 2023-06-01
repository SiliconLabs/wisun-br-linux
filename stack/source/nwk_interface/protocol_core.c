/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#include "common/bits.h"
#include "common/log_legacy.h"
#include "common/events_scheduler.h"
#include "common/endian.h"
#include "stack/mac/platform/arm_hal_phy.h"
#include "stack/mac/mac_api.h"
#include "stack/timers.h"

#include "app_wsbrd/rcp_api.h"
#include "app_wsbrd/wsbr_mac.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_llc.h"
#include "common_protocols/ipv6.h"
#include "common_protocols/icmpv6.h"
#include "legacy/ns_socket.h"
#include "mpl/mpl.h"
#include "rpl/rpl_control.h"

#include "nwk_interface/protocol_stats.h"

#include "nwk_interface/protocol.h"


#define TRACE_GROUP_CORE "core"

#define TRACE_GROUP "core"

#ifndef SEC_LIB_X_100MS_COUNTER
#define SEC_LIB_X_100MS_COUNTER 1 //Default scaller is 100ms tick
#endif

// RFC 4861 says we only have to reroll ReachableTime every couple of hours, but
// to make sure the code is regularly exercised, let's make it 10 minutes.
#define REACHABLE_TIME_UPDATE_SECONDS       600

/** Quick monotonic time for simple timestamp comparisons; 100ms ticks.
 * This can of course wrap, so to handle this correctly comparisons must be
 * expressed like:
 *
 * "if (time_now - time_then < 200)"
 * NOT
 * "if (time_now < time_then + 200)"
 */
static int8_t protocol_root_tasklet_ID = -1;

typedef struct lowpan_core_timer_structures {
    uint8_t core_timer_ticks;
    bool core_timer_event;
} lowpan_core_timer_structures_s;

protocol_interface_list_t NS_LIST_NAME_INIT(protocol_interface_info_list);

// maximum value of nwk_interface_id_e is 1
struct net_if protocol_interface_info;

/** Cores Power Save Varibale whic indicate States  */
volatile uint8_t power_save_state =  0;

static int8_t net_interface_get_free_id(void);

int8_t protocol_read_tasklet_id(void)
{
    return protocol_root_tasklet_ID;
}

uint8_t check_power_state(uint8_t mode)
{
    uint8_t ret_val = power_save_state & mode;
    return ret_val;
}


void set_power_state(uint8_t mode)
{
    power_save_state |= mode;
}

void clear_power_state(uint8_t mode)
{
    power_save_state &= ~mode;
}

void protocol_root_tasklet(struct event_payload *event)
{
    BUG_ON(event->event_type != ARM_IN_INTERFACE_BOOTSTRAP_CB);
    net_bootstrap_cb_run(event->event_id);
}

void nwk_bootstrap_timer(int ticks)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (!(cur->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    if (cur->bootstrap_state_machine_cnt && cur->bootstrap_state_machine_cnt-- == 1)
        net_bootstrap_cb_run(cur->id);
}

void icmp_fast_timer(int ticks)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    /* This gives us the RFC 4443 default (10 tokens/s, bucket size 10) */
    cur->icmp_tokens += ticks;
    if (cur->icmp_tokens > 10) {
        cur->icmp_tokens = 10;
    }
}

void update_reachable_time(int seconds)
{
    struct net_if *cur = protocol_stack_interface_info_get();

    if (cur->reachable_time_ttl > seconds) {
        cur->reachable_time_ttl -= seconds;
    } else {
        protocol_stack_interface_set_reachable_time(cur, cur->base_reachable_time);
    }
}

void protocol_core_init(void)
{
    protocol_root_tasklet_ID = event_handler_create(&protocol_root_tasklet, ARM_LIB_TASKLET_INIT_EVENT);

    ws_timer_start(WS_TIMER_MONOTONIC_TIME);
    ws_timer_start(WS_TIMER_MPL_SLOW);
    ws_timer_start(WS_TIMER_RPL_FAST);
    ws_timer_start(WS_TIMER_RPL_SLOW);
    ws_timer_start(WS_TIMER_PAE_FAST);
    ws_timer_start(WS_TIMER_PAE_SLOW);
    ws_timer_start(WS_TIMER_IPV6_DESTINATION);
    ws_timer_start(WS_TIMER_IPV6_ROUTE);
    ws_timer_start(WS_TIMER_IPV6_FRAG);
    ws_timer_start(WS_TIMER_CIPV6_FRAG);
    ws_timer_start(WS_TIMER_ICMP_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_MLD_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_MLD_SLOW);
    ws_timer_start(WS_TIMER_6LOWPAN_ADDR_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_ADDR_SLOW);
    ws_timer_start(WS_TIMER_6LOWPAN_ND);
    ws_timer_start(WS_TIMER_6LOWPAN_ETX);
    ws_timer_start(WS_TIMER_6LOWPAN_ADAPTATION);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR_SLOW);
    ws_timer_start(WS_TIMER_6LOWPAN_NEIGHBOR_FAST);
    ws_timer_start(WS_TIMER_6LOWPAN_CONTEXT);
    ws_timer_start(WS_TIMER_6LOWPAN_BOOTSTRAP);
    ws_timer_start(WS_TIMER_6LOWPAN_REACHABLE_TIME);
    ws_timer_start(WS_TIMER_WS_COMMON_FAST);
    ws_timer_start(WS_TIMER_WS_COMMON_SLOW);
}

void protocol_core_interface_info_reset(struct net_if *entry)
{
    if (entry) {
        entry->global_address_available = false;
        lowpan_context_list_free(&entry->lowpan_contexts);
        ipv6_neighbour_cache_flush(&entry->ipv6_neighbour_cache);
        entry->if_stack_buffer_handler = 0;
        entry->if_6lowpan_dad_process.active = false;
        //Clean
        ns_list_foreach_safe(if_address_entry_t, addr, &entry->ip_addresses) {
            addr_delete_entry(entry, addr);
        }
        /* This is done after address deletion, so RPL can act on them */
        rpl_control_remove_domain_from_interface(entry);
    }
}

void bootstrap_next_state_kick(icmp_state_e new_state, struct net_if *cur)
{
    cur->bootstrap_state_machine_cnt = 0;
    cur->nwk_bootstrap_state = new_state;
    struct event_payload event = {
        .receiver = protocol_root_tasklet_ID,
        .sender = 0,
        .event_id = (uint8_t)cur->id,
        .event_type = ARM_IN_INTERFACE_BOOTSTRAP_CB,
        .data_ptr = NULL,
        .priority = ARM_LIB_LOW_PRIORITY_EVENT,
    };
    if (event_send(&event) != 0) {
        tr_error("bootstrap_next_state_kick(): event send failed");
    }
}

uint32_t protocol_stack_interface_set_reachable_time(struct net_if *cur, uint32_t base_reachable_time)
{
    cur->base_reachable_time = base_reachable_time;
    cur->reachable_time_ttl = REACHABLE_TIME_UPDATE_SECONDS;

    return cur->ipv6_neighbour_cache.reachable_time = rand_randomise_base(base_reachable_time, 0x4000, 0xBFFF);
}


static void protocol_core_base_init(struct net_if *entry)
{
    entry->bootstrap_mode = ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_ROUTER;
    entry->bootStrapId = -1;
    entry->if_ns_transmit = NULL;
    entry->if_common_forwarding_out_cb = NULL;
    entry->if_special_forwarding = NULL;
    entry->if_snoop = NULL;
    entry->if_icmp_handler = NULL;
    entry->if_map_ip_to_link_addr = NULL;
    entry->if_map_link_addr_to_ip = NULL;
    entry->if_6lowpan_dad_process.active = false;
    entry->lowpan_desired_short_address = 0xfffe;
    entry->lowpan_info = 0;
    entry->rpl_domain = NULL;
    entry->if_down = NULL;
    entry->if_up = NULL;
}

static void protocol_core_base_finish_init(struct net_if *entry)
{
    entry->configure_flags = 0;
    entry->bootstrap_state_machine_cnt = 0;
    entry->global_address_available = false;
    entry->reallocate_short_address_if_duplicate = true;
    entry->dad_failures = 0;
    entry->icmp_tokens = 10;
    entry->ip_forwarding = true; /* Default to on for now... */
    entry->ip_multicast_forwarding = true; /* Default to on for now... */
    entry->recv_ra_routes = true;
    entry->recv_ra_prefixes = true;
    entry->send_mld = true;
    entry->mpl_seed = false;
    entry->mpl_control_trickle_params = rfc7731_default_control_message_trickle_params;
    entry->mpl_data_trickle_params = rfc7731_default_data_message_trickle_params;
    entry->mpl_seed_set_entry_lifetime = RFC7731_DEFAULT_SEED_SET_ENTRY_LIFETIME;
    entry->mpl_proactive_forwarding = true;
    entry->mpl_seed_id_mode = MULTICAST_MPL_SEED_ID_IPV6_SRC_FOR_DOMAIN;
    entry->cur_hop_limit = UNICAST_HOP_LIMIT_DEFAULT;
    protocol_stack_interface_set_reachable_time(entry, 30000);
    entry->dup_addr_detect_transmits = 1;
    entry->ipv6_neighbour_cache.link_mtu = IPV6_MIN_LINK_MTU;
    entry->max_link_mtu = IPV6_MIN_LINK_MTU;
    entry->pmtu_lifetime = 10 * 60; // RFC 1981 default - 10 minutes
    ns_list_link_init(entry, link);
    entry->if_stack_buffer_handler = NULL;
    entry->interface_name = 0;
    ns_list_init(&entry->lowpan_contexts);
    ns_list_init(&entry->ip_addresses);
    ns_list_init(&entry->ip_groups);
    ns_list_init(&entry->ipv6_neighbour_cache.list);
}

static struct net_if *protocol_interface_class_allocate()
{
    struct net_if *entry = &protocol_interface_info;
    int id = net_interface_get_free_id();

    memset(entry, 0, sizeof(struct net_if));
    /* We assume for now zone indexes for interface, link and realm all equal interface id */
    entry->id = id;
    entry->zone_index[IPV6_SCOPE_INTERFACE_LOCAL] = id;
    entry->zone_index[IPV6_SCOPE_LINK_LOCAL] = id;
    entry->zone_index[IPV6_SCOPE_REALM_LOCAL] = id;
    protocol_core_base_init(entry);
    return entry;
}

static struct net_if *protocol_core_interface_6lowpan_entry_get_with_mac(struct rcp *rcp, int mtu)
{
    struct net_if *entry = protocol_interface_class_allocate();
    if (!entry) {
        return NULL;
    }

    if (lowpan_adaptation_interface_init(entry->id) != 0) {
        goto interface_failure;
    }

    if (reassembly_interface_init(entry->id, 8, 5) != 0) {
        goto interface_failure;
    }

    memset(&entry->mac_parameters, 0, sizeof(arm_15_4_mac_parameters_t));
    entry->mac_parameters.pan_id = 0xffff;

    entry->mac_parameters.mac_default_ffn_key_index = 0;
    entry->mac_parameters.mtu = mtu;

    entry->rcp = rcp;

    mac_helper_set_default_key_source(entry);

    protocol_core_base_finish_init(entry);
    return entry;

interface_failure:
    lowpan_adaptation_interface_free(entry->id);
    reassembly_interface_free(entry->id);
    entry = NULL;
    return NULL;
}

void nwk_interface_print_neigh_cache()
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
        ipv6_neighbour_cache_print(&cur->ipv6_neighbour_cache);
    }
}

void nwk_interface_flush_neigh_cache(void)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
        ipv6_neighbour_cache_flush(&cur->ipv6_neighbour_cache);
    }
}

struct net_if *protocol_stack_interface_info_get()
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list)
        return cur;

    return NULL;
}

struct net_if *protocol_stack_interface_info_get_by_id(int8_t nwk_id)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list)
    if (cur->id == nwk_id) {
        return cur;
    }

    return NULL;
}

struct net_if *protocol_stack_interface_info_get_by_bootstrap_id(int8_t id)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list)
    if (cur->bootStrapId == id) {
        return cur;
    }

    return NULL;
}

struct net_if *protocol_stack_interface_info_get_by_rpl_domain(const struct rpl_domain *domain, int8_t last_id)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
        if (cur->id > last_id && cur->rpl_domain == domain) {
            return cur;
        }
    }

    return NULL;
}

struct net_if *protocol_stack_interface_info_get_wisun_mesh(void)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list)
        return cur;
    return NULL;
}

uint8_t nwk_bootstrap_ready(struct net_if *cur)
{
    int8_t ret_val = 0;
    if ((cur->lowpan_info & INTERFACE_NWK_BOOTSTRAP_ACTIVE) == 0) {
        if (cur->nwk_bootstrap_state == ER_BOOTSTRAP_DONE) {
            ret_val = 1;
        }
    }
    return ret_val;
}

static int8_t net_interface_get_free_id(void)
{
    uint_fast8_t id; // Must be unsigned for loop test to work...

    for (id = 1; id <= INT8_MAX; id++) {
        bool in_use = false;
        /* interface index == default zone index for link, interface and realm, so
         * ensure selected ID is not in use for any of those scopes */
        ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
            if (cur->id == (int8_t) id ||
                    cur->zone_index[IPV6_SCOPE_INTERFACE_LOCAL] == id ||
                    cur->zone_index[IPV6_SCOPE_LINK_LOCAL] == id ||
                    cur->zone_index[IPV6_SCOPE_REALM_LOCAL] == id) {
                in_use = true;
                break;
            }
        }
        if (!in_use) {
            return id;
        }
    }

    return -1;
}

struct net_if *protocol_stack_interface_generate_lowpan(struct rcp *rcp, int mtu)
{
    struct net_if *new_entry = protocol_core_interface_6lowpan_entry_get_with_mac(rcp, mtu);

    if (new_entry) {
        ipv6_neighbour_cache_init(&new_entry->ipv6_neighbour_cache, new_entry->id);
        memcpy(new_entry->iid_eui64, rcp->eui64, 8);
        memcpy(new_entry->iid_slaac, rcp->eui64, 8);
        /* RFC4291 2.5.1: invert the "u" bit */
        new_entry->iid_eui64[0] ^= 2;
        new_entry->iid_slaac[0] ^= 2;
        ns_list_add_to_start(&protocol_interface_info_list, new_entry);
        return new_entry;
    }
    return NULL;
}

/**
 * \brief Push Buffer to Protocol Core.
 *
 * \param buf pointer to buffer. NULL is accepted and ignored.
 */
void protocol_push(buffer_t *b)
{
    /* Ignore NULL */
    if (!b)
        return;

    // Call the actual handler
    struct net_if *cur = b->interface;
    if (cur && cur->if_stack_buffer_handler) {
        cur->if_stack_buffer_handler(b);
        return;
    }

    socket_tx_buffer_event_and_free(b, SOCKET_TX_FAIL);
}

void nwk_bootstrap_state_update(arm_nwk_interface_status_type_e posted_event, struct net_if *cur)
{
    //Clear Bootstrap Active Bit always
    cur->lowpan_info &= ~INTERFACE_NWK_BOOTSTRAP_ACTIVE;
    cur->bootstrap_state_machine_cnt = 0;

    if (posted_event == ARM_NWK_BOOTSTRAP_READY) {

        switch (cur->bootstrap_mode) {

            case ARM_NWK_BOOTSTRAP_MODE_6LoWPAN_BORDER_ROUTER:
                break;

            default:
                if (!cur->rpl_domain) {
                    tr_info("NON RPL Ready");
                    //nwk_protocol_poll_mode_disable(cur->nwk_id, 0);
                } else {
                    tr_info("RPL Ready");
                }
        }
    } else {
        if (cur->if_down) {
            cur->if_down(cur);
        } else {
            tr_debug("if_down() NULL");
        }
    }
}

void net_bootstrap_cb_run(uint8_t event)
{
    int8_t nwk_id = (int8_t) event;
    struct net_if *cur = protocol_stack_interface_info_get_by_id(nwk_id);

    if (cur) {
        //event_scheduler_set_active_tasklet(protocol_read_tasklet_id());
        ws_common_state_machine(cur);
    }
}

void protocol_core_dhcpv6_allocated_address_remove(struct net_if *cur, uint8_t *guaPrefix)
{
    //Delete Address & Routes
    ns_list_foreach(if_address_entry_t, e, &cur->ip_addresses) {
        if (e->source == ADDR_SOURCE_DHCP && (e->prefix_len == 64) && !bitcmp(e->address, guaPrefix, 64)) {
            ns_list_remove(&cur->ip_addresses, e);
            free(e);
            tr_debug("Delete DHCPv6 Allocated Address");
            break;
        }
    }
}

/* XXX note that this does not perform any scope checks, so will for example match
 * link local addresses on any interface - you may want addr_interface_address_compare */
int8_t protocol_interface_address_compare(const uint8_t *addr)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {
        if (addr_is_assigned_to_interface(cur, addr)) {
            return 0;
        }
    }

    return -1;
}

bool protocol_address_prefix_cmp(struct net_if *cur, const uint8_t *prefix, uint8_t prefix_len)
{
    ns_list_foreach(if_address_entry_t, adr, &cur->ip_addresses) {
        if (!bitcmp(adr->address, prefix, prefix_len)) {
            /* Prefix  stil used at list so stop checking */
            return true;
        }
    }
    return false;
}

bool protocol_interface_any_address_match(const uint8_t *prefix, uint8_t prefix_len)
{
    ns_list_foreach(struct net_if, cur, &protocol_interface_info_list) {

        if (protocol_address_prefix_cmp(cur, prefix, prefix_len)) {
            return true;
        }
    }

    return false;
}


