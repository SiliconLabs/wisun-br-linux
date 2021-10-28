/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "nsconfig.h"

#include <string.h>
#include <ns_list.h>
#include <nsdynmemLIB.h>
#include <net_thread_test.h>
#include "randLIB.h"

#include "ns_trace.h"
#include "common_functions.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_abstract.h"
#include "6lowpan/thread/thread_config.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_routing.h"
#include "6lowpan/thread/thread_joiner_application.h"
#include "6lowpan/thread/thread_leader_service.h"
#include "6lowpan/thread/thread_management_internal.h"
#include "6lowpan/thread/thread_bootstrap.h"
#include "6lowpan/thread/thread_router_bootstrap.h"
#include "6lowpan/thread/thread_discovery.h"
#include "6lowpan/thread/thread_nvm_store.h"
#include "6lowpan/thread/thread_neighbor_class.h"
#include "6lowpan/thread/thread_bbr_commercial.h"
#include "6lowpan/thread/thread_ccm.h"
#include "mle/mle.h"
#include "thread_meshcop_lib.h"
#include "thread_diagcop_lib.h"
#include "coap_service_api.h"
#include "service_libs/mle_service/mle_service_api.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "6lowpan/mac/mac_helper.h"

#define TRACE_GROUP "tapi"


int_fast8_t arm_nwk_6lowpan_thread_test_add_neighbour(
    int8_t interface_id,
    uint16_t neighbour_short_addr,
    uint_fast8_t link_margin_db,
    uint8_t id_sequence,
    const uint8_t *id_mask,
    const uint8_t *route_data)
{
#ifdef HAVE_THREAD_ROUTER
    protocol_interface_info_entry_t *cur;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        tr_warn("Invalid interface id");
        return -1;
    }

    return thread_routing_add_link(cur, neighbour_short_addr, link_margin_db, id_sequence, id_mask, route_data, true);
#else
    (void)interface_id;
    (void)neighbour_short_addr;
    (void)link_margin_db;
    (void)id_sequence;
    (void)id_mask;
    (void)route_data;
    return -1;
#endif
}

int_fast8_t arm_nwk_6lowpan_thread_test_remove_neighbour(
    int8_t interface_id,
    uint16_t neighbour_short_addr)
{
#ifdef HAVE_THREAD_ROUTER
    protocol_interface_info_entry_t *cur;
    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur) {
        tr_warn("Invalid interface id");
        return -1;
    }

    return thread_routing_remove_link(cur, neighbour_short_addr);
#else
    (void)interface_id;
    (void)neighbour_short_addr;
    return -1;
#endif

}

void arm_nwk_6lowpan_thread_test_print_routing_database(int8_t interface_id)
{
    (void)interface_id;
}

int8_t thread_routing_set_network_id_timeout(int8_t interface_id, uint16_t network_id_timeout)
{
    (void)interface_id;
    (void)network_id_timeout;
    return -1;
}

int8_t thread_routing_get_network_id_timeout(int8_t interface_id, uint16_t *network_id_timeout)
{
    (void)interface_id;
    (void)network_id_timeout;
    return -1;
}

int thread_test_set_context_id_reuse_timeout(
    int8_t interface_id,
    uint32_t timeout)
{
    (void)interface_id;
    (void)timeout;
    return -1;
}

int thread_test_remove_router_by_id(int8_t interface_id, uint8_t routerId)
{
    (void)interface_id;
    (void)routerId;
    return -1;
}

int thread_test_router_downgrade(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_test_print_network_data(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}


int8_t thread_reed_set_advertisement_interval(int8_t interface_id, uint16_t advertisement_interval, uint16_t jitter_interval)
{
    (void)interface_id;
    (void)advertisement_interval;
    (void)jitter_interval;
    return -1;
}

int thread_test_key_sequence_counter_update(int8_t interface_id, uint32_t thrKeySequenceCounter)
{
    (void)interface_id;
    (void)thrKeySequenceCounter;
    return -1;
}

int thread_test_stack_cache_reset(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_test_key_rotation_update(int8_t interface_id, uint32_t thrKeyRotation)
{
    (void)interface_id;
    (void)thrKeyRotation;
    return -1;
}

int thread_test_router_select_threshold_values_set(
    int8_t interface_id,
    uint8_t upgradeThreshold,
    uint8_t downgradeThreshold)
{
    (void)interface_id;
    (void)upgradeThreshold;
    (void)downgradeThreshold;
    return -1;
}
int thread_test_max_accepted_router_id_limit_set(
    int8_t interface_id,
    uint8_t maxRouterLimit)
{
    (void)interface_id;
    (void)maxRouterLimit;
    return -1;
}


/**
 * Set Thread Security Master Key and Key Index
 *
 * \param interface_id Network Interface
 * \param enableSecurity Boolean for enable security or disable
 * \param threadMasterKey Thread Master Key material which will be used for generating new key
 * \param threadMasterKeyIndex Thread key material key index which will be increment periodically
 * \param keyRollPeriod Define Key index & key update process
 *
 * return 0, ADD OK
 * return <0 Add Not OK
 */
int thread_test_security_material_set(int8_t interface_id, bool enableSecurity, uint8_t *thrMasterKey, uint32_t thrKeySequenceCounter, uint32_t thrKeyRotation)
{
    (void)interface_id;
    (void)enableSecurity;
    (void)thrMasterKey;
    (void)thrKeySequenceCounter;
    (void)thrKeyRotation;
    return -1;
}

int thread_test_version_set(int8_t interface_id, uint8_t version)
{
    (void)version;
    (void)interface_id;
    return -1;
}

int thread_test_pbbr_response_override_set(int8_t interface_id, uint8_t dua_status, uint8_t dua_count, uint8_t ba_failure_count)
{
    (void)interface_id;
    (void)dua_status;
    (void)dua_count;
    (void)ba_failure_count;
    return -1;
}

int thread_test_router_selection_jitter_set(int8_t interface_id, uint32_t jitter)
{
    (void)interface_id;
    (void)jitter;
    return -1;
}

int thread_test_min_delay_timer_set(int8_t interface_id, uint32_t delay_timer_value)
{
    (void)interface_id;
    (void)delay_timer_value;
    return -1;
}

int thread_test_increment_key_sequence_counter(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int thread_test_panid_query_send(int8_t interface_id, uint8_t *address_ptr, uint16_t session_id, uint16_t panid, uint8_t channel_page, uint8_t *mask_ptr)
{
    (void)interface_id;
    (void)address_ptr;
    (void)session_id;
    (void)panid;
    (void)channel_page;
    (void)mask_ptr;
    return -1;
}
int thread_test_energy_scan_send(int8_t interface_id, uint8_t *address_ptr, uint16_t session_id, uint8_t channel_page, uint8_t *mask_ptr, uint16_t period, uint8_t count, uint16_t duration)
{
    (void)interface_id;
    (void)address_ptr;
    (void)session_id;
    (void)channel_page;
    (void)mask_ptr;
    (void)period;
    (void)count;
    (void)duration;
    return -1;
}

int thread_test_diagnostic_command_send(int8_t interface_id, uint8_t *address_ptr, const char *uri_ptr, uint8_t request_length, uint8_t *request_ptr, response_cb *resp_cb)
{
    (void)interface_id;
    (void)address_ptr;
    (void)uri_ptr;
    (void)request_length;
    (void)request_ptr;
    (void)resp_cb;
    return -1;
}
int thread_test_coap_request_send(int8_t interface_id, uint8_t *address_ptr, uint16_t port, uint8_t msg_type, uint8_t msg_code, uint16_t content_format, const char *uri_ptr, uint8_t *request_ptr, uint8_t request_length, coap_response_cb *resp_cb)
{
    (void)interface_id;
    (void)address_ptr;
    (void)port;
    (void)msg_type;
    (void)msg_code;
    (void)content_format;
    (void)uri_ptr;
    (void)request_length;
    (void)request_ptr;
    (void)resp_cb;
    return -1;
}


int thread_test_announce_ntf_send(int8_t interface_id, uint8_t *address_ptr, uint32_t channel, uint16_t panid, uint64_t timestamp)
{
    (void)interface_id;
    (void)address_ptr;
    (void)channel;
    (void)panid;
    (void)timestamp;
    return -1;
}

int thread_test_announce_begin_send(int8_t interface_id, uint8_t *address_ptr, uint16_t session_id, uint8_t channel_page, uint8_t *mask_ptr, uint16_t period, uint8_t count)
{
    (void)interface_id;
    (void)address_ptr;
    (void)session_id;
    (void)channel_page;
    (void)mask_ptr;
    (void)period;
    (void)count;
    return -1;
}

int thread_test_partition_info_get(int8_t interface_id, uint32_t *partition_id, uint8_t *weighting, uint8_t *data_version, uint8_t *stable_data_version, uint8_t *leader_id)
{
    (void)interface_id;
    (void)partition_id;
    (void)weighting;
    (void)data_version;
    (void)stable_data_version;
    (void)leader_id;
    return -1;
}
int thread_test_partition_info_set(int8_t interface_id, uint32_t partition_id)
{
    (void)interface_id;
    (void)partition_id;
    return -1;
}
int8_t thread_test_thread_information_get(int8_t interface_id, uint16_t *short_addr, uint8_t *router_count, bool *network_stable)
{
    (void)interface_id;
    (void)short_addr;
    (void)router_count;
    (void)network_stable;
    return -1;
}


int8_t thread_test_child_count_get(int8_t interface_id)
{
    (void)interface_id;
    return -1;
}

int8_t thread_test_child_info_get(int8_t interface_id, uint8_t index, uint16_t *short_addr, bool *sleepy, uint8_t *mac64, uint8_t *margin)
{
    (void)interface_id;
    (void)index;
    (void)short_addr;
    (void)sleepy;
    (void)mac64;
    (void)margin;
    return -1;
}
int8_t thread_test_neighbour_info_get(int8_t interface_id, uint8_t index, uint16_t *short_addr, uint8_t *mac64, uint8_t *margin)
{
    (void)interface_id;
    (void)index;
    (void)short_addr;
    (void)mac64;
    (void)margin;
    return -1;
}

int8_t thread_test_initial_slaac_iid_set(int8_t interface_id, uint8_t *iid)
{
    (void)interface_id;
    (void)iid;
    return -1;
}


int8_t thread_test_router_id_request_send(int8_t interface_id, uint8_t status)
{
#ifdef HAVE_THREAD_ROUTER
    protocol_interface_info_entry_t *cur;

    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur || !cur->thread_info) {
        return -1;
    }

    if (thread_attach_ready(cur) != 0) {
        return -1;
    }

    tr_debug("Trigger REED router upgrade process with status %d", status);

    thread_router_bootstrap_router_id_request(cur, status);

    return 0;
#else
    (void)interface_id;
    (void)status;
    return -1;
#endif

}

int8_t thread_test_router_address_set(int8_t interface_id, uint16_t router_address)
{
    (void)interface_id;
    (void)router_address;
    return -1;
}

int8_t thread_test_joiner_router_joiner_port_set(uint16_t port)
{
    (void)port;
    return -1;

}

int8_t thread_test_mcast_address_per_message_set(uint8_t value)
{
    (void)value;
    return -1;
}

int thread_test_mle_message_send(int8_t interface_id, uint8_t *dst_address, uint8_t msg_id, bool write_src_addr, bool write_leader_data, bool write_network_data, bool write_timestamp, bool write_operational_set, bool write_challenge, uint8_t *msg_ptr, uint8_t msg_len)
{
    (void)interface_id;
    (void)dst_address;
    (void)msg_id;
    (void)write_src_addr;
    (void)write_leader_data;
    (void)write_network_data;
    (void)write_timestamp;
    (void)write_operational_set;
    (void)write_challenge;
    (void)msg_ptr;
    (void)msg_len;
    return -1;
}


int thread_test_extension_name_set(int8_t interface_id, char extension_name[16])
{
    (void) interface_id;
    (void) extension_name;
    return -1;
}

int thread_test_parent_priority_set(int8_t interface_id, uint8_t parent_priority)
{
    (void) interface_id;
    (void) parent_priority;
    return -1;
}
