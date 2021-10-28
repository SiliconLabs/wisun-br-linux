/*
 * Copyright (c) 2014-2019, 2021, Pelion and affiliates.
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
#include "ns_types.h"
#include "mlme.h"
#include "nwk_interface/protocol.h"
#include "thread_management_if.h"
#include <nsdynmemLIB.h>
#include "eventOS_event.h"
#include <ns_list.h>
#include <net_thread_test.h>
#include <net_ipv6_api.h>
#include "ns_trace.h"
#include "core/include/ns_buffer.h"
#include "common_functions.h"
#include "6lowpan/thread/thread_config.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_bootstrap.h"
#include "6lowpan/thread/thread_border_router_api_internal.h"
#include "6lowpan/thread/thread_routing.h"
#include "6lowpan/thread/thread_network_data_lib.h"
#include "6lowpan/thread/thread_network_data_storage.h"
#include "6lowpan/thread/thread_leader_service.h"
#include "6lowpan/thread/thread_nd.h"
#include "thread_diagnostic.h"
#include "dhcpv6_client/dhcpv6_client_api.h"
#include "6lowpan/thread/thread_discovery.h"
#include "6lowpan/thread/thread_network_synch.h"
#include "6lowpan/thread/thread_management_internal.h"
#include "6lowpan/thread/thread_management_server.h"
#include "6lowpan/thread/thread_joiner_application.h"
#include "6lowpan/thread/thread_management_client.h"
#include "6lowpan/thread/thread_nvm_store.h"
#include "6lowpan/thread/thread_ccm.h"
#include "6lowpan/thread/thread_tmfcop_lib.h"
#include "6lowpan/thread/thread_constants.h"
#include "6lowpan/thread/thread_bbr_api_internal.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "service_libs/mle_service/mle_service_security.h"
#include "rpl/rpl_control.h" // insanity - bootstraps shouldn't be doing each others' clean-up
#include "mle/mle.h"
#include "mle/mle_tlv.h"
#include "thread_meshcop_lib.h"
#include "thread_commissioning_if.h"
#include "shalib.h"
#include "common_protocols/icmpv6.h"
#include "dhcpv6_server/dhcpv6_server_service.h"
#include "6lowpan/thread/thread_dhcpv6_server.h"
#include "service_libs/mle_service/mle_service_api.h"
#include "service_libs/blacklist/blacklist.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mac_pairwise_key.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "mac_common_defines.h"
#include "mlme.h"
#include "mac_api.h"


/**
 *  Public interface functions.
 */

/**
 * Set DHCPV6 server for Thread GP data purpose
 *
 * \param interface_id Network Interface
 * \param prefix_ptr pointer DHCPv6 Server Given Prefix
 *
 * return 0, Set OK
 * return <0 Set Not OK
 */
int thread_dhcpv6_server_add(int8_t interface_id, uint8_t *prefix_ptr, uint32_t max_client_cnt, bool stableData)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) max_client_cnt;
    (void) stableData;
    return -1;
}

int thread_dhcpv6_server_set_lifetime(int8_t interface_id, uint8_t *prefix_ptr, uint32_t valid_lifetime)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) valid_lifetime;
    return -1;
}

int thread_dhcpv6_server_set_max_client(int8_t interface_id, uint8_t *prefix_ptr, uint32_t max_client_count)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) max_client_count;
    return -1;
}

int thread_dhcpv6_server_set_anonymous_addressing(int8_t interface_id, uint8_t *prefix_ptr, bool anonymous)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) anonymous;
    return -1;

}


int thread_dhcpv6_server_delete(int8_t interface_id, uint8_t *prefix_ptr)
{
    (void) interface_id;
    (void) prefix_ptr;
    return -1;
}


int thread_management_node_init(
    int8_t interface_id,
    channel_list_s *channel_list,
    device_configuration_s *device_configuration,
    link_configuration_s *static_configuration)
{
    (void) interface_id;
    (void) channel_list;
    (void) device_configuration;
    (void) static_configuration;
    return -1;
}

int thread_management_device_type_set(int8_t interface_id, thread_device_type_e device_type)
{
    (void) interface_id;
    (void) device_type;
    return -1;
}

int thread_management_max_child_count(
    int8_t interface_id,
    uint8_t maxChildCount)
{
    (void) interface_id;
    (void) maxChildCount;
    return -1;
}

link_configuration_s *thread_management_configuration_get(int8_t interface_id)
{
    (void) interface_id;
    return NULL;
}

device_configuration_s *thread_management_device_configuration_get(int8_t interface_id)
{
    (void) interface_id;
    return NULL;
}

int thread_management_link_configuration_store(int8_t interface_id, link_configuration_s *link_config)
{
    (void) interface_id;
    (void) link_config;
    return -1;
}

int thread_management_link_configuration_add(int8_t interface_id, uint8_t *additional_ptr, uint8_t additional_len)
{
    (void) interface_id;
    (void) additional_ptr;
    (void) additional_len;
    return -1;
}

int thread_management_link_configuration_delete(int8_t interface_id)
{
    (void) interface_id;
    return -1;
}

int thread_management_get_leader_address(int8_t interface_id, uint8_t *address_buffer)
{
    (void) interface_id;
    (void) address_buffer;
    return -1;
}

int thread_management_get_leader_aloc(int8_t interface_id, uint8_t *address_buffer)
{
    (void) interface_id;
    (void) address_buffer;
    return -1;
}
int thread_management_get_ml64_address(int8_t interface_id, uint8_t *address_ptr)
{
    (void) interface_id;
    (void) address_ptr;
    return -1;
}

int thread_management_get_ml16_address(int8_t interface_id, uint8_t *address_ptr)
{
    (void) interface_id;
    (void) address_ptr;
    return -1;
}

int thread_management_get_parent_address(int8_t interface_id, uint8_t *address_ptr)
{
    (void) interface_id;
    (void) address_ptr;
    return -1;
}

int thread_management_get_commissioner_address(int8_t interface_id, uint8_t *address_ptr, uint16_t *port_ptr)
{
    (void) interface_id;
    (void) address_ptr;
    (void) port_ptr;
    return -1;
}
int8_t thread_management_set_link_timeout(int8_t interface_id, uint32_t link_timeout)
{
    (void) interface_id;
    (void) link_timeout;
    return -1;
}

int8_t thread_management_get_link_timeout(int8_t interface_id, uint32_t *link_timeout)
{
    (void) interface_id;
    (void) link_timeout;
    return -1;
}

int8_t thread_management_set_request_full_nwk_data(int8_t interface_id, bool full_nwk_data)
{
    (void) interface_id;
    (void) full_nwk_data;
    return -1;
}

int8_t thread_management_get_request_full_nwk_data(int8_t interface_id, bool *full_nwk_data)
{
    (void) interface_id;
    (void) full_nwk_data;
    return -1;
}

int thread_management_device_certificate_set(int8_t interface_id, const unsigned char *device_certificate_ptr, uint16_t device_certificate_len, const unsigned char *priv_key_ptr, uint16_t priv_key_len)
{
    (void) device_certificate_ptr;
    (void) device_certificate_len;
    (void) priv_key_ptr;
    (void) priv_key_len;

    (void) interface_id;
    return -1;
}
int thread_management_network_certificate_set(int8_t interface_id, const unsigned char *network_certificate_ptr, uint16_t network_certificate_len, const unsigned char *priv_key_ptr, uint16_t priv_key_len)
{
    (void) network_certificate_ptr;
    (void) network_certificate_len;
    (void) priv_key_ptr;
    (void) priv_key_len;

    (void) interface_id;
    return -1;
}

int thread_management_partition_weighting_set(int8_t interface_id, uint8_t partition_weighting)
{
    (void) interface_id;
    (void) partition_weighting;
    return -1;
}
