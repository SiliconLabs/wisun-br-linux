/*
 * Copyright (c) 2014-2019, Pelion and affiliates.
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
#include <nsdynmemLIB.h>
#include "eventOS_event.h"
#include <ns_list.h>
#include "ns_trace.h"
#include "core/include/ns_buffer.h"
#include "common_functions.h"
#include "randLIB.h"
#include "thread_border_router_api.h"
#include "thread_management_if.h"
#include "nwk_interface/protocol.h"
#include "6lowpan/thread/thread_config.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_network_data_lib.h"
#include "6lowpan/thread/thread_network_data_storage.h"
#include "6lowpan/thread/thread_management_client.h"
#include "6lowpan/thread/thread_joiner_application.h"
#include "6lowpan/thread/thread_tmfcop_lib.h"
#include "6lowpan/thread/thread_border_router_api_internal.h"
#include "6lowpan/thread/thread_bbr_commercial.h"
#include "6lowpan/thread/thread_mdns.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "mle/mle.h"
#include "thread_meshcop_lib.h"
#include "thread_network_data_lib.h"
#include "coap_service_api.h"

#define TRACE_GROUP "tBRa"


/*External APIs*/

int thread_border_router_prefix_add(int8_t interface_id, uint8_t *prefix_ptr, uint8_t prefix_len, thread_border_router_info_t *prefix_info_ptr)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) prefix_len;
    (void) prefix_info_ptr;
    return -1;
}

int thread_border_router_prefix_delete(int8_t interface_id, uint8_t *prefix_ptr, uint8_t prefix_len)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) prefix_len;
    return -1;
}

int thread_border_router_route_add(int8_t interface_id, uint8_t *prefix_ptr, uint8_t prefix_len, bool stable, int8_t prf)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) prefix_len;
    (void) stable;
    (void) prf;
    return -1;
}

int thread_border_router_route_delete(int8_t interface_id, uint8_t *prefix_ptr, uint8_t prefix_len)
{
    (void) interface_id;
    (void) prefix_ptr;
    (void) prefix_len;
    return -1;

}

int thread_border_router_service_add(int8_t interface_id, uint8_t *service_data, uint8_t service_len, uint8_t sid, uint32_t enterprise_number, uint8_t *server_data, uint8_t server_data_len, bool stable)
{
    (void)interface_id;
    (void)service_data;
    (void)service_len;
    (void)sid;
    (void)enterprise_number;
    (void)server_data;
    (void)server_data_len;
    (void)stable;
    return -1;
}

int thread_border_router_service_delete(int8_t interface_id, uint8_t *service_data, uint8_t service_len, uint32_t enterprise_number)
{
    (void) interface_id;
    (void) service_data;
    (void) service_len;
    (void) enterprise_number;
    return -1;
}

int thread_border_router_recursive_dns_server_option_set(int8_t interface_id, uint8_t *recursive_dns_server_option, uint16_t recursive_dns_server_option_len)
{
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_border_router_recursive_dns_server_option_store(interface_id, recursive_dns_server_option, recursive_dns_server_option_len);
#else
    (void)interface_id;
    (void)recursive_dns_server_option;
    (void)recursive_dns_server_option_len;
    return -1;
#endif
}

int thread_border_router_dns_search_list_option_set(int8_t interface_id, uint8_t *dns_search_list_option, uint16_t search_list_option_len)
{
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_border_router_dns_search_list_option_store(interface_id, dns_search_list_option, search_list_option_len);
#else
    (void)interface_id;
    (void)dns_search_list_option;
    (void)search_list_option_len;
    return -1;
#endif
}

/** Network data set response callback.
 *
 * callback to inform if network data was set to leader.
 *
 * /param status status of operation 0 success, -1 failure from leader received
 * /param data_ptr pointer to network data TLV that leader accepted.
 * /param data_len length of network data.
 *
 */

int thread_border_router_publish(int8_t interface_id)
{
    (void) interface_id;
    return -1;
}

int thread_border_router_delete_all(int8_t interface_id)
{
    (void) interface_id;
    return -1;
}

int thread_border_router_network_data_callback_register(int8_t interface_id, thread_network_data_tlv_cb *nwk_data_cb)
{
    (void)interface_id;
    (void)nwk_data_cb;
    return -1;
}

int thread_border_router_prefix_tlv_find(uint8_t *network_data_tlv, uint16_t network_data_tlv_length, uint8_t **prefix_tlv, bool *stable)
{
    (void)network_data_tlv;
    (void)network_data_tlv_length;
    (void)prefix_tlv;
    (void)stable;
    return -1;
}

int thread_border_router_tlv_find(uint8_t *prefix_tlv, uint16_t prefix_tlv_length, uint8_t **border_router_tlv, bool *stable)
{
    (void)prefix_tlv;
    (void)prefix_tlv_length;
    (void)border_router_tlv;
    (void)stable;
    return -1;
}

int thread_border_router_prefix_context_id(uint8_t *prefix_tlv, uint16_t prefix_tlv_length)
{
    (void)prefix_tlv;
    (void)prefix_tlv_length;
    return -1;
}

int thread_border_router_service_tlv_find(uint8_t *network_data_tlv, uint16_t network_data_tlv_length, uint8_t **service_tlv, bool *stable)
{
    (void)network_data_tlv;
    (void)network_data_tlv_length;
    (void)service_tlv;
    (void)stable;
    return -1;
}

int thread_border_router_server_tlv_find(uint8_t *service_tlv, uint16_t service_tlv_length, uint8_t **server_tlv, bool *stable)
{
    (void)service_tlv;
    (void)service_tlv_length;
    (void)server_tlv;
    (void)stable;
    return -1;
}

int thread_border_router_mdns_responder_start(int8_t interface_id, int8_t interface_id_mdns, const char *service_name)
{
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_mdns_start(interface_id, interface_id_mdns, service_name);
#else
    (void)interface_id;
    (void)interface_id_mdns;
    (void)service_name;
    return -1;
#endif
}

int thread_border_router_mdns_responder_stop(void)
{
#ifdef HAVE_THREAD_BORDER_ROUTER
    return thread_mdns_stop();
#else
    return -1;
#endif
}

