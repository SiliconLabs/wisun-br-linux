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
#include <ns_types.h>
#include <ns_list.h>
#include <ns_trace.h>
#include "nsdynmemLIB.h"
#include "common_functions.h"
#include "nwk_interface/protocol.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_management_server.h"
#include "6lowpan/thread/thread_network_data_lib.h"
#include "6lowpan/thread/thread_leader_service.h"
#include "6lowpan/thread/thread_discovery.h"
#include "6lowpan/thread/thread_bbr_api_internal.h"
#include "6lowpan/thread/thread_border_router_api_internal.h"
#include "6lowpan/mac/mac_helper.h"

#define TRACE_GROUP "TMFs"

#include "eventOS_event_timer.h"
#include "coap_service_api.h"

#include "net_interface.h"
#include "socket_api.h"
#include "thread_common.h"
#include "thread_config.h"
#include "thread_tmfcop_lib.h"
#include "thread_meshcop_lib.h"
#include "thread_management_if.h"
#include "thread_management_internal.h"
#include "thread_commissioning_if.h"
#include "thread_joiner_application.h"
#include "thread_beacon.h"
#include "thread_bootstrap.h"
#include "thread_management_server.h"
#include "thread_management_client.h"
#include "thread_ccm.h"
#include "thread_nvm_store.h"
#include "mac_api.h"
#include "6lowpan/mac/mac_data_poll.h"
#include "common_protocols/ipv6_constants.h"
#include "core/include/ns_address_internal.h"
#include "mlme.h"


int thread_management_server_init(int8_t interface_id)
{
    (void) interface_id;
    return 0;
}

void thread_management_server_delete(int8_t interface_id)
{
    (void) interface_id;
}

int thread_management_server_joiner_router_init(int8_t interface_id)
{
    (void)interface_id;
    return 0;
}

void thread_management_server_joiner_router_deinit(int8_t interface_id)
{
    (void) interface_id;
}

int thread_management_server_commisoner_data_get(int8_t interface_id, thread_management_server_data_t *server_data)
{
    (void) interface_id;
    (void) server_data;
    return -1;
}

bool thread_management_server_source_address_check(int8_t interface_id, uint8_t source_address[16])
{
    (void)interface_id;
    (void)source_address;
    return false;
}

int thread_management_server_tmf_get_request_handler(int8_t interface_id, int8_t coap_service_id, struct sn_coap_hdr_ *request_ptr)
{
    (void)interface_id;
    (void)coap_service_id;
    (void)request_ptr;
    return -1;
}
