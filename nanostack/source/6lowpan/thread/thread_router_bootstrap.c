/*
 * Copyright (c) 2015-2020, Pelion and affiliates.
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

/*
 * \file thread_router_bootstrap.c
 * \brief Add short description about this file!!!
 *
 */
#include "nsconfig.h"
#include <string.h>
#include <ns_types.h>
#include <ns_list.h>
#include <nsdynmemLIB.h>
#include "eventOS_event.h"
#include "eventOS_event_timer.h"
#include "randLIB.h"
#include "shalib.h"
#include "common_functions.h"
#include "nwk_interface/protocol.h"
#include "net_thread_test.h"
#include "ns_trace.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_routing.h"
#include "6lowpan/thread/thread_nd.h"
#include "6lowpan/thread/thread_bootstrap.h"
#include "6lowpan/thread/thread_router_bootstrap.h"
#include "6lowpan/thread/thread_host_bootstrap.h"
#include "6lowpan/thread/thread_management_internal.h"
#include "6lowpan/thread/thread_network_synch.h"
#include "6lowpan/thread/thread_discovery.h"
#include "6lowpan/thread/thread_joiner_application.h"
#include "6lowpan/thread/thread_management_client.h"
#include "6lowpan/thread/thread_management_server.h"
#include "6lowpan/thread/thread_leader_service.h"
#include "6lowpan/thread/thread_beacon.h"
#include "6lowpan/thread/thread_network_data_lib.h"
#include "6lowpan/thread/thread_lowpower_private_api.h"
#include "6lowpan/thread/thread_tmfcop_lib.h"
#include "6lowpan/thread/thread_nvm_store.h"
#include "6lowpan/thread/thread_neighbor_class.h"
#include "6lowpan/thread/thread_ccm.h"
#include "thread_management_if.h"
#include "common_protocols/ipv6.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/icmpv6_radv.h"
#include "mle/mle.h"
#include "mle/mle_tlv.h"
#include "thread_config.h"
#include "multicast_api.h"
#include "service_libs/nd_proxy/nd_proxy.h"
#include "service_libs/mle_service/mle_service_api.h"
#include "service_libs/blacklist/blacklist.h"
#include "dhcpv6_client/dhcpv6_client_api.h"
#include "6lowpan/mac/mac_helper.h"
#include "mac_api.h"
#include "6lowpan/mac/mac_data_poll.h"
#include "thread_border_router_api.h"
#include "core/include/ns_address_internal.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"

