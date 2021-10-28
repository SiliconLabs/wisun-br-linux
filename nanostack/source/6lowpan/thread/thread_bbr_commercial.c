/*
 * Copyright (c) 2017-2019, 2021, Pelion and affiliates.
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
#include <ns_types.h>
#include <string.h>
#include <nsdynmemLIB.h>
#include "ns_list.h"
#include "ns_trace.h"
#include "randLIB.h"
#include "common_functions.h"

#include "thread_config.h"
#include "coap_service_api.h"
#include "thread_bbr_api.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_bootstrap.h"
#include "6lowpan/thread/thread_network_data_lib.h"
#include "6lowpan/thread/thread_management_client.h"
#include "6lowpan/thread/thread_tmfcop_lib.h"
#include "6lowpan/thread/thread_joiner_application.h"
#include "6lowpan/thread/thread_management_internal.h"
#include "6lowpan/thread/thread_discovery.h"
#include "6lowpan/thread/thread_bbr_api_internal.h"
#include "6lowpan/thread/thread_resolution_client.h"
#include "6lowpan/thread/thread_bbr_commercial.h"
#include "6lowpan/thread/thread_ccm.h"
#include "6lowpan/mac/mac_helper.h"
#include "nwk_interface/protocol.h"
#include "common_protocols/ipv6.h"


