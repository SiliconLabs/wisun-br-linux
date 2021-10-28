/*
 * Copyright (c) 2014-2018, Pelion and affiliates.
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
 * Thread-specific routing functionality
 *
 * draft-kelsey-thread-routing-00
 */

#include "nsconfig.h"
#include <string.h>
#include <ns_types.h>
#include <ns_list.h>
#include <randLIB.h>
#include <nsdynmemLIB.h>

#define THREAD_ROUTING_FN extern

#include  <net_thread_test.h>
#include "ns_trace.h"
#include "common_functions.h"
#include "nwk_interface/protocol.h"
#include "mle/mle.h"
#include "6lowpan/mesh/mesh.h"
#include "6lowpan/thread/thread_common.h"
#include "6lowpan/thread/thread_nd.h"
#include "6lowpan/thread/thread_routing.h"
#include "6lowpan/thread/thread_leader_service.h"
#include "6lowpan/mac/mac_helper.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"

#define TRACE_GROUP "trou"

/* MLE Route Data bit assignments (draft-kelsey-thread-routing-00) */
#define ROUTE_DATA_OUT_MASK     0xC0
#define ROUTE_DATA_OUT_SHIFT    6
#define ROUTE_DATA_IN_MASK      0x30
#define ROUTE_DATA_IN_SHIFT     4
#define ROUTE_DATA_COST_MASK    0x0F
#define ROUTE_DATA_OURSELF      0x01

/*
 * MAX_LINK_AGE must be > 1.5 * trickle Imax, as that's the maximum spacing
 * between advert transmissions (assuming all peers have same Imax, as they
 * should)
 *
 * |---Imax---|---Imax---|  (Two Imax intervals, transmitting at Imax/2 in first
 *       t               t   and Imax-1 in second, so 1.5*Imax - 1 apart).
 */
#define MAX_LINK_AGE 100*10     /* 100 seconds */

#define LINK_AGE_STATIC 0xFFF  /* Magic number to indicate "never expire" */

