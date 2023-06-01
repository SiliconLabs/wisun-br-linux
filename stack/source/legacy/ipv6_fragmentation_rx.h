/*
 * Copyright (c) 2015-2017, Pelion and affiliates.
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
#ifndef IPV6_FRAGMENTATION_RX_H
#define IPV6_FRAGMENTATION_RX_H

#ifdef HAVE_IPV6_FRAGMENT

#include "common_protocols/ipv6_constants.h"
#include "core/ns_buffer.h"

/* How large a fragmented packet are we prepared to handle? */
/* Must be a multiple of 8. This default can be overridden. */
#ifndef IPV6_FRAG_MRU
#define IPV6_FRAG_MRU 1504
#endif

#if IPV6_FRAG_MRU & 7
#error IPV6_FRAG_MRU must be a multiple of 8
#endif

/* Note that the MRU above applies only to fragmented packets. RFC 2460 says:
 *
 *  From each link to which a node is directly attached, the node must be
 *  able to accept packets as large as that link's MTU.
 *
 * The IP spec doesn't seem to be explicit, but it is generally assumed that the
 * MRU should be greater than or equal to the MTU of every link - we shouldn't
 * refuse a packet just because it was fragmented.
 */

#if IPV6_FRAG_MRU < IPV6_MIN_FRAG_MRU
#error "IPV6_MRU too small"
#endif

uint16_t ipv6_frag_set_mru(uint16_t frag_mru);

void ipv6_frag_timer(int secs);
buffer_t *ipv6_frag_up(buffer_t *buf, const uint8_t *ptr, uint8_t *nh_ptr, uint16_t payload_length);

#else
#include <stdint.h>

static inline uint16_t ipv6_frag_set_mru(uint16_t frag_mru)
{
    return 0;
}

static inline void ipv6_frag_timer(int secs)
{
}

#endif

#endif
