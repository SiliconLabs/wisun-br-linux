/*
 * Copyright (c) 2015-2019, Pelion and affiliates.
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
/* IPv6 fragmentation and defragmentation
 *
 * (Could fairly easily be modified to also do IPv4)
 *
 * References:
 *
 * RFC  815   IP Datagram Reassembly Algorithms
 * RFC 3168   The Addition of Explicit Congestion Notification (ECN) to IP
 * RFC 6040   Tunnelling of Explicit Congestion Notification
 * RFC 6660   Encoding Three Pre-Congestion Notification (PCN) States in the
 *            IP Header Using a Single Diffserv Codepoint (DSCP)
 * RFC 8200   Internet Protocol, Version 6 (IPv6) Specification
 * RFC 8201   Path MTU Discovery for IP version 6
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "common/endian.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "legacy/ns_socket.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"

#include "common_protocols/ip.h"
#include "common_protocols/ipv6.h"
#include "common_protocols/icmpv6.h"

#include "legacy/ipv6_fragmentation_tx.h"

#define TRACE_GROUP "Ifrg"

/*                         FRAGMENT CREATION
 *
 * Allow fragment TX to be disabled for constrained systems.
 * This would violate RFC 6434, which says all IPv6 nodes must be able to
 * generate fragment headers. (Even if our only link has the minimum 1280-byte
 * MTU, we may still need to insert a fragment header).
 */
buffer_t *ipv6_frag_down(buffer_t *dgram_buf)
{
    uint8_t *ip_ptr = buffer_data_pointer(dgram_buf);
    uint16_t pmtu = ipv6_mtu(dgram_buf);
    uint8_t *frag_hdr;
    buffer_list_t frags_list = NS_LIST_INIT(frags_list);
    ipv6_destination_t *dest = ipv6_destination_lookup_or_create(dgram_buf->dst_sa.address, dgram_buf->interface->id);
    if (!dest) {
        return buffer_free(dgram_buf);
    }

    /* Skip over HbH and Routing headers to reach fragmentable part. Assume
     * packet well-formed (we created it...).
     */
    uint8_t *nh_ptr = &ip_ptr[6];
    uint8_t nh = *nh_ptr;
    uint8_t *fragmentable = ip_ptr + 40;
    while (nh == IPV6_NH_HOP_BY_HOP || nh == IPV6_NH_ROUTING) {
        nh_ptr = &fragmentable[0];
        nh = *nh_ptr;
        fragmentable += (fragmentable[1] + 1) * 8;
    }
    uint16_t unfrag_len = fragmentable - ip_ptr;
    uint16_t fragmentable_len = buffer_data_end(dgram_buf) - fragmentable;

    *nh_ptr = IPV6_NH_FRAGMENT;

    /* Check for silly situation - can't fit any fragment data (8 for fragment
     * header, 8 for minimum fragment payload) */
    if (unfrag_len + 8 + 8 > pmtu) {
        goto failed;
    }

    ++dest->fragment_id;

    /* RFC 7112 requires the entire header chain to be in the first fragment. */
    /* We don't explicitly check for this, but it would be spectacularly unlikely. */
    /* I think it would require a super-sized routing header */

    /* This is much simpler (more simplistic?) than the 6LoWPAN fragmentation,
     * which relies on co-operation with lower layers to ensure it works one
     * fragment at a time. We make all the fragments in one go, meaning higher
     * overhead, but IP fragmentation should be pretty rare - we don't need
     * to optimise this.
     */
    for (uint16_t frag_offset = 0; fragmentable_len;) {
        /* How much going in this packet? */
        uint16_t frag_len = (pmtu - unfrag_len - 8);
        if (fragmentable_len > frag_len) {
            frag_len &= ~7;
        } else {
            frag_len = fragmentable_len;
        }

        buffer_t *frag_buf = buffer_get(unfrag_len + 8 + frag_len);
        if (!frag_buf) {
            goto failed;
        }

        /* Clone the buffer header, apart from size+ptr */
        buffer_copy_metadata(frag_buf, dgram_buf, false);

        /* We splat the socket, so no upper-layer callbacks from the fragments */
        buffer_socket_set(frag_buf, NULL);

        /* Construct the new packet contents */
        buffer_data_length_set(frag_buf, unfrag_len + 8 + frag_len);
        uint8_t *ptr = buffer_data_pointer(frag_buf);
        /* Unfragmentable part */
        memcpy(ptr, ip_ptr, unfrag_len);
        /* Adjust length in IP header */
        write_be16(ptr + 4, unfrag_len - 40 + 8 + frag_len);
        /* Fragment header */
        frag_hdr = ptr + unfrag_len;
        frag_hdr[0] = nh;
        frag_hdr[1] = 0;
        write_be16(frag_hdr + 2, frag_offset | (frag_len != fragmentable_len));
        write_be32(frag_hdr + 4, dest->fragment_id);
        /* Fragment data */
        memcpy(frag_hdr + 8, fragmentable + frag_offset, frag_len);
        fragmentable_len -= frag_len;
        frag_offset += frag_len;

        /* Add to our fragment list */
        ns_list_add_to_start(&frags_list, frag_buf);
    }

    /* Now have a list of fragment buffers - report "success" to the socket */
    /* (TCP may save the dgram payload here? It strips off headers, so okay...) */
    socket_tx_buffer_event_and_free(dgram_buf, SOCKET_TX_DONE);

    /* Push the fragments. Backwards, as it happens, but who cares? */
    ns_list_foreach_safe(buffer_t, f, &frags_list) {
        ns_list_remove(&frags_list, f);
        protocol_push(f);
    }

    return NULL;

failed:
    /* Failed to allocate a buffer - no point sending any fragments if we
     * can't send all.
     */
    ns_list_foreach_safe(buffer_t, f, &frags_list) {
        ns_list_remove(&frags_list, f);
        buffer_free(f);
    }

    socket_tx_buffer_event_and_free(dgram_buf, SOCKET_NO_RAM);
    return NULL;
}
