/*
 * Copyright (c) 2013-2018, Pelion and affiliates.
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

#include <stdint.h>
#include <string.h>
#include "common/log_legacy.h"
#include "common/endian.h"

#include "ipv6/ipv6.h"
#include "ipv6/ipv6_resolution.h"
#include "net/protocol.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"

#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/iphc_decode/iphc_compress.h"
#include "6lowpan/iphc_decode/iphc_decompress.h"

#define TRACE_GROUP  "iphc"

/* Input: Final IP packet for transmission on link.
 *        Buffer destination = final destination
 *        Buffer source undefined.
 *        Route next hop address set.
 * Output: Buffer destination+source = link-layer addresses
 *         Sent to mesh, LowPAN fragmentation or MAC layers
 */
buffer_t *lowpan_down(buffer_t *buf)
{
    struct net_if *cur = buf->interface;

    buf->options.type = 0;

    if (!buf->route) {
        tr_debug("lowpan_down route");
        return buffer_free(buf);
    }

    const uint8_t *ip_src = buffer_data_pointer(buf) + 8;
    const uint8_t *next_hop = buf->route->route_info.next_hop_addr;

    /* We have IP next hop - figure out the MAC address */
    if (addr_is_ipv6_multicast(next_hop)) {
        buf->dst_sa.addr_type = ADDR_BROADCAST;
        write_be16(buf->dst_sa.address, cur->ws_info.pan_information.pan_id);
        buf->dst_sa.address[2] = 0x80 | (next_hop[14] & 0x1f);
        buf->dst_sa.address[3] = next_hop[15];
    } else { /* unicast */
        ipv6_neighbour_t *n = ipv6_interface_resolve_new(cur, buf);
        if (!n) {
            return NULL;
        }
    }

    /* Figure out which source MAC address to use. Usually try to match the
     * source, for best compression, and to ensure if the layer above uses LL64
     * (like MLE), it forces us to use our MAC64.
     */
    if (addr_iid_matches_eui64(ip_src + 8, cur->mac)) {
        buf->src_sa.addr_type = ADDR_802_15_4_LONG;
    } else {
        /* This lets mac_mlme_write_our_addr choose based on address mode */
        buf->src_sa.addr_type = ADDR_NONE;
    }

    if (cur->ws_info.pan_information.pan_id == 0xffff)
        return buffer_free(buf);
    buf->src_sa.addr_type = ADDR_802_15_4_LONG;
    write_le16(buf->src_sa.address, cur->ws_info.pan_information.pan_id);
    memcpy(buf->src_sa.address + 2, cur->mac, 8);

    /* Clear Link Layer Re Transmission Counter */
    //buf->fhss_channel_retries_left = 1+ cur->mac_parameters.number_of_fhss_channel_retries;


    if (buf->dst_sa.addr_type != ADDR_802_15_4_LONG && buf->dst_sa.addr_type != ADDR_802_15_4_SHORT && buf->dst_sa.addr_type != ADDR_BROADCAST) {
        tr_debug("IP:Dest Pro. addr_type: %02x", buf->dst_sa.addr_type);
        return buffer_free(buf);
    }

    if (buf->dst_sa.addr_type == ADDR_BROADCAST) {
        /*
         * Not using a mesh header, so have to "purify" RFC 4944 multicast - we
         * set a 100xxxxxxxxxxxxx RFC 4944 multicast address above, but
         * IEEE 802.15.4 only supports broadcast in the real MAC header.
         */
        write_be16(buf->dst_sa.address + 2, 0xFFFF);
    }

    /* RFC 6282+4944 require that we limit compression to the first fragment.
     * This check is slightly conservative - always allow 4 for first-fragment header
     */
    uint16_t max_iphc_size = cur->mac_parameters.mtu - mac_helper_frame_overhead(cur, buf) - 4;

    buf = iphc_compress(buf, max_iphc_size);
    if (!buf) {
        return NULL;
    }

    buf->info = (buffer_info_t)(B_FROM_IPV6_TXRX | B_TO_MAC | B_DIR_DOWN);

    return buf;
}

buffer_t *lowpan_up(buffer_t *buf)
{
    /* Reject:
     *    Packets without address
     *    Source broadcast PAN ID
     *    Short source addresses 0xfffe (illegal) and 0xffff (broadcast)
     */
    if (buf->dst_sa.addr_type == ADDR_NONE || buf->src_sa.addr_type == ADDR_NONE ||
            read_be16(buf->src_sa.address) == 0xffff ||
            (buf->dst_sa.addr_type == ADDR_802_15_4_SHORT && read_be16(buf->src_sa.address + 2) > 0xfffd)) {
        goto drop;
    }

    const uint8_t *ip_hc = buffer_data_pointer(buf);

    //tr_debug("IP-UP";

    if (buffer_data_length(buf) < 4 || addr_check_broadcast(buf->src_sa.address, buf->src_sa.addr_type) == 0) {
        tr_debug("cipv6_up() Too short or broadcast src");
        goto drop;
    } else if ((ip_hc[0] & LOWPAN_FRAG_MASK) == LOWPAN_FRAG) {
        /* 11 x00xxx: FRAG1/FRAGN (RFC 4944) */
        buf->info = (buffer_info_t)(B_DIR_UP | B_FROM_IPV6_TXRX | B_TO_FRAGMENTATION);
        return buf;
    } else if ((ip_hc[0] & LOWPAN_MESH_MASK) == LOWPAN_MESH) {
        /* 10 xxxxxx: MESH (RFC 4944) */
        buf->info = (buffer_info_t)(B_DIR_UP | B_FROM_IPV6_TXRX | B_TO_MESH_ROUTING);
        return buf;
    } else if (ip_hc[0] == LOWPAN_DISPATCH_IPV6) {
        /* Send this to new handler */
        buffer_data_strip_header(buf, 1);
        buf->ip_routed_up = true;
        buf->info = (buffer_info_t)(B_DIR_UP | B_FROM_IPV6_TXRX | B_TO_IPV6_FWD);
        return buf;
    } else if ((ip_hc[0] & LOWPAN_DISPATCH_IPHC_MASK) != LOWPAN_DISPATCH_IPHC) {
        /* Not handled: LOWPAN_HC1/LOWPAN_BC0/IPv6 (RFC 4944), or extension */
        tr_debug("LOWPAN: %02x %02x", ip_hc[0], ip_hc[1]);
        goto drop;
    }

    /* Divert to new routing system - in final system, MAC/mesh/Frag should send to IPV6_TXRX layer */
    buf->ip_routed_up = true;
    buf = iphc_decompress(buf);
    if (buf) {
        buf->info = (buffer_info_t)(B_DIR_UP | B_FROM_IPV6_TXRX | B_TO_IPV6_FWD);
    }
    return buf;

drop:
    return buffer_free(buf);
}
