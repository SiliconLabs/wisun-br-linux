/*
 * Copyright (c) 2013-2021, Pelion and affiliates.
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/rand.h"
#include "common/log_legacy.h"
#include "common/endian.h"

#include "6lowpan/fragmentation/cipv6_fragmenter.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "ipv6/nd_router_object.h"
#include "ipv6/icmpv6.h"
#include "ipv6/ipv6.h"
#include "net/ns_buffer.h"
#include "net/protocol.h"

#include "6lowpan/bootstraps/protocol_6lowpan.h"

#define TRACE_GROUP "6lo"

static void protocol_6lowpan_stack(buffer_t *b)
{
    struct net_if *cur = b->interface;
    if (!cur) {
        tr_debug("Drop Packets");
        buffer_free(b);
        return;
    }
    /* Protocol Buffer Handle until Buffer Go out from Stack */
    do {
        /* Buffer Direction Select Switch */
        if ((b->info & B_DIR_MASK) == B_DIR_DOWN) {
            /* Direction DOWN */
            switch (b->info & B_TO_MASK) {
                case B_TO_ICMP:
                    /* Build ICMP Header */
                    b = icmpv6_down(b);
                    break;
                case B_TO_IPV6:
                    /* Build IP header */
                    b = ipv6_down(b);
                    break;

                case B_TO_IPV6_FWD:
                    /* IPv6 forwarding */
                    b = ipv6_forwarding_down(b);
                    break;

                case B_TO_IPV6_TXRX:
                    /* Resolution, Compress IP header */
                    b = lowpan_down(b);
                    break;

                case B_TO_MAC:
                /* no break */
                case B_TO_PHY:
                    b = lowpan_adaptation_data_process_tx_preprocess(cur, b);
                    if (lowpan_adaptation_interface_tx(cur, b) != 0) {
                        tr_error("Adaptation Layer Data req fail");
                    }
                    b = NULL;
                    break;

                default:
                    b = buffer_free(b);
                    break;
            }
        } else {
            /* Direction UP */
            switch (b->info & B_TO_MASK) {
                case B_TO_ICMP:
                    /* Parse ICMP Message */
                    b = icmpv6_up(b);
                    break;

                case B_TO_FRAGMENTATION:
                    /* Packet Reasemley */
                    b = cipv6_frag_reassembly(cur->id, b);

                    break;
                case B_TO_IPV6_FWD:
                    /* Handle IP Payload */
                    b = ipv6_forwarding_up(b);
                    break;
                case B_TO_IPV6_TXRX:
                    /* Handle MAC Payload */
                    b = lowpan_up(b);
                    break;
                case B_TO_TCP:
                default:
                    tr_debug("LLL");
                    b = buffer_free(b);
                    break;
            }
        }
    } while (b);
}

/* Return length of option always, and write option if opt_out != NULL */
static uint8_t protocol_6lowpan_llao_write(struct net_if *cur, uint8_t *opt_out, uint8_t opt_type, bool must, const uint8_t *ip_addr)
{
    /* Don't bother including optional LLAO if it's a link-local address -
     * they should be mapping anyway.
     */
    if (!must && addr_is_ipv6_link_local(ip_addr)) {
        return 0;
    }

    if (opt_out) {
        opt_out[0] = opt_type;
        opt_out[1] = 2;
        memcpy(opt_out + 2, cur->mac, 8);
        memset(opt_out + 10, 0, 6);
    }
    return 16;
}

/* Parse, and return actual size, or 0 if error */
static uint8_t protocol_6lowpan_llao_parse(struct net_if *cur, const uint8_t *opt_in, sockaddr_t *ll_addr_out)
{
    write_be16(ll_addr_out->address + 0, cur->ws_info.pan_information.pan_id);

    switch (opt_in[1]) {
        case 1:
            ll_addr_out->addr_type = ADDR_802_15_4_SHORT;
            memcpy(ll_addr_out->address + 2, opt_in + 2, 2);
            return 2 + 2;
        case 2:
            ll_addr_out->addr_type = ADDR_802_15_4_LONG;
            memcpy(ll_addr_out->address + 2, opt_in + 2, 8);
            return 2 + 8;
        default:
            return 0;
    }
}

static bool protocol_6lowpan_map_ip_to_link_addr(struct net_if *cur, const uint8_t *ip_addr, addrtype_e *ll_type, const uint8_t **ll_addr_out)
{
    static uint8_t ll_addr[10];
    *ll_type = ADDR_NONE;

    /* RFC 6775 says link-local addresses are based on extended MAC (LL64) */
    /* ZigBee IP and Thread both also have link-local addresses based on short MAC (LL16) */
    /* Our old IP stack assumed all addresses were based on MAC; this is available as an option */
    if (addr_is_ipv6_link_local(ip_addr)) {
        if (memcmp(&ip_addr[8], ADDR_SHORT_ADDR_SUFFIX, 6) == 0) {
            *ll_type = ADDR_802_15_4_SHORT;
            memcpy(&ll_addr[2], &ip_addr[14], 2);
        } else {
            *ll_type = ADDR_802_15_4_LONG;
            memcpy(&ll_addr[2], &ip_addr[8], 8);
            ll_addr[2] ^= 2;
        }
    }

    if (*ll_type != ADDR_NONE) {
        write_be16(&ll_addr[0], cur->ws_info.pan_information.pan_id);
        *ll_addr_out = ll_addr;
        return true;
    } else {
        return false;
    }

}

void protocol_6lowpan_up(struct net_if *cur)
{
    cur->if_stack_buffer_handler = protocol_6lowpan_stack;
    cur->if_llao_parse = protocol_6lowpan_llao_parse;
    cur->if_llao_write = protocol_6lowpan_llao_write;
    cur->if_map_ip_to_link_addr = protocol_6lowpan_map_ip_to_link_addr;

    cur->ipv6_neighbour_cache.recv_addr_reg = true;
    cur->ipv6_neighbour_cache.recv_ns_aro = true;
    /* Always send AROs, (compulsory for hosts, and "SHOULD" in RFC 6557 6.5.5
     * for routers, as RPL doesn't deal with it) */
    cur->ipv6_neighbour_cache.send_addr_reg = true;

    ipv6_route_add(ADDR_LINK_LOCAL_PREFIX, 64, cur->id, NULL, ROUTE_STATIC, 0xFFFFFFFF, 0);
    // Putting a multicast route to ff00::/8 makes sure we can always transmit multicast.
    // Interface metric will determine which interface is actually used, if we have multiple.
    ipv6_route_add(ADDR_LINK_LOCAL_ALL_NODES, 8, cur->id, NULL, ROUTE_STATIC, 0xFFFFFFFF, -1);
}
