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
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"

#include "app_wsbrd/rcp_api_legacy.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "common_protocols/ipv6.h"
#include "common_protocols/icmpv6.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/nd/nd_router_object.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/nd/nd_router_object.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"

#include "6lowpan/bootstraps/protocol_6lowpan.h"

#define TRACE_GROUP_LOWPAN "6lo"
#define TRACE_GROUP "6lo"

/* Data rate for application used in Stagger calculation */
#define STAGGER_DATARATE_FOR_APPL(n) ((n)*75/100)

/* Time after network is considered stable and smaller stagger values can be given*/
#define STAGGER_STABLE_NETWORK_TIME 3600*4

/* Having to sidestep old rpl_dodag_t type for the moment */
struct rpl_dodag *protocol_6lowpan_rpl_root_dodag;

static bool protocol_buffer_valid(buffer_t *b, struct net_if *cur)
{
    if (!cur)
        return false;
    if ((b->info & B_TO_MAC_MLME_MASK) == B_TO_MAC_FROM_MAC)
        return true;
    if (cur->lowpan_info & INTERFACE_NWK_ACTIVE)
        return true;
    return false;
}

void protocol_init(void)
{
    ws_cfg_settings_init();
}

void protocol_6lowpan_stack(buffer_t *b)
{
    struct net_if *cur = b->interface;
    if (!protocol_buffer_valid(b, cur)) {
        tr_debug("Drop Packets");
        buffer_free(b);
        return;
    }
    /* Protocol Buffer Handle until Buffer Go out from Stack */
    while (b) {
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
    }
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
    write_be16(ll_addr_out->address + 0, cur->mac_parameters.pan_id);

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
        if (memcmp(&ip_addr[8], ADDR_SHORT_ADR_SUFFIC, 6) == 0) {
            *ll_type = ADDR_802_15_4_SHORT;
            memcpy(&ll_addr[2], &ip_addr[14], 2);
        } else {
            *ll_type = ADDR_802_15_4_LONG;
            memcpy(&ll_addr[2], &ip_addr[8], 8);
            ll_addr[2] ^= 2;
        }
    }

    if (*ll_type != ADDR_NONE) {
        write_be16(&ll_addr[0], cur->mac_parameters.pan_id);
        *ll_addr_out = ll_addr;
        return true;
    } else {
        return false;
    }

}

void protocol_6lowpan_configure_core(struct net_if *cur)
{
    cur->dup_addr_detect_transmits = 0;
    cur->ipv6_neighbour_cache.max_ll_len = 2 + 8;
    cur->ipv6_neighbour_cache.link_mtu = LOWPAN_MTU;
    cur->ipv6_neighbour_cache.send_nud_probes = true;
    cur->max_link_mtu = LOWPAN_MAX_MTU;
    cur->send_mld = false;
}

void protocol_6lowpan_register_handlers(struct net_if *cur)
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
}

void protocol_6lowpan_release_long_link_address_from_neighcache(struct net_if *cur, const uint8_t *mac64)
{
    uint8_t temp_ll[10];
    uint8_t *ptr = temp_ll;
    ptr = write_be16(ptr, cur->mac_parameters.pan_id);
    memcpy(ptr, mac64, 8);
    ipv6_neighbour_invalidate_ll_addr(&cur->ipv6_neighbour_cache,
                                      ADDR_802_15_4_LONG, temp_ll);
    nd_remove_registration(cur, ADDR_802_15_4_LONG, temp_ll);
}

void protocol_6lowpan_interface_common_init(struct net_if *cur)
{
    cur->lowpan_info |= INTERFACE_NWK_ACTIVE;
    protocol_6lowpan_register_handlers(cur);
    ipv6_route_add(ADDR_LINK_LOCAL_PREFIX, 64, cur->id, NULL, ROUTE_STATIC, 0xFFFFFFFF, 0);
    // Putting a multicast route to ff00::/8 makes sure we can always transmit multicast.
    // Interface metric will determine which interface is actually used, if we have multiple.
    ipv6_route_add(ADDR_LINK_LOCAL_ALL_NODES, 8, cur->id, NULL, ROUTE_STATIC, 0xFFFFFFFF, -1);
}
