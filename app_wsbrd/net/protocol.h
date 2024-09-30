/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#ifndef _NS_PROTOCOL_H
#define _NS_PROTOCOL_H
#include "common/random_early_detection.h"
#include "common/trickle_legacy.h"
#include "common/ns_list.h"

#include "net/protocol_abstract.h"
#include "net/ns_address_internal.h"
#include "ws/ws_common.h"
#include "ipv6/ipv6_routing_table.h"

#include "rpl/rpl.h"

typedef struct buffer buffer_t;

void protocol_push(buffer_t *buf);
void protocol_core_init(void);

typedef struct arm_15_4_mac_parameters {
    uint16_t mtu;
    /* Security API USE */
} arm_15_4_mac_parameters_t;

struct net_if {
    int8_t id;
    uint8_t zone_index[16];
    ns_list_link_t link;
    if_address_list_t ip_addresses;
    if_group_list_t ip_groups;
    struct mpl_domain *mpl_domain;
    ipv6_neighbour_cache_t ipv6_neighbour_cache;

    uint16_t icmp_tokens; /* Token bucket for ICMP rate limiting */
    /* RFC 4861 Host Variables */
    uint8_t cur_hop_limit;
    uint16_t reachable_time_ttl;        // s
    uint32_t base_reachable_time;       // ms

    uint8_t mac[8];
    uint8_t iid_eui64[8];
    uint8_t iid_slaac[8];

    struct red_config random_early_detection;
    struct red_config llc_random_early_detection;
    struct red_config llc_eapol_random_early_detection;
    struct red_config pae_random_early_detection;
    struct ws_info ws_info;

    struct rcp *rcp;
    arm_15_4_mac_parameters_t mac_parameters;

    struct rpl_root rpl_root;

    void (*if_stack_buffer_handler)(buffer_t *);
    bool (*if_ns_transmit)(struct net_if *cur, ipv6_neighbour_t *neighCacheEntry, bool unicast, uint8_t seq);
    bool (*if_map_ip_to_link_addr)(struct net_if *cur, const uint8_t *ip_addr, enum addrtype *ll_type, const uint8_t **ll_addr_out);
    uint8_t (*if_llao_parse)(struct net_if *cur, const uint8_t *opt_in, sockaddr_t *ll_addr_out);
    uint8_t (*if_llao_write)(struct net_if *cur, uint8_t *opt_out, uint8_t opt_type, bool must, const uint8_t *ip_addr);
};

typedef NS_LIST_HEAD(struct net_if, link) protocol_interface_list_t;

extern protocol_interface_list_t protocol_interface_info_list;

struct net_if *protocol_stack_interface_info_get();
void protocol_init(struct net_if *net_if, struct rcp *rcp, int mtu);

void icmp_fast_timer(int ticks);
void update_reachable_time(int seconds);

#endif
