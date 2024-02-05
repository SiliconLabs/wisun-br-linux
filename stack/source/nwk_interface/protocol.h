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
#include "common/trickle.h"
#include "common/ns_list.h"

#include "nwk_interface/protocol_abstract.h"
#include "core/ns_address_internal.h"
#include "6lowpan/iphc_decode/lowpan_context.h"
#include "6lowpan/ws/ws_common.h"
#include "ipv6_stack/ipv6_routing_table.h"

typedef struct buffer buffer_t;

void protocol_push(buffer_t *buf);
void protocol_core_init(void);

#define INTERFACE_BOOTSTRAP_DEFINED     1
#define INTERFACE_SECURITY_DEFINED      2

#define INTERFACE_SETUP_MASK        3
#define INTERFACE_SETUP_READY       3

#define INTERFACE_NWK_BOOTSTRAP_ACTIVE                   2
#define INTERFACE_NWK_ACTIVE                             8
#define INTERFACE_NWK_ROUTER_DEVICE                     16
#define INTERFACE_NWK_CONF_MAC_RX_OFF_IDLE              64

typedef enum multicast_mpl_seed_id_mode {
    MULTICAST_MPL_SEED_ID_DEFAULT = -256,               /** Default selection (used to make a domain use the interface's default) */
    MULTICAST_MPL_SEED_ID_MAC_SHORT = -1,               /** Use short MAC address if available (eg IEEE 802.15.4 interface's macShortAddress (16-bit)), else full MAC */
    MULTICAST_MPL_SEED_ID_MAC = -2,                     /** Use MAC padded to 64-bit (eg IEEE 802.15.4 interface's macExtendedAddress, or 48-bit Ethernet MAC followed by 2 zero pad bytes) */
    MULTICAST_MPL_SEED_ID_IID_EUI64 = -3,               /** Use 64-bit IPv6 IID based on EUI-64 (eg 02:11:22:ff:fe:00:00:00 for an Ethernet interface with MAC 00:11:22:00:00:00) */
    MULTICAST_MPL_SEED_ID_IID_SLAAC = -4,               /** Use 64-bit IPv6 IID that would be used for SLAAC */
    MULTICAST_MPL_SEED_ID_IPV6_SRC_FOR_DOMAIN = 0,      /** Use IPv6 source address selection to choose 128-bit Seed ID based on MPL Domain Address as destination */
    MULTICAST_MPL_SEED_ID_16_BIT = 2,                   /** Use a manually-specified 16-bit ID */
    MULTICAST_MPL_SEED_ID_64_BIT = 8,                   /** Use a manually-specified 64-bit ID */
    MULTICAST_MPL_SEED_ID_128_BIT = 16,                 /** Use a manually-specified 128-bit ID */
} multicast_mpl_seed_id_mode_e;

typedef struct arm_15_4_mac_parameters {
    uint16_t mtu;
    /* Security API USE */
    uint8_t mac_default_ffn_key_index;
    uint8_t mac_default_lfn_key_index;
} arm_15_4_mac_parameters_t;

struct net_if {
    int8_t id;
    uint8_t zone_index[16];
    ns_list_link_t link;
    uint8_t configure_flags;
    uint8_t lowpan_info;
    if_address_list_t ip_addresses;
    if_group_list_t ip_groups;
    multicast_mpl_seed_id_mode_e mpl_seed_id_mode;
    trickle_params_t mpl_data_trickle_params;
    uint16_t mpl_seed_set_entry_lifetime;
    uint8_t mpl_seed_id[16];
    struct mpl_domain *mpl_domain;
    lowpan_context_list_t lowpan_contexts;
    ipv6_neighbour_cache_t ipv6_neighbour_cache;

    uint16_t icmp_tokens; /* Token bucket for ICMP rate limiting */
    bool pan_advert_running: 1;
    bool pan_config_running: 1;
    /* RFC 4861 Host Variables */
    uint8_t cur_hop_limit;
    uint16_t reachable_time_ttl;        // s
    uint32_t base_reachable_time;       // ms
    bool mpl_seed: 1;

    uint8_t mac[8];
    uint8_t iid_eui64[8];
    uint8_t iid_slaac[8];

    struct red_config random_early_detection;
    struct red_config llc_random_early_detection;
    struct red_config *llc_eapol_random_early_detection;
    struct ws_info ws_info;

    struct rcp *rcp;
    arm_15_4_mac_parameters_t mac_parameters;

    void (*if_stack_buffer_handler)(buffer_t *);
    void (*if_common_forwarding_out_cb)(struct net_if *, buffer_t *);
    bool (*if_ns_transmit)(struct net_if *cur, ipv6_neighbour_t *neighCacheEntry, bool unicast, uint8_t seq);
    bool (*if_map_ip_to_link_addr)(struct net_if *cur, const uint8_t *ip_addr, enum addrtype *ll_type, const uint8_t **ll_addr_out);
    buffer_t *(*if_special_forwarding)(struct net_if *cur, buffer_t *buf, const sockaddr_t *ll_src, bool *bounce);
    buffer_t *(*if_snoop)(struct net_if *cur, buffer_t *buf, const sockaddr_t *ll_dst, const sockaddr_t *ll_src, bool *bounce);
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
