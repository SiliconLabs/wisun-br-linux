/*
 * Copyright (c) 2008, 2010-2020, Pelion and affiliates.
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
/**
 *
 * \file ns_address_internal.h
 * \brief address type definitions.
 *
 *  nanoStack: supported address types and associated data structures.
 *
 *
 */


#ifndef _NS_ADDRESS_H
#define _NS_ADDRESS_H
#include <stdbool.h>
#include "common/ns_list.h"

#include "netaddr_types.h"

#define ADDR_MULTICAST_MAX 3
#define PAN_ID_LEN 2

struct net_if;
struct if_address_entry;
struct socket;

/** \name Flags for SOCKET_IPV6_ADDR_PREFERENCES - opposites 16 bits apart. */
///@{
#define SOCKET_IPV6_PREFER_SRC_TMP              0x00000001 /**< Prefer temporary address (RFC 4941); default. */
#define SOCKET_IPV6_PREFER_SRC_PUBLIC           0x00010000 /**< Prefer public address (RFC 4941). */
#define SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT    0x00000100 /**< Prefer 6LoWPAN short address. */
#define SOCKET_IPV6_PREFER_SRC_6LOWPAN_LONG     0x01000000 /**< Prefer 6LoWPAN long address. */
///@}

typedef struct if_address_entry {
    uint8_t address[16];        // IPv6 (or IPv4-mapped IPv6 in future)
    uint8_t prefix_len;         // length of prefix part
    ns_list_link_t link;
} if_address_entry_t;

typedef NS_LIST_HEAD(if_address_entry_t, link) if_address_list_t;

/* Groups we are a member of on an interface */
typedef struct if_group_entry {
    uint8_t group[16];
    uint16_t ref_count;
    ns_list_link_t link;
} if_group_entry_t;

typedef NS_LIST_HEAD(if_group_entry_t, link) if_group_list_t;

extern uint32_t addr_preferences_default;   // default SOCKET_IPV6_ADDR_PREFERENCES

/** Functions provided by address.c */
uint8_t addr_check_broadcast(const address_t addr, addrtype_e addr_type);

void address_module_init(void);
struct if_address_entry *addr_add(struct net_if *cur, const uint8_t address[16], uint8_t prefix_len);

uint8_t addr_len_from_type(addrtype_e addr_type);
const char *trace_sockaddr(const sockaddr_t *addr, bool panid_prefix);

const uint8_t *addr_select_source(struct net_if *interface, const uint8_t dest[16], uint32_t addr_preferences);
const uint8_t *addr_select_with_prefix(struct net_if *cur, const uint8_t *prefix, uint8_t prefix_len, uint32_t addr_preferences);
int8_t addr_interface_select_source(struct net_if *cur, uint8_t *src_ptr, const uint8_t *dest, uint32_t addr_preferences);
bool addr_is_assigned_to_interface(const struct net_if *interface, const uint8_t addr[16]);

struct if_group_entry *addr_add_group(struct net_if *interface, const uint8_t group[16]);
void addr_remove_group(struct net_if *interface, const uint8_t group[16]);
bool addr_am_group_member_on_interface(const struct net_if *interface, const uint8_t group[16]);

void addr_add_router_groups(struct net_if *interface);

bool addr_is_ipv6_unspecified(const uint8_t addr[16]);
bool addr_is_ipv6_loopback(const uint8_t addr[16]);
bool addr_is_ipv6_link_local(const uint8_t addr[16]);
bool addr_is_ipv6_multicast(const uint8_t addr[16]);
uint8_t addr_ipv6_scope(const uint8_t addr[16]);
uint8_t addr_ipv6_multicast_scope(const uint8_t addr[16]);
bool addr_ipv6_equal(const uint8_t a[16], const uint8_t b[16]);
bool addr_iid_matches_eui64(const uint8_t iid[8], const uint8_t eui64[8]);
bool addr_iid_from_outer(uint8_t iid_out[8], const sockaddr_t *addr_in);

int addr_interface_set_ll64(struct net_if *cur);

/* address_type 0 means "any" address - we return short by preference */
/* address_type 1 means long address - we ignore short addresses */
int8_t addr_interface_get_ll_address(struct net_if *cur, uint8_t *address_ptr, uint8_t address_type);
int8_t addr_interface_address_compare(struct net_if *cur, const uint8_t *addr);
#endif /*_NS_ADDRESS_H*/
