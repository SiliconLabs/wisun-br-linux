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
 * \file ns_address_internal.c
 * \brief Utility functions concerning addresses
 *
 * This file contains all the utility functions that can be used to
 * check, manipulate etc. addresses.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "common/endian.h"
#include "common/log.h"
#include "common/memutils.h"
#include "common/rand.h"
#include "common/bits.h"
#include "common/string_extra.h"
#include "common/log_legacy.h"
#include "common/string_extra.h"

#include "common/specs/ipv6.h"

#include "net/protocol.h"

#define TRACE_GROUP "addr"

typedef struct addr_policy_table_entry {
    uint8_t prefix[16];
    uint8_t prefix_len;
    uint8_t precedence;
    uint8_t label;
    ns_list_link_t link;
} addr_policy_table_entry_t;

static NS_LIST_DEFINE(addr_policy_table, addr_policy_table_entry_t, link);

uint32_t addr_preferences_default = SOCKET_IPV6_PREFER_SRC_TMP | SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT;

static void addr_policy_table_reset(void);
static struct if_group_entry *addr_get_group_entry(const struct net_if *interface, const uint8_t group[16]);

static bool addr_am_implicit_group_member(const uint8_t group[16])
{
    static const uint8_t *const implicit_groups[] = {
        ADDR_LINK_LOCAL_ALL_NODES,
        ADDR_IF_LOCAL_ALL_NODES,
    };

    for (uint8_t i = 0; i < sizeof implicit_groups / sizeof implicit_groups[0]; i++) {
        if (addr_ipv6_equal(implicit_groups[i], group)) {
            return true;
        }
    }
    return false;
}

uint8_t addr_len_from_type(addrtype_e addr_type)
{
    switch (addr_type) {
        case ADDR_NONE:
            return 0;
        case ADDR_802_15_4_SHORT:
            return 2 + 2; /* Some users don't have the PAN ID */
        case ADDR_802_15_4_LONG:
            return 2 + 8;
        case ADDR_EUI_48:
            return 6;
        case ADDR_IPV6:
            return 16;
        case ADDR_BROADCAST:
            return 0; /* Don't really handle this */
    }
    return 0;
}

/**
 * Check if an address is a broadcast address
 *
 * \param addr pointer to an address_t containing the address to be checked
 * \param addr_type the type of the address_t
 * \return 0 if the address is a broadcast address
 */
uint8_t addr_check_broadcast(const address_t addr, addrtype_e addr_type)
{
    switch (addr_type) {
        case ADDR_802_15_4_SHORT:
            break;
        case ADDR_BROADCAST:
            return 0;
        default:
            return 1;
    }

    uint8_t size = 2;
    uint8_t *ptr = (uint8_t *) addr;
    ptr += 2;

    while (size) {
        if ((*ptr++) != 0xFF) {
            break;
        } else {
            size--;
        }
    }
    return (size);

}

bool addr_is_ipv6_link_local(const uint8_t addr[16])
{
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80;
}

bool addr_is_ipv6_unspecified(const uint8_t addr[16])
{
    return !memzcmp(addr, 16);
}

bool addr_is_ipv6_loopback(const uint8_t addr[16])
{
    return !memcmp(addr, ADDR_LOOPBACK, 16);
}

bool addr_is_ipv6_multicast(const uint8_t addr[16])
{
    return addr[0] == 0xFF;
}

/* Site-local addresses deprecated, but still processed by RFC 6724 address selection */
static bool addr_is_ipv6_site_local(const uint8_t addr[16])
{
    return addr[0] == 0xfe && (addr[1] & 0xc0) == 0xc0;
}

static bool addr_is_ipv4_mapped(const uint8_t addr[16])
{
    return memcmp(addr, ADDR_IPV4_MAPPED_PREFIX, 12) == 0;
}

/* Scope(A), as defined in RFC 6724 plus RFC 4007 */
uint8_t addr_ipv6_scope(const uint8_t addr[16])
{
    if (addr_is_ipv6_multicast(addr)) {
        return addr_ipv6_multicast_scope(addr);
    }
    if (addr_is_ipv6_link_local(addr) || addr_is_ipv6_loopback(addr)) {
        return IPV6_SCOPE_LINK_LOCAL;
    }
    if (addr_is_ipv6_site_local(addr)) {
        return IPV6_SCOPE_SITE_LOCAL;
    }
    if (addr_is_ipv4_mapped(addr)) {
        if ((addr[12] == 169 && addr[13] == 254) || addr[12] == 127) {
            return IPV6_SCOPE_LINK_LOCAL;
        }
        return IPV6_SCOPE_GLOBAL;
    }
    return IPV6_SCOPE_GLOBAL;
}

uint8_t addr_ipv6_multicast_scope(const uint8_t addr[16])
{
    return addr[1] & 0x0F;
}

void address_module_init(void)
{
    addr_policy_table_reset();
    //mac_reset_short_address();
}

static int_fast8_t addr_policy_table_add_entry(const char *_netmask, uint8_t precedence, uint8_t label)
{
    addr_policy_table_entry_t *entry = zalloc(sizeof(addr_policy_table_entry_t));
    char *netmask = strdupa(_netmask);
    char *ptr = strchrnul(netmask, '/');
    uint8_t len = strtol(ptr + 1, NULL, 10);
    struct in6_addr prefix;

    BUG_ON(!*ptr);
    *ptr = '\x00';
    inet_pton(AF_INET6, netmask, &prefix);

    memcpy(entry->prefix, prefix.s6_addr, sizeof(entry->prefix));
    entry->prefix_len = len;
    entry->precedence = precedence;
    entry->label = label;

    /* Table is sorted longest-prefix-first, for longest-match searching */
    bool inserted = false;
    ns_list_foreach(addr_policy_table_entry_t, before, &addr_policy_table) {
        if (before->prefix_len > len) {
            continue;
        }
        if (before->prefix_len == len && !bitcmp(before->prefix, entry->prefix, len)) {
            free(entry);
            return -2;
        }
        ns_list_add_before(&addr_policy_table, before, entry);
        inserted = true;
        break;
    }

    if (!inserted) {
        ns_list_add_to_end(&addr_policy_table, entry);
    }

    return 0;
}

/// @TODO do we need this test print anymore ?
void addr_policy_table_print(void)
{
    ns_list_foreach(addr_policy_table_entry_t, entry, &addr_policy_table)
        tr_debug("%3d %3d %s", entry->precedence, entry->label,
                 tr_ipv6_prefix(entry->prefix, entry->prefix_len));
}

static void addr_policy_table_reset(void)
{
    ns_list_foreach_safe(addr_policy_table_entry_t, entry, &addr_policy_table) {
        ns_list_remove(&addr_policy_table, entry);
        free(entry);
    }

    /* Default policy table from RFC 6724 section 10.7 */
    addr_policy_table_add_entry("::1/128",       50,  0);
    addr_policy_table_add_entry("::/0",          40,  1);
    addr_policy_table_add_entry("::ffff:0:0/96", 35,  4);
    addr_policy_table_add_entry("2002::/16",     30,  2);
    addr_policy_table_add_entry("2001::/32",      5,  5);
    addr_policy_table_add_entry("fc00::/7",       3, 13);
    addr_policy_table_add_entry("::/96",          1,  3);
    addr_policy_table_add_entry("fec0::/10",      1, 11);
    addr_policy_table_add_entry("3ffe::/16",      1, 12);
    //addr_policy_table_print();
}

static const addr_policy_table_entry_t *addr_get_policy(const uint8_t addr[16])
{
    ns_list_foreach(const addr_policy_table_entry_t, entry, &addr_policy_table)
        if (!bitcmp(entry->prefix, addr, entry->prefix_len))
            return entry;

    /* Shouldn't happen - should always have a default entry */
    BUG();
}

/* RFC 6724 CommonPrefixLen(S, D) */
static uint8_t addr_common_prefix_len(const uint8_t src[16], uint8_t src_prefix_len, const uint8_t dst[16])
{
    uint8_t i = 0;

    while (i < src_prefix_len) {
        if (bittest(src, i) != bittest(dst, i))
            return i;
        i++;
    }
    return i;
}

static if_address_entry_t *addr_get_entry(const struct net_if *interface, const uint8_t addr[16])
{
    ns_list_foreach(if_address_entry_t, entry, &interface->ip_addresses) {
        if (addr_ipv6_equal(entry->address, addr)) {
            return entry;
        }
    }

    return NULL;
}

bool addr_is_assigned_to_interface(const struct net_if *interface, const uint8_t addr[16])
{
    if_address_entry_t *entry = addr_get_entry(interface, addr);

    return entry;
}

if_group_entry_t *addr_add_group(struct net_if *interface, const uint8_t group[16])
{
    if_group_entry_t *entry = addr_get_group_entry(interface, group);
    if (entry) {
        if (entry->ref_count != 0xFFFF) {
            entry->ref_count++;
        }
        return entry;
    }

    if (!addr_is_ipv6_multicast(group)) {
        return NULL;
    }

    if (addr_am_implicit_group_member(group)) {
        return NULL;
    }

    entry = malloc(sizeof(if_group_entry_t));
    if (!entry) {
        return NULL;
    }
    memcpy(entry->group, group, 16);
    entry->ref_count = 1;
    ns_list_add_to_end(&interface->ip_groups, entry);

    return entry;
}

/* This does NOT reference count - it actually deletes the entry */
static void addr_delete_group_entry(struct net_if *interface, if_group_entry_t *entry)
{
    ns_list_remove(&interface->ip_groups, entry);
    free(entry);
}

/* This does reference count */
void addr_remove_group(struct net_if *interface, const uint8_t group[16])
{
    if_group_entry_t *entry = addr_get_group_entry(interface, group);
    if (entry) {
        if (entry->ref_count != 0xFFFF) {
            if (--entry->ref_count == 0) {
                addr_delete_group_entry(interface, entry);
            }
        }
    }
}

static if_group_entry_t *addr_get_group_entry(const struct net_if *interface, const uint8_t group[16])
{
    ns_list_foreach(if_group_entry_t, entry, &interface->ip_groups) {
        if (addr_ipv6_equal(entry->group, group)) {
            return entry;
        }
    }

    return NULL;
}

void addr_add_router_groups(struct net_if *interface)
{
    /* The standard IPv6 ones, but not "Realm-Local-All-Routers"
     * which is ZigBee IP / Thread-specific (and not IANA registered)
     */
    addr_add_group(interface, ADDR_IF_LOCAL_ALL_ROUTERS);
    addr_add_group(interface, ADDR_LINK_LOCAL_ALL_ROUTERS);

    /* We only want to join the site address on one interface per site zone,
     * or we'd get multiple copies of packets. Exit if we're already a member.
     */
    ns_list_foreach(struct net_if, i, &protocol_interface_info_list) {
        if (i->zone_index[IPV6_SCOPE_SITE_LOCAL] == interface->zone_index[IPV6_SCOPE_SITE_LOCAL] &&
                addr_get_group_entry(i, ADDR_SITE_LOCAL_ALL_ROUTERS)) {
            return;
        }
    }
    addr_add_group(interface, ADDR_SITE_LOCAL_ALL_ROUTERS);
}

bool addr_am_group_member_on_interface(const struct net_if *interface, const uint8_t group[16])
{
    return addr_am_implicit_group_member(group) || addr_get_group_entry(interface, group);
}

/* RFC 6724 Default source address selection */
const uint8_t *addr_select_source(struct net_if *interface, const uint8_t dest[16], uint32_t addr_preferences)
{
    /* Let's call existing preferred address "SA" and new candidate "SB", to
     * make it look like a bit like RFC 6724
     */
    if_address_entry_t *SA = NULL;
    uint8_t scope_D = addr_ipv6_scope(dest);
    const addr_policy_table_entry_t *policy_D = addr_get_policy(dest);

    if (addr_preferences == 0) {
        addr_preferences = addr_preferences_default;
    }

    /*
     * As we go around the loop, if we prefer the new "SB", we set SA to SB
     * and continue. If we decide we prefer the existing SA, we just continue.
     *
     * Careful with these macros - they must only be used with if/else, and
     * inside { }, as per the coding style rules.
     */
#define PREFER_SA continue
#define PREFER_SB SA = SB; continue

    ns_list_foreach(if_address_entry_t, SB, &interface->ip_addresses) {
        /* First (non-tentative) address seen becomes SA */
        if (!SA) {
            PREFER_SB;
        }

        /* Rule 1: Prefer same address */
        if (memcmp(SB->address, dest, 16) == 0) {
            SA = SB;
            /* It's an exact match, no point checking any other addresses */
            break;
        }

        /* Rule 2: Prefer appropriate scope */
        uint8_t scope_SA = addr_ipv6_scope(SA->address);
        uint8_t scope_SB = addr_ipv6_scope(SB->address);
        if (scope_SA < scope_SB) {
            if (scope_SA < scope_D) {
                PREFER_SB;
            } else {
                PREFER_SA;
            }
        } else if (scope_SB < scope_SA) {
            if (scope_SB < scope_D) {
                PREFER_SA;
            } else {
                PREFER_SB;
            }
        }

        /* (Rule 4: Prefer home addresses - Mobile IPv6 not implemented) */
        /* (Rule 5: Prefer outgoing interface - candidate set already limited) */
        /* (Rule 5.5: Prefer addresses in a prefix advertised by the next-hop - we don't track this information) */

        /* Rule 6: Prefer matching label */
        const addr_policy_table_entry_t *policy_SA = addr_get_policy(SA->address);
        const addr_policy_table_entry_t *policy_SB = addr_get_policy(SB->address);
        if (policy_SA->label == policy_D->label && policy_SB->label != policy_D->label) {
            PREFER_SA;
        } else if (policy_SB->label == policy_D->label && policy_SA->label != policy_D->label) {
            PREFER_SB;
        }

        /* Rule 8: Use longest matching prefix */
        uint8_t common_SA = addr_common_prefix_len(SA->address, SA->prefix_len, dest);
        uint8_t common_SB = addr_common_prefix_len(SB->address, SB->prefix_len, dest);
        if (common_SA > common_SB) {
            PREFER_SA;
        } else if (common_SB > common_SA) {
            PREFER_SB;
        }

        /* A tie-breaker: Prefer 6LoWPAN short address (or the opposite) */
        bool short_SA = SA->prefix_len == 64 && memcmp(SA->address + 8, ADDR_SHORT_ADDR_SUFFIX, 6) == 0;
        bool short_SB = SB->prefix_len == 64 && memcmp(SB->address + 8, ADDR_SHORT_ADDR_SUFFIX, 6) == 0;
        if (short_SA != short_SB) {
            bool prefer_short = (addr_preferences & SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT);

            if (short_SA == prefer_short) {
                PREFER_SA;
            } else {
                PREFER_SB;
            }
        }

        /* Rule 9 select most precated one  */
        if (policy_SA->precedence > policy_SB->precedence) {
            PREFER_SA;
        } else if (policy_SB->precedence > policy_SA->precedence) {
            PREFER_SB;
        }

        /* Tie */
        PREFER_SA;
    }

    return SA ? SA->address : NULL;
}

/* A variant of RFC 6724 Default source address selection, to select an address
 * on an interface with a specific prefix. The prefix must match, and some
 * source address rules don't apply, but some are handled similarly. See
 * comments in addr_select_source.
 */
const uint8_t *addr_select_with_prefix(struct net_if *cur, const uint8_t *prefix, uint8_t prefix_len, uint32_t addr_preferences)
{
    if_address_entry_t *SA = NULL;

    if (addr_preferences == 0) {
        addr_preferences = addr_preferences_default;
    }

    ns_list_foreach(if_address_entry_t, SB, &cur->ip_addresses) {
        /* Prefix must match */
        if (bitcmp(SB->address, prefix, prefix_len)) {
            continue;
        }

        /* First (non-tentative, matching prefix) address seen becomes SA */
        if (!SA) {
            PREFER_SB;
        }

        /* (Rule 1: Prefer same address - doesn't apply here) */
        /* Rule 2: Was prefer appropriate scope - for this purpose we instead prefer wider scope */
        uint8_t scope_SA = addr_ipv6_scope(SA->address);
        uint8_t scope_SB = addr_ipv6_scope(SB->address);
        if (scope_SA < scope_SB) {
            PREFER_SB;
        } else if (scope_SB < scope_SA) {
            PREFER_SA;
        }

        /* (Rule 4: Prefer home addresses - Mobile IPv6 not implemented) */
        /* (Rule 5: Prefer outgoing interface - candidate set already limited) */
        /* (Rule 5.5: Prefer addresses in a prefix advertised by the next-hop - we don't track this information) */

        /* Rule 6: Prefer matching label - doesn't apply here. But instead,
         * let's use precedence, like rule 6 of destination selection.
         */
        const addr_policy_table_entry_t *policy_SA = addr_get_policy(SA->address);
        const addr_policy_table_entry_t *policy_SB = addr_get_policy(SB->address);
        if (policy_SA->precedence > policy_SB->precedence) {
            PREFER_SA;
        } else if (policy_SB->precedence > policy_SA->precedence) {
            PREFER_SB;
        }

        /* (Rule 8: Use longest matching prefix - doesn't apply) */

        /* A tie-breaker: Prefer 6LoWPAN short address (or the opposite) */
        bool short_SA = SA->prefix_len == 64 && memcmp(SA->address + 8, ADDR_SHORT_ADDR_SUFFIX, 6) == 0;
        bool short_SB = SB->prefix_len == 64 && memcmp(SB->address + 8, ADDR_SHORT_ADDR_SUFFIX, 6) == 0;
        if (short_SA != short_SB) {
            bool prefer_short = (addr_preferences & SOCKET_IPV6_PREFER_SRC_6LOWPAN_SHORT);

            if (short_SA == prefer_short) {
                PREFER_SA;
            } else {
                PREFER_SB;
            }
        }

        /* Tie */
        PREFER_SA;
    }

    return SA ? SA->address : NULL;
}

#undef PREFER_SA
#undef PREFER_SB

if_address_entry_t *addr_add(struct net_if *cur, const uint8_t address[16], uint8_t prefix_len)
{
    if (addr_get_entry(cur, address)) {
        return NULL;
    }

    if_address_entry_t *entry = malloc(sizeof(if_address_entry_t));
    if (!entry) {
        return NULL;
    }

    memset(entry, 0, sizeof * entry);
    memcpy(entry->address, address, 16);
    entry->prefix_len = prefix_len;

    tr_info("Address added to IF %d: %s", cur->id, tr_ipv6(address));

    ns_list_add_to_end(&cur->ip_addresses, entry);
    return entry;
}

/* Optimised for quick discard of mismatching addresses (eg in a cache lookup):
 * searches BACKWARDS, as last bytes are most likely to differ.
 */
bool addr_ipv6_equal(const uint8_t a[16], const uint8_t b[16])
{
    for (int_fast8_t n = 15; n >= 0; n--) {
        if (a[n] != b[n]) {
            return false;
        }
    }
    return true;
}

bool addr_iid_matches_eui64(const uint8_t iid[8], const uint8_t eui64[8])
{
    for (int_fast8_t n = 7; n >= 1; n--) {
        if (iid[n] != eui64[n]) {
            return false;
        }
    }
    return iid[0] == (eui64[0] ^ 2);
}

/* Turn an address (either MAC or IP) into a base IP address for context compression */
bool addr_iid_from_outer(uint8_t iid_out[8], const sockaddr_t *addr_in)
{
    switch (addr_in->addr_type) {
        case ADDR_802_15_4_LONG:
            memcpy(iid_out, addr_in->address + 2, 8);
            iid_out[0] ^= 2;
            break;
        case ADDR_BROADCAST:
        case ADDR_802_15_4_SHORT:
            memcpy(iid_out, ADDR_SHORT_ADDR_SUFFIX, 6);
            iid_out[6] = addr_in->address[2];
            iid_out[7] = addr_in->address[3];
            break;
        case ADDR_IPV6:
            memcpy(iid_out, addr_in->address + 8, 8);
            break;
        default:
            return false;
    }

    return true;
}

int addr_interface_set_ll64(struct net_if *cur)
{
    int ret_val = -1;
    if_address_entry_t *address_entry = NULL;
    uint8_t temp_ll64[16];
    memcpy(temp_ll64, ADDR_LINK_LOCAL_PREFIX, 8);
    memcpy(temp_ll64 + 8, cur->iid_eui64, 8);

    address_entry = addr_add(cur, temp_ll64, 64);
    if (address_entry) {
        tr_debug("LL64 Register OK!");
        ret_val = 0;
    }
    return ret_val;
}

/* address_type 0 means "any" address - we return short by preference */
/* address_type 1 means long address - we ignore short addresses */
int8_t addr_interface_get_ll_address(struct net_if *cur, uint8_t *address_ptr, uint8_t address_type)
{
    const uint8_t *short_addr = NULL;
    const uint8_t *long_addr = NULL;

    if (!cur) {
        return -1;
    }

    ns_list_foreach(if_address_entry_t, e, &cur->ip_addresses) {
        if (addr_is_ipv6_link_local(e->address)) {
            if (memcmp(e->address + 8, ADDR_SHORT_ADDR_SUFFIX, 6) == 0) {
                short_addr = e->address;
            } else {
                long_addr = e->address;
            }

            if (long_addr && short_addr) {
                break;
            }
        }
    }

    if (short_addr && address_type != 1) {
        if (address_ptr) {
            memcpy(address_ptr, short_addr, 16);
        }
        return 0;
    } else if (long_addr) {
        if (address_ptr) {
            memcpy(address_ptr, long_addr, 16);
        }
        return 0;
    } else {
        return -1;
    }
}

int8_t addr_interface_address_compare(struct net_if *cur, const uint8_t *addr)
{
    /* First check the specified interface */
    if (addr_is_assigned_to_interface(cur, addr)) {
        return 0;
    }

    /* Then check other interfaces, enforcing scope zones */
    uint8_t scope = addr_ipv6_scope(addr);
    ns_list_foreach(struct net_if, other, &protocol_interface_info_list) {
        if (other != cur &&
                other->zone_index[scope] == cur->zone_index[scope] &&
                addr_is_assigned_to_interface(other, addr)) {
            return 0;
        }
    }

    return -1;
}

int8_t addr_interface_select_source(struct net_if *cur, uint8_t *src_ptr, const uint8_t *dest, uint32_t addr_preferences)
{
    int8_t ret_val = -1;
    if (cur) {
        const uint8_t *src = addr_select_source(cur, dest, addr_preferences);
        if (src) {
            memcpy(src_ptr, src, 16);
            ret_val = 0;
        }
    }
    return ret_val;
}

// This last function must always be compiled with tracing enabled
const char *trace_sockaddr(const sockaddr_t *addr, bool panid_prefix)
{
    uint8_t length = addr_len_from_type(addr->addr_type);

    if (length == 0) {
        return "<n/a>";
    }

    /* Awkward hack for 802.15.4 address types */
    if (addr->addr_type == ADDR_802_15_4_SHORT ||
            addr->addr_type == ADDR_802_15_4_LONG) {
        length -= (panid_prefix) ? 0 : 2;
    }

    /* Start from index 0 (prints PAN ID if exists) */
    return trace_array(&addr->address[0], length);
}
