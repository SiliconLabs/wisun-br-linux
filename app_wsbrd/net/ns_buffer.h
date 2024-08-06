/*
 * Copyright (c) 2008-2021, Pelion and affiliates.
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
 * \file buffer.h
 * \brief buffer type definitions.
 *
 *  nanoStack: buffer carrier structure.
 *
 */


#ifndef _NS_BUFFER_H
#define _NS_BUFFER_H


#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "common/int24.h"
#include "common/ns_list.h"

#include "net/netaddr_types.h"
#include "ipv6/ipv6_routing_table.h"

#ifndef BUFFERS_MAX
#define BUFFERS_MAX 10
#endif

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 128
#endif

#ifndef ACK_BUFFER_SIZE
#define ACK_BUFFER_SIZE 5
#endif

/*
 * headroom given to buffers by default.
 * if buffer value is below 107 bytes then remaining value is allocated as headroom.
 */
#define BUFFER_DEFAULT_HEADROOM     40

/*
 * default minimum size for buffers.
 * if size is below this then extra space is allocated as headroom.
 */
#define BUFFER_DEFAULT_MIN_SIZE     127

/* The new, really-configurable default hop limit (RFC 4861 CurHopLimit);
 * this can be overridden at compile-time, or changed on a per-socket basis
 * with socket_setsockopt. It can also be overridden by Router Advertisements.
 */
#ifndef UNICAST_HOP_LIMIT_DEFAULT
#define UNICAST_HOP_LIMIT_DEFAULT 64
#endif

/** link-specific buffer data */
typedef struct buffer_link_ieee802_15_4 {
    bool fc_security: 1;            // Security Enabled flag from frame control
    bool requestAck: 1;
    uint16_t srcPanId;
    uint16_t dstPanId;
} buffer_link_ieee802_15_4_t;

typedef union buffer_link_info {
    buffer_link_ieee802_15_4_t ieee802_15_4;
} buffer_link_info_t;

/* Flags to indicate presence of extension headers in _current_ IP layer */
/* Placed as a non-bitfield in ip_extflags so that IP core can bulk clear */
#define IPEXT_HBH_RPL           0x01    /*!< RPL hop-by-hop option */
#define IPEXT_SRH_RPL           0x02    /*!< RPL Routing Header */
#define IPEXT_HBH_ROUTER_ALERT  0x04    /*!< Router alert */
#define IPEXT_HBH_MPL           0x08    /*!< MPL hop-by-hop option */
#define IPEXT_HBH_MPL_UNFILLED  0x10    /*!< MPL option is unfilled */
#define IPEXT_FRAGMENT          0x20    /*!< Fragment header present - if set on entry to IP parsing this was reassembled packet */

/** buffer option fields */
typedef struct buffer_options {
    uint8_t hop_limit;                  /*!< IPv6 hop limit */
    uint8_t type;                       /*!< ICMP type, IP next header, MAC frame type... */
    uint8_t code;                       /*!< ICMP code, TCP flags, MAC ack request... */
    uint8_t ip_extflags;                /*!< IPv6 extension header flags */
    bool    ll_security_bypass_rx: 1;   /*!< Was received without link-layer security, when security was enabled */
    bool    ll_broadcast_rx: 1;         /*!< Was received as link-layer broadcast */
    bool    tunnelled: 1;               /*!< We tunnelled it as part of (RPL?) routing */
    bool    lfn_multicast: 1;           /*!< Buffer contain multicast data for LFN */
    bool    mpl_permitted: 1;           /*!< MPL will be used if enabled on interface and scope >=3 */
    signed  ipv6_use_min_mtu: 2;        /*!< Use minimum 1280-byte MTU (RFC 3542) - three settings +1, 0, -1 */
    uint8_t traffic_class;              /*!< Traffic class */
    int24_t flow_label;                 /*!< IPv6 flow label; -1 means unspecified (may auto-generate); -2 means auto-generate required */
    bool    mpl_fwd_workaround;         // force tunneling for packets arriving at TUN with dst ff03::fc
} buffer_options_t;

#define IPV6_FLOW_UNSPECIFIED (-1)
#define IPV6_FLOW_AUTOGENERATE (-2)

typedef enum {
    B_TO_NONE           = 0x0000,
    B_TO_MAC            = 0x0001,
    B_TO_IPV6           = 0x0002,
    B_TO_UDP            = 0x0003,
    B_TO_ICMP           = 0x0004,
    B_TO_NAP            = 0x0005,
    B_TO_FRAGMENTATION  = 0x0006,
    B_TO_TCP            = 0x0007,
    B_TO_MLME           = 0x0008,
    B_TO_IPV6_TXRX      = 0x0009,
    B_TO_DNSSD          = 0x000A,
    B_TO_IPV6_FWD       = 0x000B,
    B_TO_TLS            = 0x000C,
    B_TO_MESH_ROUTING   = 0x000D,
    B_TO_PHY            = 0x000E,
    B_TO_APP            = 0x000F,
    B_TO_MASK           = 0x000F,
    B_FROM_NONE         = 0x0000,
    B_FROM_MAC          = 0x0010,
    B_FROM_IPV6         = 0x0020,
    B_FROM_UDP          = 0x0030,
    B_FROM_ICMP         = 0x0040,
    B_FROM_NAP          = 0x0050,
    B_FROM_FRAGMENTATION = 0x0060,
    B_FROM_TCP          = 0x0070,
    B_FROM_MLME         = 0x0080,
    B_FROM_IPV6_TXRX    = 0x0090,
    B_FROM_DNSSD        = 0x00A0,
    B_FROM_IPV6_FWD     = 0x00B0,
    B_FROM_LOCAL        = 0x00C0,
    B_FROM_MESH_ROUTING = 0x00D0,
    B_FROM_APP          = 0x00F0,
    B_FROM_MASK         = 0x00F0,
    B_DIR_DOWN          = 0x0000,
    B_DIR_UP            = 0x0800,
    B_DIR_MASK          = 0x0800,
} buffer_info_t;

#define B_TO_MAC_MLME_MASK (B_DIR_MASK + B_FROM_MASK + B_TO_MASK )
#define B_TO_MAC_FROM_MAC (B_DIR_UP + B_FROM_MAC + B_TO_MAC )

struct socket;

typedef struct buffer_routing_info {
    ipv6_route_info_t   route_info;
    const uint8_t       *ip_dest;
    uint8_t             ref_count;
} buffer_routing_info_t;

/** buffer structure */
/* If adding pointers to this, ensure buffer_free and buffer_copy_metadata are informed */
typedef struct buffer {
    ns_list_link_t      link;
    sockaddr_t          dst_sa;                 /*!< Destination sockaddr */
    sockaddr_t          src_sa;                 /*!< Source sockaddr */
    struct net_if *interface; /*!< Pointer to interface */
    buffer_info_t       info;                   /*!< Protocol information */
    uint8_t             seq;                    /*!< Packet MAC header sequence number */
    uint16_t            buf_ptr;                /*!< Current pointer in the buffer */
    uint16_t            buf_end;                /*!< End pointer in the buffer */
    uint16_t            size;                   /*!< Buffer size */
    uint16_t            offset;                 /*!< Offset indicator (used in some upward paths) */
    bool                ip_routed_up: 1;
    uint32_t            adaptation_timestamp;   /*!< Timestamp when buffer pushed to adaptation interface. Unit 100ms */
    buffer_link_info_t  link_specific;
    uint16_t            mpl_option_data_offset;
    buffer_options_t    options;                /*!< Additional signal info etc */
    buffer_routing_info_t *route;               /* A pointer last to try to get neat alignment for data */
    uint8_t             buf[];                  /*!< Trailing buffer data */
} buffer_t;

typedef NS_LIST_HEAD(buffer_t, link) buffer_list_t;
static_assert(offsetof(buffer_t, link) == 0, "Some use NS_LIST_HEAD_INCOMPLETE");

#define SYST_WDCLEAR    0xff
#define SYST_TX_TO      0xfe

#define buffer_data_pointer_after_adjustment(x) buffer_corrupt_check(x)

/** Allocate memory for a buffer_t from the heap */
buffer_t *buffer_get(uint16_t size);

/** Allocate memory for a buffer_t from the heap, with more detailed sizing */
buffer_t *buffer_get_specific(uint16_t headroom, uint16_t size, uint16_t minspace);

/** Allocate memory for a minimal buffer (no headroom or extra space) */
buffer_t *buffer_get_minimal(uint16_t size);

/** Free a buffer from the heap, and return NULL */
buffer_t *buffer_free(buffer_t *buf);

/** Free a linked buffer list from the heap */
void buffer_free_list(buffer_list_t *list);

/** Free any routing info in the buffer, returning the buffer pointer */
buffer_t *buffer_free_route(buffer_t *buf);

/** Check for corrupt buffers should only be used when testing.*/
uint8_t *buffer_corrupt_check(buffer_t *buf);

/** Allocate header space in buffer */
buffer_t *buffer_headroom(buffer_t *buf, uint16_t size);

/** Add buffer at the end of current buffer.
 * Modifies all pointer and indexes correctly.
 *
 */
void buffer_data_add(buffer_t *buf, const uint8_t *data_ptr, uint16_t data_len);

/** create new buffer and copy all fields and data
 *
 *  Notice that data can have different headroom reserved. so the actual data might
 *  be located in different part of buffer than in original.*/
buffer_t *buffer_clone(buffer_t *buf);

/** prepare an input buffer to become a response - clear unwanted metadata */
buffer_t *buffer_turnaround(buffer_t *buf);

/** copy metadata from src to dst - see definition for more info */
void buffer_copy_metadata(buffer_t *dst, buffer_t *src, bool non_clonable_to_dst);

/** get pointer to data*/
#define buffer_data_pointer(x)  (&(x)->buf[(x)->buf_ptr])

/** get pointer to end of data*/
#define buffer_data_end(x)  (&(x)->buf[(x)->buf_end])

/** get pointer to data*/
#define buffer_data_pointer_set(x,new_start_ptr)  ((x)->buf_ptr = (new_start_ptr) - (x)->buf)

/** get pointer to end of data*/
#define buffer_data_end_set(x,new_end_ptr)     do {\
        ((x)->buf_end = (new_end_ptr) - (x)->buf);\
        buffer_corrupt_check(x);\
        } while(0)

/** get data length*/
#define buffer_data_length(x)  (int)(x->buf_end - x->buf_ptr)

/** get data length Set*/
#define buffer_data_length_set(x,z)  ((x)->buf_end = (x)->buf_ptr + (z))

/** free data bytes in buffer */
#define buffer_data_free_length(x)  ((x)->size - (x)->buf_end)

/** Clears buffer to initial value
 * uint8_t *buffer_data_clear(buffer_t *x)
 * */
#define buffer_data_clear(x) ((x)->buf_ptr = (x)->buf_end = BUFFER_DEFAULT_HEADROOM, buffer_data_pointer_after_adjustment(x))

/** Clears buffer and sets the headroom */
#define buffer_data_clear_with_headroom(x,z)  ((x)->buf_ptr = (x)->buf_end = (z))

/** Removes z amount of bytes from the begining of buffer
 * uint8_t *buffer_data_strip_header(buffer_t *x, uint16_t z)
 * */
static inline uint8_t *buffer_data_strip_header(buffer_t *x, uint16_t z)
{
    x->buf_ptr += z;
    return buffer_data_pointer_after_adjustment(x);
}

/** Adds z amount of bytes to the begining of buffer check if this is allowed using buffer_headroom method.
 * uint8_t *buffer_data_reserve_header(buffer_t *x, uint16_t z)
 * */
static inline uint8_t *buffer_data_reserve_header(buffer_t *x, uint16_t z)
{
    x->buf_ptr -= z;
    return buffer_data_pointer_after_adjustment(x);
}

#endif
