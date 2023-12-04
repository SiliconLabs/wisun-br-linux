/*
 * Copyright (c) 2013-2018, 2020, Pelion and affiliates.
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
#ifndef _ICMPV6_H
#define _ICMPV6_H
#include <stdint.h>
#include <stdbool.h>

#include "common_protocols/icmpv6_prefix.h"

#define ICMPV6_TYPE_ERROR_DESTINATION_UNREACH       1
#define ICMPV6_TYPE_ERROR_PACKET_TOO_BIG            2
#define ICMPV6_TYPE_ERROR_TIME_EXCEEDED             3
#define ICMPV6_TYPE_ERROR_PARAMETER_PROBLEM         4

#define ICMPV6_TYPE_INFO_ECHO_REQUEST               128
#define ICMPV6_TYPE_INFO_ECHO_REPLY                 129
#define ICMPV6_TYPE_INFO_MCAST_LIST_QUERY           130
#define ICMPV6_TYPE_INFO_MCAST_LIST_REPORT          131
#define ICMPV6_TYPE_INFO_MCAST_LIST_DONE            132
#define ICMPV6_TYPE_INFO_RS                         133
#define ICMPV6_TYPE_INFO_RA                         134
#define ICMPV6_TYPE_INFO_NS                         135
#define ICMPV6_TYPE_INFO_NA                         136
#define ICMPV6_TYPE_INFO_REDIRECT                   137
#define ICMPV6_TYPE_INFO_MCAST_LIST_REPORT_V2       143
#define ICMPV6_TYPE_INFO_DAR                        157
#define ICMPV6_TYPE_INFO_DAC                        158
#define ICMPV6_TYPE_INFO_MPL_CONTROL                159

#define ICMPV6_CODE_DST_UNREACH_NO_ROUTE            0
#define ICMPV6_CODE_DST_UNREACH_ADM_PROHIB          1
#define ICMPV6_CODE_DST_UNREACH_BEYOND_SCOPE        2
#define ICMPV6_CODE_DST_UNREACH_ADDR_UNREACH        3
#define ICMPV6_CODE_DST_UNREACH_PORT_UNREACH        4
#define ICMPV6_CODE_DST_UNREACH_SRC_FAILED_POLICY   5
#define ICMPV6_CODE_DST_UNREACH_ROUTE_REJECTED      6

#define ICMPV6_CODE_TME_EXCD_HOP_LIM_EXCD           0
#define ICMPV6_CODE_TME_EXCD_FRG_REASS_TME_EXCD     1

#define ICMPV6_CODE_PARAM_PRB_HDR_ERR               0
#define ICMPV6_CODE_PARAM_PRB_UNREC_NEXT_HDR        1
#define ICMPV6_CODE_PARAM_PRB_UNREC_IPV6_OPT        2
#define ICMPV6_CODE_PARAM_PRB_FIRST_FRAG_IPV6_HDR   3

/* Options in ICMPv6 Neighbor Discovery Protocol (RPL has totally different options...) */
#define ICMPV6_OPT_SRC_LL_ADDR                      1
#define ICMPV6_OPT_TGT_LL_ADDR                      2
#define ICMPV6_OPT_PREFIX_INFO                      3
#define ICMPV6_OPT_REDIRECTED_HDR                   4
#define ICMPV6_OPT_MTU                              5
#define ICMPV6_OPT_ROUTE_INFO                       24
#define ICMPV6_OPT_RECURSIVE_DNS_SERVER             25
#define ICMPV6_OPT_DNS_SEARCH_LIST                  31
#define ICMPV6_OPT_ADDR_REGISTRATION                33
#define ICMPV6_OPT_6LOWPAN_CONTEXT                  34
#define ICMPV6_OPT_AUTHORITATIVE_BORDER_RTR         35

/* Neighbour Advertisement flags */
#define NA_R    0x80
#define NA_S    0x40
#define NA_O    0x20

/* Router Advertisement flags */
#define RA_M            0x80    // Managed
#define RA_O            0x40    // Other Configuration
#define RA_H            0x20    // Home Agent (RFC 6275)
#define RA_PRF_MASK     0x18    // Router Preference (RFC 4191)
#define RA_PRF_LOW      0x18    // (RA_PRF_xxx also occurs in Route Info Options)
#define RA_PRF_MEDIUM   0x00
#define RA_PRF_HIGH     0x08
#define RA_PRF_INVALID  0x10

struct buffer;
struct net_if;

struct ipv6_nd_opt_earo {
    uint16_t lifetime;
    uint8_t status;
    uint8_t opaque;
    uint8_t p: 2;
    uint8_t i: 2;
    bool    r: 1;
    bool    t: 1;
    uint8_t tid;
    uint8_t eui64[8];
    bool present;
};

#define ARO_SUCCESS     0
#define ARO_DUPLICATE   1
#define ARO_FULL        2
#define ARO_TOPOLOGICALLY_INCORRECT 8

#define IPV6_ND_OPT_EARO_FLAGS_P_MASK 0b00110000
#define IPV6_ND_OPT_EARO_FLAGS_I_MASK 0b00001100
#define IPV6_ND_OPT_EARO_FLAGS_R_MASK 0b00000010
#define IPV6_ND_OPT_EARO_FLAGS_T_MASK 0b00000001

#define IPV6_ND_OPT_EARO_FLAGS_P_UC 0 // Unused
#define IPV6_ND_OPT_EARO_FLAGS_P_MC 1
#define IPV6_ND_OPT_EARO_FLAGS_P_AN 2 // Unused

void icmpv6_init(void);
struct buffer *icmpv6_down(struct buffer *buf);
struct buffer *icmpv6_up(struct buffer *buf);
struct buffer *icmpv6_error(struct buffer *buf, struct net_if *cur, uint8_t type, uint8_t code, uint32_t aux);

const uint8_t *icmpv6_find_option_in_buffer(const struct buffer *buf, uint_fast16_t offset, uint8_t option);

struct net_if;

struct buffer *icmpv6_build_ns(struct net_if *cur, const uint8_t target_addr[static 16], const uint8_t *prompting_src_addr,
                               bool unicast, bool unspecified_source, const struct ipv6_nd_opt_earo *aro);
struct buffer *icmpv6_build_na(struct net_if *cur, bool solicited, bool override, bool tllao_required,
                               const uint8_t target[16], const struct ipv6_nd_opt_earo *earo,
                               const uint8_t src_addr[16]);

/*
 * Write either an ICMPv6 Prefix Information Option for a Router Advertisement
 * (RFC4861+6275), or an RPL Prefix Information Option (RFC6550).
 * Same payload, different type/len.
 */
uint8_t *icmpv6_write_icmp_lla(struct net_if *cur, uint8_t *dptr, uint8_t icmp_opt, bool must, const uint8_t *ip_addr);

#endif /* _ICMPV6_H */
