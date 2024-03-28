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

/* Neighbour Advertisement flags */
#define NA_R    0x80
#define NA_S    0x40
#define NA_O    0x20

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

struct net_if;

struct buffer *icmpv6_build_ns(struct net_if *cur, const uint8_t target_addr[16], const uint8_t *prompting_src_addr,
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
