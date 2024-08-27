/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#ifndef RPL_PKT_H
#define RPL_PKT_H
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/endian.h"

// RFC 6550 Figure 13: The DIS Base Object
struct rpl_dis_base {
    uint8_t flags;
    uint8_t reserved;
} __attribute__((packed));

// RFC 6550 Figure 14: The DIO Base Object
struct rpl_dio_base {
    uint8_t instance_id;
    uint8_t dodag_verno;
    be16_t  rank;
    uint8_t g_mop_prf;
    uint8_t dtsn;
    uint8_t flags;
    uint8_t reserved;
    struct in6_addr dodag_id;
} __attribute__((packed));

// RFC 6550 Figure 16: The DAO Base Object
struct rpl_dao_base {
    uint8_t instance_id;
    uint8_t flags;
    uint8_t reserved;
    uint8_t dao_seq;
} __attribute__((packed));

// RFC 6550 Figure 17: The DAO ACK Base Object
struct rpl_dao_ack_base {
    uint8_t instance_id;
    uint8_t flags;
    uint8_t dao_seq;
    uint8_t status;
} __attribute__((packed));

// RFC 6550 Figure 19: RPL Option Generic Format
struct rpl_opt {
    uint8_t type;
    uint8_t len;
} __attribute__((packed));

// RFC 6550 Figure 24: Format of the DODAG Configuration Option
// https://www.iana.org/assignments/rpl/rpl.xhtml#dodag-config-option-flags
struct rpl_opt_config {
    uint8_t flags;
    uint8_t dio_i_doublings;
    uint8_t dio_i_min;
    uint8_t dio_redundancy;
    be16_t  max_rank_inc;
    be16_t  min_hop_rank_inc;
    be16_t  ocp; // Objective Code Point
    uint8_t reserved;
    uint8_t lifetime_default;
    be16_t  lifetime_unit_s;
} __attribute__((packed));

// RFC 6550 Figure 25: Format of the RPL Target Option
struct rpl_opt_target {
    uint8_t flags;
    uint8_t prefix_len;
    struct in6_addr prefix;
} __attribute__((packed));

// RFC 6550 Figure 26: Format of the Transit Information Option
struct rpl_opt_transit {
    uint8_t flags;
    uint8_t path_ctl;
    uint8_t path_seq;
    uint8_t path_lifetime;
    struct in6_addr parent_addr;
} __attribute__((packed));

// RFC 6550 Figure 29: Format of the Prefix Information Option
struct rpl_opt_prefix {
    uint8_t prefix_len;
    uint8_t flags;
    be32_t  lifetime_valid_s;
    be32_t  lifetime_preferred_s;
    be32_t  reserved2;
    struct in6_addr prefix;
} __attribute__((packed));

#endif
