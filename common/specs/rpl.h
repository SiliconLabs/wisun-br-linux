/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SPECS_RPL_H
#define SPECS_RPL_H
#include <netinet/in.h>

#include "common/endian.h"

// RFC 6550: RPL Control Codes
// https://www.iana.org/assignments/rpl/rpl.xhtml#control-codes
enum {
    RPL_CODE_DIS     = 0x00,
    RPL_CODE_DIO     = 0x01,
    RPL_CODE_DAO     = 0x02,
    RPL_CODE_DAO_ACK = 0x03,
};

// RFC 6550: Figure 19: RPL Option Generic Format
struct rpl_opt {
    uint8_t type;
    uint8_t len;
} __attribute__((packed));

// RFC 6550: RPL Control Message Options
// https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
enum {
    RPL_OPT_PAD1       = 0x00,
    RPL_OPT_PADN       = 0x01,
    RPL_OPT_METRICS    = 0x02,
    RPL_OPT_ROUTE      = 0x03,
    RPL_OPT_CONFIG     = 0x04,
    RPL_OPT_TARGET     = 0x05,
    RPL_OPT_TRANSIT    = 0x06,
    RPL_OPT_SOLICIT    = 0x07,
    RPL_OPT_PREFIX     = 0x08,
    RPL_OPT_DESCRIPTOR = 0x09,
};

// RFC 9008: "Mode of Operation"
// https://www.iana.org/assignments/rpl/rpl.xhtml#mop
enum {
    RPL_MOP_UPWARD        = 0,
    RPL_MOP_NON_STORING   = 1,
    RPL_MOP_STORING       = 2,
    RPL_MOP_STORING_MCAST = 3,
};

// RFC 6550: "Objective Code Point"
// https://www.iana.org/assignments/rpl/rpl.xhtml#ocp
enum {
    RPL_OCP_OF0   = 0,
    RPL_OCP_MRHOF = 1,
};

// RFC 6550 - Figure 13: The DIS Base Object
struct rpl_dis {
    uint8_t flags;
    uint8_t reserved;
} __attribute__((packed));

// RFC 6550 - Figure 14: The DIO Base Object
struct rpl_dio {
    uint8_t instance_id;
    uint8_t dodag_verno;
    be16_t  rank;
    uint8_t g_mop_prf;
#define RPL_MASK_DIO_G   0x80
#define RPL_MASK_DIO_MOP 0x38
#define RPL_MASK_DIO_PRF 0x07
    uint8_t dtsn;
    uint8_t flags;
    uint8_t reserved;
    struct in6_addr dodag_id;
} __attribute__((packed));

// RFC 6550 - Figure 16: The DAO Base Object
struct rpl_dao {
    uint8_t instance_id;
    uint8_t flags;
#define RPL_MASK_DAO_K 0x80
#define RPL_MASK_DAO_D 0x40
    uint8_t reserved;
    uint8_t dao_seq;
} __attribute__((packed));

// RFC 6550 - Figure 17: The DAO ACK Base Object
struct rpl_dao_ack {
    uint8_t instance_id;
    uint8_t flags;
#define RPL_MASK_DAO_ACK_D 0x80
    uint8_t dao_seq;
    uint8_t status;
} __attribute__((packed));

// RFC 6550 - Figure 24: Format of the DODAG Configuration Option
struct rpl_opt_config {
    uint8_t flags;
// https://www.iana.org/assignments/rpl/rpl.xhtml#dodag-config-option-flags
#define RPL_MASK_OPT_CONFIG_RPI 0x10
#define RPL_MASK_OPT_CONFIG_A   0x08
#define RPL_MASK_OPT_CONFIG_PCS 0x07
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

// RFC 6550 - Figure 25: Format of the RPL Target Option
struct rpl_opt_target {
    uint8_t flags;
    uint8_t prefix_len;
    struct in6_addr prefix;
} __attribute__((packed));

// RFC 6550 - Figure 26: Format of the Transit Information Option
struct rpl_opt_transit {
    uint8_t flags;
#define RPL_MASK_OPT_TRANSIT_E 0x80
    uint8_t path_ctl;
// RFC 6550 - Figure 27: Path Control Preference Subfield Encoding
#define RPL_MASK_PATH_CTL_PC1 0xc0
#define RPL_MASK_PATH_CTL_PC2 0x30
#define RPL_MASK_PATH_CTL_PC3 0x0c
#define RPL_MASK_PATH_CTL_PC4 0x03
    uint8_t path_seq;
    uint8_t path_lifetime;
    struct in6_addr parent_addr;
} __attribute__((packed));

// RFC 6550 - Figure 28: Format of the Solicited Information Option
struct rpl_opt_solicit {
    uint8_t instance_id;
    uint8_t flags;
#define RPL_MASK_OPT_SOLICIT_V 0x80
#define RPL_MASK_OPT_SOLICIT_I 0x40
#define RPL_MASK_OPT_SOLICIT_D 0x20
    struct in6_addr dodag_id;
    uint8_t dodag_verno;
} __attribute__((packed));

// RFC 6550 - Figure 29: Format of the Prefix Information Option
struct rpl_opt_prefix {
    uint8_t prefix_len;
    uint8_t flags;
#define RPL_MASK_OPT_PREFIX_L 0x80
#define RPL_MASK_OPT_PREFIX_A 0x40
#define RPL_MASK_OPT_PREFIX_R 0x20
    be32_t  lifetime_valid_s;
    be32_t  lifetime_preferred_s;
    be32_t  reserved2;
    struct in6_addr prefix;
} __attribute__((packed));

// RFC 6553 - Figure 1: RPL Option
struct rpl_rpi {
    uint8_t flags;
#define RPL_MASK_RPI_O 0x80
#define RPL_MASK_RPI_R 0x40
#define RPL_MASK_RPI_F 0x20
    uint8_t instance_id;
    be16_t  sender_rank;
} __attribute__((packed));

// RFC 6554 - 3. Format of the RPL Routing Header
#define RPL_MASK_SRH_CMPRI 0xf0000000
#define RPL_MASK_SRH_CMPRE 0x0f000000
#define RPL_MASK_SRH_PAD   0x00f00000

// RFC 6550 - 5.1. RPL Instance ID
#define RPL_MASK_INSTANCE_ID_TYPE 0x80
#define RPL_INSTANCE_ID_TYPE_GLOBAL 0
#define RPL_INSTANCE_ID_TYPE_LOCAL  1

#endif
