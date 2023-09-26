/*
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
#ifndef RPL_DEFS_H
#define RPL_DEFS_H

#include <sys/queue.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "rpl.h"

// RFC 6550 - 6. ICMPv6 RPL Control Message
#define ICMPV6_TYPE_RPL 155

// RFC 6550 - 20.18. ICMPv6: Error in Source Routing Header
#define ICMPV6_CODE_DST_UNREACH_SRH 7

// RFC 6554 - 3. Format of the RPL Routing Header
#define IPV6_EXTHDR_ROUTE_TYPE_RPL_SRH 3

// RFC 9008 - 11.1. Option Type in RPL Option
#define IPV6_OPT_TYPE_RPI            0x23
#define IPV6_OPT_TYPE_RPI_DEPRECATED 0x63

// RPL Control Codes
// https://www.iana.org/assignments/rpl/rpl.xhtml#control-codes
#define RPL_CODE_DIS     0x00
#define RPL_CODE_DIO     0x01
#define RPL_CODE_DAO     0x02
#define RPL_CODE_DAO_ACK 0x03

// Control Message Options
// https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
#define RPL_OPT_PAD1       0x00
#define RPL_OPT_PADN       0x01
#define RPL_OPT_METRICS    0x02
#define RPL_OPT_ROUTE      0x03
#define RPL_OPT_CONFIG     0x04
#define RPL_OPT_TARGET     0x05
#define RPL_OPT_TRANSIT    0x06
#define RPL_OPT_SOLICIT    0x07
#define RPL_OPT_PREFIX     0x08
#define RPL_OPT_DESCRIPTOR 0x09

// Mode of Operation
// https://www.iana.org/assignments/rpl/rpl.xhtml#mop
#define RPL_MOP_UPWARD        0
#define RPL_MOP_NON_STORING   1
#define RPL_MOP_STORING       2
#define RPL_MOP_STORING_MCAST 3

// Objective Code Point
// https://www.iana.org/assignments/rpl/rpl.xhtml#ocp
#define RPL_OCP_OF0   0
#define RPL_OCP_MRHOF 1

// RFC 6550 - Figure 14: The DIO Base Object
#define RPL_MASK_DIO_G   0x80
#define RPL_MASK_DIO_MOP 0x38
#define RPL_MASK_DIO_PRF 0x07
// RFC 6550 - Figure 16: The DAO Base Object
#define RPL_MASK_DAO_K 0x80
#define RPL_MASK_DAO_D 0x40
// RFC 6550 - Figure 17: The DAO ACK Base Object
#define RPL_MASK_DAO_ACK_D 0x80
// DODAG Configuration Option
// https://www.iana.org/assignments/rpl/rpl.xhtml#dodag-config-option-flags
#define RPL_MASK_OPT_CONFIG_RPI 0x10
#define RPL_MASK_OPT_CONFIG_A   0x08
#define RPL_MASK_OPT_CONFIG_PCS 0x07
// RFC 6550 - Figure 26: Format of the Transit Information Option
#define RPL_MASK_OPT_TRANSIT_E 0x80
// RFC 6550 - Figure 27: Path Control Preference Subfield Encoding
#define RPL_MASK_PATH_CTL_PC1 0xc0
#define RPL_MASK_PATH_CTL_PC2 0x30
#define RPL_MASK_PATH_CTL_PC3 0x0c
#define RPL_MASK_PATH_CTL_PC4 0x03
// RFC 6550 - Figure 28: Format of the Solicited Information Option
#define RPL_MASK_OPT_SOLICIT_V 0x80
#define RPL_MASK_OPT_SOLICIT_I 0x40
#define RPL_MASK_OPT_SOLICIT_D 0x20
// RFC 6550 - Figure 29: Format of the Prefix Information Option
#define RPL_MASK_OPT_PREFIX_L 0x80
#define RPL_MASK_OPT_PREFIX_A 0x40
#define RPL_MASK_OPT_PREFIX_R 0x20

// RFC 6553 - Figure 1: RPL Option
#define RPL_MASK_RPI_O 0x80
#define RPL_MASK_RPI_R 0x40
#define RPL_MASK_RPI_F 0x20

// RFC 6554 - 3. Format of the RPL Routing Header
#define RPL_MASK_SRH_CMPRI 0xf0000000
#define RPL_MASK_SRH_CMPRE 0x0f000000
#define RPL_MASK_SRH_PAD   0x00f00000

// RFC 6550 - 5.1. RPL Instance ID
#define RPL_MASK_INSTANCE_ID_TYPE 0x80
#define RPL_INSTANCE_ID_TYPE_GLOBAL 0
#define RPL_INSTANCE_ID_TYPE_LOCAL  1

struct rpl_opt_target {
    uint8_t prefix_len;
    uint8_t prefix[16];
};

struct rpl_opt_transit {
    bool external;
    uint8_t path_ctl;
    uint8_t path_seq;
    uint8_t path_lifetime;
    uint8_t parent[16];
};

static inline uint16_t rpl_dag_rank(const struct rpl_root *root, uint16_t rank)
{
    //   RFC 6550 - 3.5.1.  Rank Comparison (DAGRank())
    // The integer portion of the Rank is computed by the DAGRank() macro as
    // follows, where floor(x) is the function that evaluates to the greatest
    // integer less than or equal to x:
    //   DAGRank(rank) = floor(rank/MinHopRankIncrease)
    return rank / root->min_rank_hop_inc;
}

static inline uint16_t rpl_root_rank(struct rpl_root *root)
{
    //   RFC 6550 - 8.2.2.2. DODAG Roots
    // A DODAG root MUST advertise a Rank of ROOT_RANK.
    //   RFC 6550 - 17. RPL Constants and Variables
    // [...] ROOT_RANK has a value of MinHopRankIncrease [...].
    return root->min_rank_hop_inc;
}

#endif
