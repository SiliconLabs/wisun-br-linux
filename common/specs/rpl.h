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

// RFC 6550: RPL Control Codes
// https://www.iana.org/assignments/rpl/rpl.xhtml#control-codes
enum {
    RPL_CODE_DIS     = 0x00,
    RPL_CODE_DIO     = 0x01,
    RPL_CODE_DAO     = 0x02,
    RPL_CODE_DAO_ACK = 0x03,
};

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

#endif
