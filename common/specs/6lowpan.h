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
 *
 */
#ifndef SPECS_6LOWPAN_H
#define SPECS_6LOWPAN_H

/*
 * 6LoWPAN is defined in:
 * - RFC 4944: Transmission of IPv6 Packets over IEEE 802.15.4 Networks
 * - RFC 6282: Compression Format for IPv6 Datagrams over IEEE 802.15.4-Based
 *   Networks
 */

// Dispatch Type Field
// https://www.iana.org/assignments/_6lowpan-parameters/_6lowpan-parameters.xhtml#_6lowpan-parameters-1
enum {
    LOWPAN_DISPATCH_NALP  = 0b00000000,
    LOWPAN_DISPATCH_ESC   = 0b01000000,
    LOWPAN_DISPATCH_IPV6  = 0b01000001,
    LOWPAN_DISPATCH_HC1   = 0b01000010,
    LOWPAN_DISPATCH_BC0   = 0b01010000,
    LOWPAN_DISPATCH_IPHC  = 0b01100000,
    LOWPAN_DISPATCH_MESH  = 0b10000000,
    LOWPAN_DISPATCH_FRAG1 = 0b11000000,
    LOWPAN_DISPATCH_FRAGN = 0b11100000,
};

#define LOWPAN_DISPATCH_IS_NALP(dispatch)  (((dispatch) & 0b11000000) == LOWPAN_DISPATCH_NALP)  // 00xxxxxx
#define LOWPAN_DISPATCH_IS_ESC(dispatch)   ( (dispatch)               == LOWPAN_DISPATCH_ESC)   // 01000000
#define LOWPAN_DISPATCH_IS_IPV6(dispatch)  ( (dispatch)               == LOWPAN_DISPATCH_IPV6)  // 01000001
#define LOWPAN_DISPATCH_IS_HC1(dispatch)   ( (dispatch)               == LOWPAN_DISPATCH_HC1)   // 01000010
#define LOWPAN_DISPATCH_IS_BC0(dispatch)   ( (dispatch)               == LOWPAN_DISPATCH_BC0)   // 01010000
#define LOWPAN_DISPATCH_IS_IPHC(dispatch)  (((dispatch) & 0b11100000) == LOWPAN_DISPATCH_IPHC)  // 011xxxxx
#define LOWPAN_DISPATCH_IS_MESH(dispatch)  (((dispatch) & 0b11000000) == LOWPAN_DISPATCH_MESH)  // 10xxxxxx
#define LOWPAN_DISPATCH_IS_FRAG1(dispatch) (((dispatch) & 0b11111000) == LOWPAN_DISPATCH_FRAG1) // 11000xxx
#define LOWPAN_DISPATCH_IS_FRAGN(dispatch) (((dispatch) & 0b11111000) == LOWPAN_DISPATCH_FRAGN) // 11100xxx

// RFC 4944 - Figure 3: Mesh Addressing Type and Header
#define LOWPAN_MASK_MESH_V    0b00100000
#define LOWPAN_MASK_MESH_F    0b00010000
#define LOWPAN_MASK_MESH_HOPS 0b00001111
// RFC 4944 - Figure 4: First Fragment
// RFC 4944 - Figure 5: Subsequent Fragments
#define LOWPAN_MASK_FRAG_DGRAM_SIZE 0b0000011111111111

// RFC 6282 - Figure 2: LOWPAN_IPHC base Encoding
#define LOWPAN_MASK_IPHC_TF   0b0001100000000000
#define LOWPAN_MASK_IPHC_NH   0b0000010000000000
#define LOWPAN_MASK_IPHC_HLIM 0b0000001100000000
#define LOWPAN_MASK_IPHC_CID  0b0000000010000000
#define LOWPAN_MASK_IPHC_SAC  0b0000000001000000
#define LOWPAN_MASK_IPHC_SAM  0b0000000000110000
#define LOWPAN_MASK_IPHC_M    0b0000000000001000
#define LOWPAN_MASK_IPHC_DAC  0b0000000000000100
#define LOWPAN_MASK_IPHC_DAM  0b0000000000000011
// RFC 6282 - Figure 3: LOWPAN_IPHC Encoding
#define LOWPAN_MASK_IPHC_SCI  0b11110000
#define LOWPAN_MASK_IPHC_DCI  0b00001111

// RFC 6282 - Figure 4: TF = 00: Traffic Class and Flow Label carried in-line
#define LOWPAN_MASK_IPHC_TF00_ECN  0xc0000000
#define LOWPAN_MASK_IPHC_TF00_DSCP 0x3c000000
#define LOWPAN_MASK_IPHC_TF00_FLOW 0x000fffff
// RFC 6282 - Figure 5: TF = 01: Flow Label carried in-line
#define LOWPAN_MASK_IPHC_TF01_ECN  0xc00000
#define LOWPAN_MASK_IPHC_TF01_FLOW 0x0fffff
// RFC 6282 - Figure 6: TF = 10: Traffic Class carried in-line
#define LOWPAN_MASK_IPHC_TF10_ECN  0b11000000
#define LOWPAN_MASK_IPHC_TF10_DSCP 0b00111100

// LOWPAN_NHC Header Type
// https://www.iana.org/assignments/_6lowpan-parameters/_6lowpan-parameters.xhtml#lowpan_nhc
#define LOWPAN_NHC_EXTHDR     0b11100000 // 1110EEEN
#define LOWPAN_NHC_UDP        0b11110000 // 11110CPP
#define LOWPAN_NHC_IS_EXTHDR(nhc) (((nhc) & 0b11110000) == LOWPAN_NHC_EXTHDR)
#define LOWPAN_NHC_IS_UDP(nhc)    (((nhc) & 0b11111000) == LOWPAN_NHC_UDP)

// RFC 6282 - Figure 13: IPv6 Extension Header Encoding
#define LOWPAN_MASK_NHC_EXTHDR_EID 0b00001110
#define LOWPAN_MASK_NHC_EXTHDR_NH  0b00000001

enum lowpan_nhc_exthdr_eid {
    LOWPAN_NHC_EID_HOPOPT   = 0,
    LOWPAN_NHC_EID_ROUTING  = 1,
    LOWPAN_NHC_EID_FRAG     = 2,
    LOWPAN_NHC_EID_DSTOPT   = 3,
    LOWPAN_NHC_EID_MOBILITY = 4,
    LOWPAN_NHC_EID_IPV6     = 7,
};

// RFC 6282 - Figure 14: UDP Header Encoding
#define LOWPAN_MASK_NHC_UDP_C 0b00000100
#define LOWPAN_MASK_NHC_UDP_P 0b00000011

#define LOWPAN_MASK_NHC_UDP_P11_SRC 0b11110000
#define LOWPAN_MASK_NHC_UDP_P11_DST 0b00001111

#endif
