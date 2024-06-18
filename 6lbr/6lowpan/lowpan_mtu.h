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
#ifndef LOWPAN_MTU_H
#define LOWPAN_MTU_H

#include "common/specs/ieee802154.h"

// MTU: Maximum Transmission Unit

// FCS is handled by the RCP
#define LOWPAN_MTU_MAX (MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE - 4)

// Maximum overhead, usually computed from mac_helper_frame_overhead() and
// ws_mpx_header_size_get()
#define LOWPAN_MTU_MIN (                                                      \
    2 + /* Frame Control */                                                   \
    1 + /* Sequence Number */                                                 \
    2 + /* Destination PAN ID */                                              \
    8 + /* Destination Address */                                             \
    2 + /* Source PAN ID */                                                   \
    8 + /* Destination Address */                                             \
                                                                              \
    /* Auxiliary Security Header */                                           \
    1 + /* Security Control */                                                \
    4 + /* Frame Control */                                                   \
    9 + /* Key Identifier */                                                  \
                                                                              \
    /* Unicast Timing and Frame Type IE (UTT-IE) */                           \
    3 + /* Wi-SUN Header IE (WH-IE) */                                        \
    1 + /* Frame Type ID + Extended Frame Type ID */                          \
    3 + /* Unicast Fractional Sequence Interval */                            \
                                                                              \
    /* Broadcast Timing IE (BT-IE) */                                         \
    3 + /* Wi-SUN Header IE (WH-IE) */                                        \
    2 + /* Broadcast Slot Number */                                           \
    3 + /* Broadcast Interval Offset */                                       \
                                                                              \
    /* Header Termination IE */                                               \
    2 + /* Length + Group ID + Type */                                        \
                                                                              \
    /* Wi-SUN Payload Header (WP-IE) */                                       \
    2 + /* Length + Group ID + Type */                                        \
                                                                              \
    /* Unicast Schedule IE (US-IE) */                                         \
    1 + /* Dwell Interval */                                                  \
    1 + /* Clock Drift */                                                     \
    1 + /* Timing Accuracy */                                                 \
    1 + /* Channel Plan + Channel Function + Excluded Channel Control */      \
    6 + /* Channel Plan Fields (see ws_channel_plan_length) */                \
    2 + /* Channel Function Fields (see ws_channel_function_length, 3 is not supported) */ \
    32 + /* Channel Exclusion Field (bitmask with 256 channels) */            \
                                                                              \
    /* Broadcast Schedule IE (BS-IE) */                                       \
    4 + /* Broadcast Interval */                                              \
    2 + /* Broadcast Schedule Identifier */                                   \
    1 + /* Dwell Interval */                                                  \
    1 + /* Clock Drift */                                                     \
    1 + /* Timing Accuracy */                                                 \
    1 + /* Channel Plan + Channel Function + Excluded Channel Control */      \
    6 + /* Channel Plan Details (see ws_channel_plan_length) */               \
    2 + /* Channel Function Details (see ws_channel_function_length, 3 is not supported) */ \
    32 + /* Channel Exclusion Details (bitmask with 256 channels) */          \
                                                                              \
    /* MPX-IE */                                                              \
    2 + /* Header */                                                          \
    1 + /* Transaction Control (Full Frame) */                                \
        /* Fragment Number (Ommitted) */                                      \
        /* Total Upper Layer Frame Size (Omitted) */                          \
    2 + /* Multiplex ID (6LoWPAN) */                                          \
                                                                              \
    /* 6LoWPAN Payload */                                                     \
                                                                              \
    /* Payload Termination IE */                                              \
    2 + /* Length + Group ID + Type */                                        \
                                                                              \
    /* Message Integrity Code */                                              \
    8)  /* MIC-64 */

#endif
