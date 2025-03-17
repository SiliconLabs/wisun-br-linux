/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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
#ifndef SPECS_WS_H
#define SPECS_WS_H

// Wi-SUN Assigned Value Registry 0v25
//   10. Wi-SUN Frame Types
enum {
    WS_FT_PA    =  0, // PAN Advert
    WS_FT_PAS   =  1, // PAN Advert Solicit
    WS_FT_PC    =  2, // PAN Config
    WS_FT_PCS   =  3, // PAN Config Solicit
    WS_FT_DATA  =  4, // Data
    WS_FT_ACK   =  5, // Ack
    WS_FT_EAPOL =  6, // EAPOL
    // 7 and 8 are reserved
    WS_FT_LPA   =  9, // LFN PAN Advert
    WS_FT_LPAS  = 10, // LFN PAN Advert Solicit
    WS_FT_LPC   = 11, // LFN PAN Config
    WS_FT_LPCS  = 12, // LFN PAN Config Solicit
    WS_FT_LTS   = 13, // LFN Time Sync
    // 14 is reserved
    WS_FT_EXT   = 15, // Extended Type
};

// Wi-SUN Assigned Value Registry 0v25
//   7.1. Wi-SUN Header Information Eement Sub-IDs
enum {
    // 0x00 is reserved
    WS_WHIE_UTT   = 0x01, // Unicast Timing and Frame Type
    WS_WHIE_BT    = 0x02, // Broadcast Timing
    WS_WHIE_FC    = 0x03, // Flow Control
    WS_WHIE_RSL   = 0x04, // Received Signal Level
    WS_WHIE_MHDS  = 0x05, // MHDS
    WS_WHIE_VH    = 0x06, // Vendor Header
    WS_WHIE_NFT   = 0x07, // Netricity Frame Type
    WS_WHIE_LQI   = 0x08, // Netricity Link Quality Index
    WS_WHIE_EA    = 0x09, // EAPOL Authenticator EUI-64
    WS_WHIE_LUTT  = 0x0a, // LFN Unicast Timing and Frame Type
    WS_WHIE_LBT   = 0x0b, // LFN Broadcast Timing
    WS_WHIE_NR    = 0x0c, // Node Role
    WS_WHIE_LUS   = 0x0d, // LFN Unicast Schedule
    WS_WHIE_FLUS  = 0x0e, // FFN for LFN Unicast Schedule
    WS_WHIE_LBS   = 0x0f, // LFN Broadcast Schedule
    WS_WHIE_LND   = 0x10, // LFN Network Discovery
    WS_WHIE_LTO   = 0x11, // LFN Timing Offset
    WS_WHIE_PANID = 0x12, // PAN Identifier
    // 0x13 to 0x7e are reserved for one-hop IEs
    WS_WHIE_PAN_WIDE_MIN = 0x80,
    WS_WHIE_PAN_WIDE_MAX = 0xbf,
    WS_WHIE_FFN_WIDE_MIN = 0xc0,
    WS_WHIE_LBC   = 0xc0, // LFN Broadcast Configuration
    WS_WHIE_FFN_WIDE_MAX = 0xfe,
};

// Wi-SUN Assigned Value Registry 0v25
//   7.2. Wi-SUN Payload Information Eement Sub-IDs
// Short form
enum {
    // 0x00 to 0x03 are reserved
    WS_WPIE_PAN      = 0x04, // PAN
    WS_WPIE_NETNAME  = 0x05, // Network Name
    WS_WPIE_PANVER   = 0x06, // PAN Version
    WS_WPIE_GTKHASH  = 0x07, // GTK Hash
    WS_WPIE_POM      = 0x08, // PHY Operating Modes
    WS_WPIE_LBATS    = 0x09, // LFN Broadcast Additional Transmit Schedule
    WS_WPIE_JM       = 0x0a, // Join Metrics
    // 0x0b to 0x3f are reserved for one-hop IEs
    WS_WPIE_SHORT_PAN_WIDE_MIN = 0x40,
    WS_WPIE_LFNVER   = 0x40, // LFN Version
    WS_WPIE_LGTKHASH = 0x41, // LFN GTK Hash
    WS_WPIE_SHORT_PAN_WIDE_MAX = 0x5f,
    WS_WPIE_SHORT_FFN_WIDE_MIN = 0x60,
    WS_WPIE_SHORT_FFN_WIDE_MAX = 0x7e,
};
// Long form
enum {
    // 0x00 is reserved
    WS_WPIE_US       = 0x01, // Unicast Schedule
    WS_WPIE_BS       = 0x02, // Broadcast Schedule
    WS_WPIE_VP       = 0x03, // Vendor Payload
    WS_WPIE_LCP      = 0x04, // LFN Channel Plan
    // 0x05 to 0x07 are reserved for one-hop IEs
    WS_WPIE_LONG_PAN_WIDE_MIN = 0x08,
    WS_WPIE_LONG_PAN_WIDE_MAX = 0x0a,
    WS_WPIE_LONG_FFN_WIDE_MIN = 0x0b,
    WS_WPIE_LONG_FFN_WIDE_MAX = 0x0e,
};

// Wi-SUN Assigned Value Registry 0v25
//   8. Join Metric IDs
enum {
    WS_JM_PLF = 1, // PAN Load Factor
};

// Wi-SUN Assigned Value Registry 0v25
//   11. Wi-SUN Key Data Cryptographic Encapsulations
enum {
    WS_KDE_PTKID = 1,
    WS_KDE_GTKL  = 2,
    WS_KDE_NR    = 3,
    WS_KDE_LGTKL = 4,
    WS_KDE_LGTK  = 5,
};

// Wi-SUN FAN 1.1v06
//   6.3.2.3.2.3 PAN Information Element (PAN-IE)
enum {
    WS_FAN_VERSION_1_0 = 1,
    WS_FAN_VERSION_1_1 = 2,
};

// Wi-SUN FAN 1.1v06
//   6.3.2.3.1.10 Node Role Information Element (NR-IE)
enum {
    WS_NR_ROLE_BR      = 0,
    WS_NR_ROLE_ROUTER  = 1,
    WS_NR_ROLE_LFN     = 2,
    WS_NR_ROLE_UNKNOWN = 3,
};

// Wi-SUN FAN 1.1v06
//   6.3.2.3.2.1.3 Field Definitions (Channel Function)
enum ws_channel_functions {
    WS_CHAN_FUNC_FIXED          = 0,
    WS_CHAN_FUNC_TR51CF         = 1,
    WS_CHAN_FUNC_DH1CF          = 2,
    WS_CHAN_FUNC_VENDOR_DEFINED = 3,
};

// Wi-SUN FAN 1.1v06
//   6.3.2.3.2.1.3 Field Definitions (Excluded Channel Control)
enum {
    WS_EXC_CHAN_CTRL_NONE    = 0,
    WS_EXC_CHAN_CTRL_RANGE   = 1,
    WS_EXC_CHAN_CTRL_BITMASK = 2,
};

// Wi-SUN Assigned Value Registry 0v25, Appendix A
enum {
    WS_VIN_SILICON_LABS = 26,
};

// Wi-SUN FAN 1.1v08 Figure 6-42 Node Role IE Format
#define WS_MASK_NR_ID 0b00000111

// Wi-SUN FAN 1.1v08
//   Figure 6-50 Unicast Schedule IE
//   Figure 6-51 Broadcast Schedule IE
//   Figure 6-66 LFN Channel Information Fields
#define WS_MASK_SCHEDULE_CHAN_PLAN 0b00000111
#define WS_MASK_SCHEDULE_CHAN_FUNC 0b00111000
#define WS_MASK_SCHEDULE_CHAN_EXCL 0b11000000

// Wi-SUN FAN 1.1v06-d0 Figure 6-58 PAN IE
#define WS_MASK_PAN_PARENT_BS 0b00000001
#define WS_MASK_PAN_ROUTING   0b00000010
#define WS_MASK_PAN_LFN_STYLE 0b00000100
#define WS_MASK_PAN_TPS       0b11100000

// Wi-SUN FAN 1.1v08 Figure 6-62 Capability IE
#define WS_MASK_POM_COUNT 0b00001111
#define WS_MASK_POM_MDR   0b00010000

// Wi-SUN FAN 1.1v08 Figure 6-68 LFN GTK Hash IE
#define WS_MASK_LGTKHASH_LGTK0 0b00000001
#define WS_MASK_LGTKHASH_LGTK1 0b00000010
#define WS_MASK_LGTKHASH_LGTK2 0b00000100
#define WS_MASK_LGTKHASH_INDEX 0b00011000

// Wi-SUN FAN 1.1v08 Figure 68c JM-IE Metric
#define WS_MASK_JM_ID  0b00111111
#define WS_MASK_JM_LEN 0b11000000

// Wi-SUN FAN 1.1v08 Figure 6-44 LFN Unicast Schedule IE
#define WS_CHAN_PLAN_TAG_CURRENT 255

// Wi-SUN FAN 1.1v08 6.2.3.1.6.1 Link Metrics
#define WS_ETX_MAX 1024

// Wi-SUN FAN 1.1v08 6.2.3 Operation
#define WS_MTU_BYTES 1576

// Wi-SUN FAN 1.1v08 6.2.1 Constants
#define WS_CAND_PARENT_THRESHOLD_DB  10
#define WS_CAND_PARENT_HYSTERESIS_DB 3

/*
 *   Wi-SUN FAN 1.1v08 6.2.1 Constants
 * ETX_EWMA_SF    ETX EWMA Smoothing Factor   1/8
 * RSL_EWMA_SF    RSL EWMA Smoothing Factor   1/8
 */
#define WS_EWMA_SF (1.0 / 8.0)

#endif
