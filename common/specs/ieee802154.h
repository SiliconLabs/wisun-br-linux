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
#ifndef SPECS_IEEE802154_H
#define SPECS_IEEE802154_H

// IEEE 802.15.4-2020 Table 7-1 Values of the Frame Type field
enum {
    IEEE802154_FRAME_TYPE_BEACON = 0b000, // Unused
    IEEE802154_FRAME_TYPE_DATA   = 0b001,
    IEEE802154_FRAME_TYPE_ACK    = 0b010,
    IEEE802154_FRAME_TYPE_CMD    = 0b011,
    IEEE802154_FRAME_TYPE_MPX    = 0b101, // Unused
    IEEE802154_FRAME_TYPE_FRAG   = 0b110, // Unused
    IEEE802154_FRAME_TYPE_EXT    = 0b111, // Unused
};

// 802.15.4 ANA database - IE Header
// https://mentor.ieee.org/802.15/documents?is_dcn=257&is_group=0000
enum {
    // ...
    IEEE802154_IE_ID_WH  = 0x2a, // Wi-SUN Header (WH-IE)
    // 0x2b to 0x7d are reserved or unused
    IEEE802154_IE_ID_HT1 = 0x7e, // Header Termination 1
    IEEE802154_IE_ID_HT2 = 0x7f, // Header Termination 2
};

// 802.15.4 ANA database - IE Payload
// https://mentor.ieee.org/802.15/documents?is_dcn=257&is_group=0000
enum {
    IEEE802154_IE_ID_ESDU   = 0x0, // Unused
    IEEE802154_IE_ID_MLME   = 0x1, // Unused
    IEEE802154_IE_ID_VEMDOR = 0x2, // Unused
    IEEE802154_IE_ID_MPX    = 0x3, // Multiplexed IE (MPX-IE)
    IEEE802154_IE_ID_WP     = 0x4, // Wi-SUN Payload (WP-IE)
    IEEE802154_IE_ID_IETF   = 0x5, // Unused
    // 0x6 to 0xe are reserved
    IEEE802154_IE_ID_PT     = 0xf, // Payload Termination
};

// IEEE 802.15.4-202, Table 7-3, "Valid values of the Destination Addressing
// Mode and Source Addressing Mode fields"
enum {
    IEEE802154_ADDR_MODE_NONE     = 0,
    // 1 is reserved
    IEEE802154_ADDR_MODE_16_BIT   = 2,
    IEEE802154_ADDR_MODE_64_BIT   = 3,
};

// IEEE 802.15.4-202, Table 7-4, "Frame Version field values"
enum {
    IEEE802154_FRAME_VERSION_2003 = 0,
    IEEE802154_FRAME_VERSION_2006 = 1,
    IEEE802154_FRAME_VERSION_2015 = 2,
};

// IEEE 802.15.4-2020, Table 9-7, "Values of the Key Identifier Mode field"
enum {
    IEEE802154_KEY_ID_MODE_IMPLICIT = 0,
    IEEE802154_KEY_ID_MODE_IDX      = 1,
    IEEE802154_KEY_ID_MODE_SRC4_IDX = 2,
    IEEE802154_KEY_ID_MODE_SRC8_IDX = 3,
};

// IEEE 802.15.4-2020, Table 9-6, "Security levels available to the MAC sublayer"
enum {
    IEEE802154_SEC_LEVEL_NONE       = 0, // No payload encoding and and no authentication
    IEEE802154_SEC_LEVEL_MIC32      = 1, // No payload encoding but 32-bit MIC authentication
    IEEE802154_SEC_LEVEL_MIC64      = 2, // No payload encoding but 64-bit MIC authentication
    IEEE802154_SEC_LEVEL_MIC128     = 3, // No payload encoding but 128-bit MIC authentication
    IEEE802154_SEC_LEVEL_ENC        = 4, // Payload encoding but no authentication
    IEEE802154_SEC_LEVEL_ENC_MIC32  = 5, // Payload encoding and 32-bit MIC authentication
    IEEE802154_SEC_LEVEL_ENC_MIC64  = 6, // Payload encoding and 64-bit MIC authentication
    IEEE802154_SEC_LEVEL_ENC_MIC128 = 7  // Payload encoding and 128-bit MIC authentication
};

// IEEE 802.15.4-202, Table 11-1, "PHY constants"
#define MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE 2047

#endif
