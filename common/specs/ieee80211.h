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
#ifndef IEEE80211_H
#define IEEE80211_H

// IEEE 802.11-2020, Table 12-10 - "Integrity and key wrap algorithms"
#define IEEE80211_AKM_1_KCK_LEN_BYTES 16
#define IEEE80211_AKM_1_KEK_LEN_BYTES 16
#define IEEE80211_AKM_1_TK_LEN_BYTES  16

// IEEE 802.11-2020, Figure 12-34 - "Key Information bit format"
#define IEEE80211_MASK_KEY_INFO_VERSION        0b0000000000000111
#define IEEE80211_MASK_KEY_INFO_TYPE           0b0000000000001000
#define IEEE80211_MASK_KEY_INFO_INSTALL        0b0000000001000000
#define IEEE80211_MASK_KEY_INFO_ACK            0b0000000010000000
#define IEEE80211_MASK_KEY_INFO_MIC            0b0000000100000000
#define IEEE80211_MASK_KEY_INFO_SECURE         0b0000001000000000
#define IEEE80211_MASK_KEY_INFO_ERR            0b0000010000000000
#define IEEE80211_MASK_KEY_INFO_REQ            0b0000100000000000
#define IEEE80211_MASK_KEY_INFO_ENCRYPTED_DATA 0b0001000000000000

// IEEE 802.11-2020, 12.7.2 - EAPOL-Key frames
#define IEEE80211_KEY_INFO_VERSION 0x02
#define IEEE80211_KDE_TYPE 0xdd

// IEEE 802.11-2020, 12.7.2 - EAPOL-Key frames
enum {
    IEEE80211_KEY_TYPE_GROUP    = 0,
    IEEE80211_KEY_TYPE_PAIRWISE = 1,
};

// IEEE 802.11-2020, Table 12-9 - "KDE selectors"
enum {
    IEEE80211_KDE_GTK      = 1,
    // ...
    IEEE80211_KDE_PMKID    = 4,
    // ...
    IEEE80211_KDE_LIFETIME = 7,
};

#endif
