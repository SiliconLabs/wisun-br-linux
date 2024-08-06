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
#ifndef COMMON_SPECS_EAPOL_H
#define COMMON_SPECS_EAPOL_H

// IEEE 802.1X-2020, 11.3.1 - Protocol Version
#define EAPOL_PROTOCOL_VERSION 0x03

// IEEE 802.1X-2020, Table 11-3 - "EAPOL Packet Types"
enum {
    EAPOL_PACKET_TYPE_EAP                    = 0x00,
    // ...
    EAPOL_PACKET_TYPE_KEY                    = 0x03,
};

// IEEE 802.1X-2020, Table 11-5 - "Descriptor Type value assignments"
enum {
    EAPOL_IEEE80211_KEY_DESCRIPTOR_TYPE = 0x02
};

#endif
