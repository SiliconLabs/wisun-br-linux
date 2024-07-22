/*
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
#ifndef IEEE802159_H
#define IEEE802159_H

// IEEE 802.15.9-2021, Table 22 - "KMP ID values"
enum {
    IEEE802159_KMP_ID_8021X     = 1,
    IEEE802159_KMP_ID_HIP       = 2, // Unused
    IEEE802159_KMP_ID_IKEV2     = 3, // Unused
    IEEE802159_KMP_ID_PANA      = 4, // Unused
    IEEE802159_KMP_ID_DRAGONFLY = 5, // Unused
    IEEE802159_KMP_ID_80211_4WH = 6,
    IEEE802159_KMP_ID_80211_GKH = 7,
    IEEE802159_KMP_ID_ETSI_TS   = 8, // Unused
};

#endif
