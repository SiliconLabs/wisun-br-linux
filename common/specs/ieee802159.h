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

/*
 *   IEEE 802.15.9-2021, 7.3.4 Multiplex ID field
 * Note: Wi-SUN Defined Payload is in fact rarely used in Wi-SUN (and not
 * supported by current code).
 */
enum {
    MPX_ID_KMP     = 0x0001, // Key Management Protocol
    MPX_ID_WISUN   = 0x0002, // Wi-SUN Defined Payload (see IEEE802.15.4 ANA database)
    // if > 1500, indicate the EtherType of the MAC client protocol
    MPX_ID_6LOWPAN = 0xA0ED, // LoWPAN encapsulation (see RFC7973).
};

#endif
