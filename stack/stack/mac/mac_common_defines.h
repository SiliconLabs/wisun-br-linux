/*
 * Copyright (c) 2016-2018, 2020, Pelion and affiliates.
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
#ifndef MAC_COMMON_DEFINES_H_
#define MAC_COMMON_DEFINES_H_

#include <stdint.h>

#define MAC_ADDR_MODE_NONE 0                    /**< Address mode for no address defined */
#define MAC_ADDR_MODE_16_BIT 2                  /**< Address mode for 16-bit addresses */
#define MAC_ADDR_MODE_64_BIT 3                  /**< Address mode for 64-bit addresses */

#define MAC_FRAME_VERSION_2003         0        /**< FCF - IEEE 802.15.4-2003 compatible */
#define MAC_FRAME_VERSION_2006         1        /**< FCF - IEEE 802.15.4-2006 (big payload or new security) */
#define MAC_FRAME_VERSION_2015         2        /**< FCF - IEEE 802.15.4-2015 (IE element support) */

//See IEEE standard 802.15.4-2006 (table 96) for more details about identifiers
#define MAC_KEY_ID_MODE_IMPLICIT    0           /**< Key identifier mode implicit */
#define MAC_KEY_ID_MODE_IDX         1           /**< Key identifier mode for 1-octet key index */
#define MAC_KEY_ID_MODE_SRC4_IDX    2           /**< Key identifier mode for combined 4-octet key source and 1-octet key index */
#define MAC_KEY_ID_MODE_SRC8_IDX    3           /**< Key identifier mode for combined 8-octet key source and 1-octet key index */

// IEEE 802.15.4 constants
#define MAC_IEEE_802_15_4G_MAX_PHY_PACKET_SIZE          2047    /**< Maximum number of octets PHY layer is able to receive */

// IEEE standard 802.15.4-2006. Table 95.
enum {
    SEC_NONE       = 0, // No payload encoding and and no authentication
    SEC_MIC32      = 1, // No payload encoding but 32-bit MIC authentication
    SEC_MIC64      = 2, // No payload encoding but 64-bit MIC authentication
    SEC_MIC128     = 3, // No payload encoding but 128-bit MIC authentication
    SEC_ENC        = 4, // Payload encoding but no authentication
    SEC_ENC_MIC32  = 5, // Payload encoding and 32-bit MIC authentication
    SEC_ENC_MIC64  = 6, // Payload encoding and 64-bit MIC authentication
    SEC_ENC_MIC128 = 7  // Payload encoding and 128-bit MIC authentication
};

/**
 * @brief struct mlme_security MLME/MCPS security structure
 * This structure encapsulates security related variables,
 * which are always used together if SecurityLevel > 0.
 *
 * See IEEE standard 802.15.4-2006 (e.g end of table 41) for more details
 */
typedef struct mlme_security {
    unsigned SecurityLevel: 3;  /**< Security level */
    unsigned KeyIdMode: 2;      /**< 2-bit value which define key source and ID use case */
    uint8_t KeyIndex;           /**< Key index */
    uint8_t Keysource[8];       /**< Key source */
} mlme_security_t;

#endif
