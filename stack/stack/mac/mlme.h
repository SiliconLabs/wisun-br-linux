/*
 * Copyright (c) 2013-2021, Pelion and affiliates.
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

/** \file mlme.h
 * \brief MLME API
 */

#ifndef MLME_H_
#define MLME_H_
#include <stdint.h>
#include <stdbool.h>

#include "stack/mac/mac_common_defines.h"

enum mlme_primitive {
    MLME_ASSOCIATE,
    MLME_DISASSOCIATE,
    MLME_BEACON_NOTIFY,
    MLME_GET,
    MLME_GTS,
    MLME_ORPHAN,
    MLME_RESET,
    MLME_RX_ENABLE,
    MLME_SCAN,
    MLME_COMM_STATUS,
    MLME_SET,
    MLME_START,
    MLME_SYNC,
    MLME_SYNC_LOSS,
    MLME_POLL
};

/**
 * @brief MLME primitive error statuses
 *
 * See IEEE standard 802.15.4-2006 for more details
 */
#define MLME_SUCCESS                    0x00 /**< The requested operation was completed successfully*/
#define MLME_BUSY_CHAN                  0xe1 /**< CSMA-CA fail*/
#define MLME_BUSY_RX                    0x01 /**< The radio is asked to change its state while receiving */
#define MLME_BUSY_TX                    0x02 /**< The radio is asked to change its state while transmitting. */
#define MLME_FORCE_TRX_OFF              0x03 /**< The radio is to be switched off immediately */
#define MLME_IDLE                       0x04 /**< The CCA attempt has detected an idle channel */
#define MLME_RX_ON                      0x06 /**< The radio is in or is to be configured into the receiver enabled state. */
#define MLME_TRX_OFF                    0x08 /**< The radio is in or is to be configured into the receiver enabled state. */
#define MLME_TX_ON                      0x09 /**< The radio is in or is to be configured into the receiver enabled state. */
#define MLME_COUNTER_ERROR              0xdb /**< Originated messages security counter is not valid */
#define MLME_IMPROPER_KEY_TYPE          0xdc /**< Received Messages key used is agains't key usage policy */
#define MLME_IMPROPER_SECURITY_LEVEL    0xdd /**< Received Messages security level does not meet minimum security level */
#define MLME_UNSUPPORTED_LEGACY         0xde /**< The received frame was purportedly secured using security based on IEEE Std 802.15.4-2003, and such security is not supported by this standard. */
#define MLME_UNSUPPORTED_SECURITY       0xdf /**< The received frame security is not supported */
#define MLME_SECURITY_FAIL              0xe4 /**< Cryptographic processing of the received secured frame failed. */
#define MLME_FRAME_TOO_LONG             0xe5 /**< Either a frame resulting from processing has a length that is greater than aMaxPHYPacketSize */
#define MLME_INVALID_HANDLE             0xe7 /**< Status for Purge request when Mac not detect proper queued message*/
#define MLME_INVALID_PARAMETER          0xe8 /**< A parameter in the primitive is either not supported or is out of the valid range */
#define MLME_TX_NO_ACK                  0xe9 /**< No ack was received after macMaxFrameRetries */
#define MLME_NO_BEACON                  0xea /**< A scan operation failed to find any network beacons */
#define MLME_NO_DATA                    0xeb /**< No response data were available following a request */
#define MLME_NO_SHORT_ADDRESS           0xec /**< Operation fail because 16-bit address is not allocated */
#define MLME_PAN_ID_CONFLICT            0xee /**< A PAN identifier conflict has been detected and communicated to the PAN coordinator. */
#define MLME_TRANSACTION_EXPIRED        0xf0 /**< The transaction has expired and its information was discarded */
#define MLME_TRANSACTION_OVERFLOW       0xf1 /**< MAC have no capacity to store the transaction */
#define MLME_UNAVAILABLE_KEY            0xf3 /**< Received message use unknown key, or the originating device is unknown or is blacklisted with that particular key */
#define MLME_UNSUPPORTED_ATTRIBUTE      0xf4 /**< A SET/GET request was issued with the unsupported identifier */
#define MLME_INVALID_ADDRESS            0xf5 /**< A request to send data was unsuccessful because neither the source address parameters nor the destination address parameters were present.*/
#define MLME_INVALID_INDEX              0xf9 /**< An attempt to write to a MAC PIB attribute that is in a table failed because the specified table index was out of range. */
#define MLME_LIMIT_REACHED              0xfa /**< A scan operation terminated prematurely because the number of PAN descriptors stored reached an implementation- specified maximum */
#define MLME_READ_ONLY                  0xfb /**< A SET request was issued with the identifier of an attribute that is read only.*/
#define MLME_SCAN_IN_PROGRESS           0xfc /**< Request scan request fail when scan is already active */
//NOT-standard
#define MLME_DATA_POLL_NOTIFICATION     0xff /**< Thread requirement feature COMM status status for indicate for successfully data poll event to refresh neighbour data */

typedef struct mlme_comm_status {
    uint16_t PANId;                 /**< Messages Pan-id */
    unsigned SrcAddrMode: 2;        /**< source address mode: MAC_ADDR_MODE_NONE,MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint8_t SrcAddr[8];             /**< source address when mode is: MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    unsigned DstAddrMode: 2;        /**< destination address mode: MAC_ADDR_MODE_NONE,MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint8_t DstAddr[8];             /**< Destination address when mode is: MAC_ADDR_MODE_16_BIT or MAC_ADDR_MODE_64_BIT */
    uint8_t status;                 /**< Communication status */
    mlme_security_t Key;            /**< Messages Security parameters */
} mlme_comm_status_t;

#endif
