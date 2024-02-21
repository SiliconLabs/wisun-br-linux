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

#ifndef WS_CONFIG_H_
#define WS_CONFIG_H_
#include <stdint.h>

/* Device min sensitivity. This value is dynamically configured and depends on radio
 *
 * Default value for us is -93
 */
extern int DEVICE_MIN_SENS;

/* Multicast MPL data message parameters
 */
#define MPL_SAFE_HOP_COUNT 6

/* Neighbour table configuration
 *
 * Amount of RPL candidate parents
 * Amount of ND reply entries left
 * rest are used as child count, but is related to neighbour table size
 */
#define WS_SMALL_TEMPORARY_NEIGHBOUR_ENTRIES 10

/*
 * MAC frame counter NVM storing configuration
 */
#define FRAME_COUNTER_INCREMENT             1000000     // How much frame counter is incremented on start up

/*
 * Candidate parent list parameters
 */

#define WS_CONGESTION_PACKET_SIZE 500           // Packet length for calculate how much heap message queue can fit
#define WS_CONGESTION_QUEUE_DELAY 60            // Define message queue max length for given delay. This value is multiple by packet/seconds
#define WS_CONGESTION_RED_DROP_PROBABILITY 10 //10.0%
#define WS_CONGESTION_BR_MIN_QUEUE_SIZE 85000 / WS_CONGESTION_PACKET_SIZE
#define WS_CONGESTION_BR_MAX_QUEUE_SIZE 600000 / WS_CONGESTION_PACKET_SIZE

// Maximum number of simultaneous security negotiations
#define MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MIN   64
#define MAX_SIMULTANEOUS_SECURITY_NEGOTIATIONS_TX_QUEUE_MAX   192

/*
 *  RADIUS client retry timer defaults
 */
#define RADIUS_CLIENT_RETRY_IMIN           20       // First retry minimum 1 seconds
#define RADIUS_CLIENT_RETRY_IMAX           30       // First retry maximum 3 seconds
#define RADIUS_CLIENT_TIMER_EXPIRATIONS    3        // Number of retries is three

/*
 *  EAP-TLS fragment length
 *
 *  Configures both EAP-TLS and the RADIUS client (Framed-MTU on RFC 2864)
 */
#define EAP_TLS_FRAGMENT_LEN_VALUE         600       // EAP-TLS fragment length

#endif
