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

/* If PAN version lifetime would be 10 minutes, 1000 increments is about 7 days i.e. storage must
   be written at least once a week */
#define PAN_VERSION_STORAGE_READ_INCREMENT    1000

/* Device min sensitivity. This value is dynamically configured and depends on radio
 *
 * Default value for us is -93
 */
extern int DEVICE_MIN_SENS;

/* Candidate parent Threshold
 */
#define CAND_PARENT_THRESHOLD 10

/* Candidate parent Threshold hysteresis
 */
#define CAND_PARENT_HYSTERISIS 3

/* Multicast MPL data message parameters
 */
#define MPL_SAFE_HOP_COUNT 6

/*Border router override to optimize the multicast startup*/
#define MPL_BORDER_ROUTER_MIN_EXPIRATIONS 2
#define MPL_BORDER_ROUTER_MAXIMUM_IMAX 40

/*Small network size*/
#define MPL_SMALL_IMIN 1
#define MPL_SMALL_IMAX 10
#define MPL_SMALL_EXPIRATIONS 2
#define MPL_SMALL_K 8
#define MPL_SMALL_SEED_LIFETIME (MPL_SMALL_IMAX * MPL_SAFE_HOP_COUNT * (MPL_SMALL_EXPIRATIONS + 1)) // time that packet should get to safe distance
/*Medium network size*/
#define MPL_MEDIUM_IMIN 1
#define MPL_MEDIUM_IMAX 32
#define MPL_MEDIUM_EXPIRATIONS 2
#define MPL_MEDIUM_K 8
#define MPL_MEDIUM_SEED_LIFETIME (MPL_MEDIUM_IMAX * MPL_SAFE_HOP_COUNT * (MPL_MEDIUM_EXPIRATIONS + 1)) // time that packet should get to safe distance
/*Large network size*/
#define MPL_LARGE_IMIN 5
#define MPL_LARGE_IMAX 40
#define MPL_LARGE_EXPIRATIONS 2
#define MPL_LARGE_K 8
#define MPL_LARGE_SEED_LIFETIME (MPL_LARGE_IMAX * MPL_SAFE_HOP_COUNT * (MPL_LARGE_EXPIRATIONS + 1)) // time that packet should get to safe distance
/*xtra large network size*/
#define MPL_XLARGE_IMIN 10
#define MPL_XLARGE_IMAX 80
#define MPL_XLARGE_EXPIRATIONS 2
#define MPL_XLARGE_K 8
#define MPL_XLARGE_SEED_LIFETIME (MPL_XLARGE_IMAX * MPL_SAFE_HOP_COUNT * (MPL_XLARGE_EXPIRATIONS + 1)) // time that packet should get to safe distance

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

/*
 * Security protocol message retry configuration parameters
 *
 * Trickle is reset on start (inconsistent heard is set)
 */
#define SEC_PROT_SMALL_IMIN 60              // Retries done in 60 seconds
#define SEC_PROT_SMALL_IMAX 120             // Largest value 120 seconds
#define SEC_PROT_RETRY_TIMEOUT_SMALL 450    // Retry timeout for small network additional 30 seconds for authenticator delay

#define SEC_PROT_LARGE_IMIN 60              // Retries done in 60 seconds
#define SEC_PROT_LARGE_IMAX 240             // Largest value 240 seconds
#define SEC_PROT_RETRY_TIMEOUT_LARGE 750    // Retry timeout for large network additional 30 seconds for authenticator delay

#define SEC_PROT_TIMER_EXPIRATIONS 4        // Number of retries

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
