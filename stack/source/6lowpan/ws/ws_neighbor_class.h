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

#ifndef WS_NEIGHBOR_CLASS_H_
#define WS_NEIGHBOR_CLASS_H_
#include <time.h>

#include "stack/mac/fhss_ws_extension.h"

#include "6lowpan/ws/ws_common_defines.h"

struct net_if;

#define RSL_UNITITIALIZED 0x7fff

typedef struct ws_neighbor_class_entry {
    fhss_ws_neighbor_timing_info_t   fhss_data;
    uint16_t rsl_in;                                       /*!< RSL EWMA heard from neighbour*/
    uint16_t rsl_out;                                      /*!< RSL EWMA heard by neighbour*/
    uint16_t routing_cost;                                 /*!< ETX to border Router. */
    uint8_t last_DSN;
    int rssi;
    bool candidate_parent: 1;
    bool broadcast_timing_info_stored: 1;
    bool broadcast_schedule_info_stored: 1;
    bool synch_done : 1;
    bool unicast_data_rx : 1;
    struct timespec host_rx_timestamp;
} ws_neighbor_class_entry_t;

/**
 * Neighbor hopping info data base
 */
typedef struct ws_neighbor_class {
    ws_neighbor_class_entry_t *neigh_info_list;           /*!< Allocated hopping info array*/
    uint8_t list_size;                                    /*!< List size*/
} ws_neighbor_class_t;


/**
 * ws_neighbor_class_alloc a function for allocate giving list size
 *
 * \param class_data pointer to structure which will be initialized by this function
 * \param list_size define list size
 *
 * \return true Allocate Ok
 * \return false Allocate Fail
 *
 */
bool ws_neighbor_class_alloc(ws_neighbor_class_t *class_data, uint8_t list_size);

/**
 * ws_neighbor_class_dealloc a function for free allocated neighbor hopping info
 *
 * \param class_data pointer to structure which will be initialized by this function
 *
 */
void ws_neighbor_class_dealloc(ws_neighbor_class_t *class_data);

/**
 * ws_neighbor_class_entry_t a function for search hopping info for giving neighbor attribut
 *
 * \param class_data pointer to structure which will be initialized by this function
 * \param attribute_index define pointer to storage info
 *
 * \return NULL when Attribute is not correct
 * \return Pointer to neighbor hopping info
 *
 */
ws_neighbor_class_entry_t *ws_neighbor_class_entry_get(ws_neighbor_class_t *class_data, uint8_t attribute_index);

/**
 * ws_neighbor_class_entry_t a function for search hopping info for giving neighbor attribute index
 *
 * \param class_data pointer to structure which will be initialized by this function
 * \param entry which attribute index is counted.
 *
 * \return Attribute index of entry
 *
 */
uint8_t ws_neighbor_class_entry_index_get(ws_neighbor_class_t *class_data, ws_neighbor_class_entry_t *entry);

/**
 * ws_neighbor_class_entry_remove a function for clean information should be call when neighbor is removed
 *
 * \param class_data pointer to structure which will be initialized by this function
 * \param attribute_index define pointer to storage info
 *
 */
void ws_neighbor_class_entry_remove(ws_neighbor_class_t *class_data, uint8_t attribute_index);

// Unicast Timing update
void ws_neighbor_class_ut_update(ws_neighbor_class_entry_t *neighbor, uint24_t ufsi,
                                 uint32_t tstamp_us, const uint8_t eui64[8]);
// Broadcast Timing update
void ws_neighbor_class_bt_update(ws_neighbor_class_entry_t *neighbor, uint16_t slot_number,
                                 uint24_t interval_offset, uint32_t timestamp);
// LFN Unicast timing update
void ws_neighbor_class_lut_update(ws_neighbor_class_entry_t *neighbor,
                                  uint16_t slot_number, uint24_t interval_offset,
                                  uint32_t tstamp_us, const uint8_t eui64[8]);
// LFN Network Discovery update
void ws_neighbor_class_lnd_update(ws_neighbor_class_entry_t *neighbor, const struct ws_lnd_ie *ie_lnd, uint32_t tstamp_us);

// Unicast Schedule update
void ws_neighbor_class_us_update(const struct net_if *net_if, ws_neighbor_class_entry_t *ws_neighbor,
                                 const struct ws_generic_channel_info *chan_info,
                                 uint8_t dwell_interval, const uint8_t eui64[8]);
// Broadcast Schedule update
void ws_neighbor_class_bs_update(const struct net_if *net_if, ws_neighbor_class_entry_t *ws_neighbor, 
                                 const struct ws_generic_channel_info *chan_info,
                                 uint8_t dwell_interval, uint32_t interval, uint16_t bsi);
// LFN Unicast Schedule update
void ws_neighbor_class_lus_update(const struct net_if *net_if,
                                  ws_neighbor_class_entry_t *ws_neighbor,
                                  const struct ws_generic_channel_info *chan_info,
                                  uint24_t listen_interval_ms);
/**
 * ws_neighbor_class_rsl_from_dbm_calculate
 *
 * Calculates rsl value from dbm heard.
 * This provides a range of -174 (0) to +80 (254) dBm.
 *
 * \param dbm_heard; dbm heard from the neighbour
 *
 */
uint8_t ws_neighbor_class_rsl_from_dbm_calculate(int8_t dbm_heard);

/** Helper macros to read RSL values from neighbour class.
 *
 */
#define ws_neighbor_class_rsl_in_get(ws_neighbour) (ws_neighbour->rsl_in >> WS_RSL_SCALING)
#define ws_neighbor_class_rsl_out_get(ws_neighbour) (ws_neighbour->rsl_out >> WS_RSL_SCALING)

/**
 * ws_neighbor_class_neighbor_broadcast_schedule_set a function for update neighbor broadcast shedule information
 *
 * \param ws_neighbor pointer to neighbor
 * \param dbm_heard; dbm heard from the neighbour
 *
 */
void ws_neighbor_class_rsl_in_calculate(ws_neighbor_class_entry_t *ws_neighbor, int8_t dbm_heard);
/**
 * ws_neighbor_class_neighbor_broadcast_schedule_set a function for update neighbor broadcast shedule information
 *
 * \param ws_neighbor pointer to neighbor
 * \param rsl_reported; rsl value reported by neighbour in packet from RSL-IE
 *
 */
void ws_neighbor_class_rsl_out_calculate(ws_neighbor_class_entry_t *ws_neighbor, uint8_t rsl_reported);

bool ws_neighbor_class_neighbor_duplicate_packet_check(ws_neighbor_class_entry_t *ws_neighbor, uint8_t mac_dsn, uint32_t rx_timestamp);

#endif
