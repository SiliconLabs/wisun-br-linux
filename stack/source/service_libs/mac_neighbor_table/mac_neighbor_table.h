/*
 * Copyright (c) 2018, Pelion and affiliates.
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

#ifndef MAC_NEIGHBOR_TABLE_H_
#define MAC_NEIGHBOR_TABLE_H_
#include <stdint.h>
#include <stdbool.h>

/**
 * Generic Neighbor table entry
 */
typedef struct mac_neighbor_table_entry {
    uint8_t         index;                  /*!< Unique Neighbour index */
    bool            in_use;                 /*!< True if the entry is in use */
    uint8_t         mac64[8];               /*!< MAC64 */
    uint32_t        expiration_s;
    uint32_t        lifetime_s;             /*!< Life time in seconds */
    uint8_t         ms_phy_mode_id;         /*!< PhyModeId selected for Mode Switch with this neighbor */
    uint8_t         ms_mode;                /*!< Mode switch mode */
    uint32_t        ms_tx_count;            /*!< Mode switch Tx success count */ // TODO: implement fallback mechanism in wbsrd
    uint32_t        ms_retries_count;       /*!< Mode switch Tx retries */ // TODO: implement fallback mechanism in wsbrd
    bool            trusted_device: 1;      /*!< True mean use normal group key, false for enable pairwise key */
} mac_neighbor_table_entry_t;

void mac_neighbor_table_entry_init(mac_neighbor_table_entry_t *entry, const uint8_t *mac64, uint32_t lifetime_s);

/**
 * mac_neighbor_table_trusted_neighbor Function for manage neighbor role at mesh network
 *
 * Call this function when node is trusted connected
 *
 * \param neighbor_entry pointer to refreshed entry
 */
void mac_neighbor_table_trusted_neighbor(mac_neighbor_table_entry_t *neighbor_entry);

void mac_neighbor_table_refresh_neighbor(mac_neighbor_table_entry_t *neighbor, uint32_t lifetime_s);


#endif
