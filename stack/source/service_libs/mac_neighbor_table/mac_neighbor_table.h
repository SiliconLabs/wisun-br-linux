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
#include "common/ns_list.h"

#define NEIGHBOR_CLASS_LINK_DEFAULT_LIFETIME 240

/**
 * Generic Neighbor table entry
 */
typedef struct mac_neighbor_table_entry {
    uint8_t         index;                  /*!< Unique Neighbour index */
    bool            in_use;                 /*!< True if the entry is in use */
    uint8_t         mac64[8];               /*!< MAC64 */
    uint32_t        lifetime;               /*!< Life time in seconds which goes down */
    uint32_t        link_lifetime;          /*!< Configured link timeout*/
    uint8_t         ms_phy_mode_id;         /*!< PhyModeId selected for Mode Switch with this neighbor */
    uint8_t         ms_mode;                /*!< Mode switch mode */
    uint32_t        ms_tx_count;            /*!< Mode switch Tx success count */ // TODO: implement fallback mechanism in wbsrd
    uint32_t        ms_retries_count;       /*!< Mode switch Tx retries */ // TODO: implement fallback mechanism in wsbrd
    bool            trusted_device: 1;      /*!< True mean use normal group key, false for enable pairwise key */
    bool            nud_active: 1;          /*!< True Neighbor NUD process is active, false not active process */
    ns_list_link_t  link;
} mac_neighbor_table_entry_t;

typedef NS_LIST_HEAD(mac_neighbor_table_entry_t, link) mac_neighbor_table_list_t;

/**
 * Remove entry notify
 *
 * \param entry_ptr Pointer to removed entry
 * \param user_data pointer for user to detect interface
 */
typedef void neighbor_entry_remove_notify(mac_neighbor_table_entry_t *entry_ptr, void *user_data);


/**
 * NUD entry notify
 *
 * \param entry_ptr Pointer to neighbor entry
 * \param user_data pointer for user to detect interface
 *
 * \return true NUD message generated
 * \return false When NUD is not generated
 */
typedef bool neighbor_entry_nud_notify(mac_neighbor_table_entry_t *entry_ptr, void *user_data);

/**
 * Neighbor table class structure
 */
typedef struct mac_neighbor_table {
    mac_neighbor_table_list_t neighbour_list;               /*!< List of neighbors */
    uint32_t nud_threshold;                                 /*!< NUD threshold time which generates keep alive message */
    uint8_t list_total_size;                                /*!< Total number allocated neighbor entries */
    uint8_t neighbour_list_size;                            /*!< Active Neighbor list size */
    void *table_user_identifier;                            /*!< Table user identifier like interface pointer */
    neighbor_entry_remove_notify *user_remove_notify_cb;    /*!< Neighbor Remove Callback notify */
    neighbor_entry_nud_notify *user_nud_notify_cb;          /*!< Trig NUD process for neighbor */
} mac_neighbor_table_t;


/**
 * \brief mac_neighbor_table_create Allocate Neighbour table class
 *
 * Call this only one's for interface
 *
 * \param table_size size of neighbor table
 * \param remove_cb callback pointer for notify removed neighbor
 * \param nud_cb Interface NUD operation trgger callback
 * \param user_indentifier user identifier pointer like interface pointer
 *
 * \return pointer to neighbor table class when create is OK
 * \return NULL when memory allocation happen
 *
 */
mac_neighbor_table_t *mac_neighbor_table_create(uint8_t table_size, neighbor_entry_remove_notify *remove_cb, neighbor_entry_nud_notify *nud_cb, void *user_indentifier);

/**
 * mac_neighbor_table_delete Delete Neigbor table class
 *
 * \param table_class neighbor table class
 */
void mac_neighbor_table_delete(mac_neighbor_table_t *table_class);

/**
 * mac_neighbor_table_neighbor_list_clean Clean neighbour_list from giving class
 */
void mac_neighbor_table_neighbor_list_clean(mac_neighbor_table_t *table_class);

/**
 * mac_neighbor_table_neighbor_timeout_update Update Neighbor table timeout values
 *
 * \param interface pointer to interface
 * \param time_update in seconds
 *
 */
void mac_neighbor_table_neighbor_timeout_update(int time_update);


/**
 * mac_neighbor_table_entry_allocate Allocate Neighbour table class entry
 *
 * \param table_class pointer to table class
 * \param mac64 neighbor 64-bit mac address
 * \param role neighbor role
 *
 * \return NULL allocate fail
 * \return pointer to allocated neighbor table entry
 */
mac_neighbor_table_entry_t *mac_neighbor_table_entry_allocate(mac_neighbor_table_t *table_class, const uint8_t *mac64, uint8_t role);

/**
 * mac_neighbor_table_trusted_neighbor Function for manage neighbor role at mesh network
 *
 * Call this function when node is trusted connected
 *
 * \param neighbor_entry pointer to refreshed entry
 */
void mac_neighbor_table_trusted_neighbor(mac_neighbor_table_entry_t *neighbor_entry);

/**
 * mac_neighbor_table_get_by_mac64 Get neighbor from list by mac address
 *
 *  \param table_class pointer to table class
 *  \param address pointer to 16-bit MAC or 64-bit address for discover
 *
 *  \return pointer to neighbor entry if it exists
 */
mac_neighbor_table_entry_t *mac_neighbor_table_get_by_mac64(mac_neighbor_table_t *table_class, const uint8_t *address);

mac_neighbor_table_entry_t *mac_neighbor_entry_get_by_ll64(mac_neighbor_table_t *table_class, const uint8_t *ipv6Address);

void neighbor_table_class_remove_entry(mac_neighbor_table_t *table_class, mac_neighbor_table_entry_t *entry);

void mac_neighbor_table_refresh_neighbor(mac_neighbor_table_t *table, const uint8_t *eui64, uint32_t link_lifetime);

#endif
