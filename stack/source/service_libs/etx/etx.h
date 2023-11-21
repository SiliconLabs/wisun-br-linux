/*
 * Copyright (c) 2014-2020, Pelion and affiliates.
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
/*
 * \file etx.h
 * \brief Expected transmission count (ETX metric), module
 *
 *
 */

#ifndef ETX_H_
#define ETX_H_
#include <stdint.h>
#include <stdbool.h>

enum nwk_interface_id;
enum addrtype;

/* Fraction that is used when calculating moving average
   e.g. ETX = 7/8 * current ETX + 1/8 * new ETX sample
   Range for value can be from 1 to 11 */
#define ETX_MOVING_AVERAGE_FRACTION      3     // n >> 3, 1/8

typedef struct etx_storage {
    uint16_t        etx;                       /*!< 12 bits fraction */
    unsigned        accumulated_failures: 5;
    unsigned        tmp_etx: 1;
    unsigned        linkIdr: 4;
    unsigned        etx_samples: 3;
    unsigned        drop_bad_count: 2;
} etx_storage_t;

typedef struct etx_sample_storage {
    uint16_t           attempts_count;         /*!< TX attempt count */
    uint8_t            etx_timer;              /*!< Count down from configured value 0 means that ETX Update is possible done again*/
    uint8_t            received_acks;          /*!< Received ACK's */
    uint8_t            transition_count;
} etx_sample_storage_t;

/**
 * \brief A function to update ETX value based on transmission attempts
 *
 *  Update is made based on failed and successful message sending
 *  attempts for a message.
 *
 * \param interface_id Interface identifier
 * \param attempts number of attempts to send message
 * \param success was message sending successful
 * \param attribute_index Neighbour attribute index
 * \param mac64_addr_ptr Neighbour MAC64
 */
void etx_transm_attempts_update(int8_t interface_id, uint8_t attempts, bool success, uint8_t attribute_index, const uint8_t *mac64_addr_ptr);

/**
 * \brief A function to read local ETXvalue
 *
 *  Returns local ETX value for an address
 *
 * \param mac64_addr_ptr long MAC address
 *
 * \return 0x0100 to 0xFFFF ETX value (8 bit fraction)
 * \return 0x0000 address unknown
 */
uint16_t etx_local_etx_read(int8_t interface_id, uint8_t attribute_index);

/**
 * \brief A function to allocte ETX storage list
 *
 * \param interface_id interface id
 * \param etx_storage_size Size of storage. 0 will free allocate data
 *
 * \return false Allocate fail
 * \return true Allocate OK
 */
bool etx_storage_list_allocate(int8_t interface_id, uint8_t etx_storage_size);

/**
 * \brief A function to read ETX storage for defined neighbour
 *
 * \param interface_id interface id
 * \param attribute_index Neighbour attribute index
 *
 * \return Pointer to ETX storage
 * \return NULL When unknow interface or attribute
 */
etx_storage_t *etx_storage_entry_get(int8_t interface_id, uint8_t attribute_index);

/**
 * \brief A function for update cached ETX calculation
 *
 *  Shuold be call second intevall
 *
 * \param interface_id Interface ID
 * \param seconds_update Seconds Update
 *
 */
void etx_cache_timer(int seconds_update);

/**
 * \brief A function for enable cached ETX mode and parametrs
 *
 *  Default values for enabled Cached mode is wait time 60 seconds, etx_max_update is 0 (disabled) and etx_min_sample_count is 4.
 *  ETX update will happen when min wait time is reached and also reached min etx sample count.
 *
 * \param min_wait_time how many seconds must wait before do new ETX
 * \param etx_min_attempts_count define how many TX attempts process must be done for new ETX. Min accepted value is 4.
 * \param init_etx_sample_count How Many sample is need to init etx calculate
 *
 * \return true Enable is OK
 * \return false Memory allocation fail
 *
 */
bool etx_cached_etx_parameter_set(uint8_t min_wait_time, uint8_t etx_min_attempts_count, uint8_t init_etx_sample_count);


/**
 * \brief A function for set Maxium ETX update
 *
 * ETX RFC define that that Max value for update is 0xffff but this API cuold make that Poor link start go down slowly.
 *
 * \param etx_max_update 0 No limit for Update higher value means. This pameter will change normal ETX which could be 0xffff.
 *
 */
void etx_max_update_set(uint16_t etx_max_update);

/**
 * \brief A function for configure limit for detect bad init ETX sample
 *
 * \param bad_link_level 0 No limit and >=2 Level
 * \param max_allowed_drops How many init probe is accepted to drop 1-2 are possible values
 *
 */
bool etx_allow_drop_for_poor_measurements(uint8_t bad_link_level, uint8_t max_allowed_drops);

/**
 * \brief A function for set Maxium ETX value
 *
 * ETX RFC define that that Max value is 0xffff but this API cuold make that Poor link start go down slowly.
 *
 * \param etx_max 0 No limit for higher value means. This pameter will change normal ETX which could be 0xffff.
 *
 */
void etx_max_set(uint16_t etx_max);

#endif
