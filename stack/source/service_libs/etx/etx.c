/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "common/log_legacy.h"
#include "common/endian.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "service_libs/etx/etx.h"

#include "core/net_interface.h"
#include "core/ns_address_internal.h"
#include "nwk_interface/protocol_abstract.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"

#define TRACE_GROUP "etx"

typedef struct ext_neigh_info {
    uint8_t attribute_index;
    const uint8_t *mac64;
} ext_neigh_info_t;

static uint16_t etx_current_calc(uint16_t etx, uint8_t accumulated_failures);
static void etx_cache_entry_init(uint8_t attribute_index);

typedef struct ext_info {
    etx_storage_t *etx_storage_list;
    etx_sample_storage_t *etx_cache_storage_list;
    uint32_t max_etx_update;
    uint32_t max_etx;
    uint16_t init_etx_sample_count;
    uint8_t accum_threshold;
    uint8_t etx_min_sampling_time;
    uint8_t ext_storage_list_size;
    uint8_t min_attempts_count;
    uint8_t drop_bad_max;
    uint8_t bad_link_level;
    bool cache_sample_requested;
    int8_t interface_id;
} ext_info_t;

static ext_info_t etx_info = {
    .accum_threshold = 0,
    .etx_storage_list = NULL,
    .etx_cache_storage_list = NULL,
    .ext_storage_list_size = 0,
    .min_attempts_count = 0,
    .drop_bad_max = 0,
    .bad_link_level = 0,
    .max_etx_update = 0,
    .max_etx = 0xffff,
    .init_etx_sample_count = 1,
    .cache_sample_requested = false,
    .etx_min_sampling_time = 0,
    .interface_id = -1
};

static void etx_calculation(etx_storage_t *entry, uint16_t attempts, uint8_t acks_rx, ext_neigh_info_t *etx_neigh_info)
{
    uint32_t etx = attempts << (12 - ETX_MOVING_AVERAGE_FRACTION);

    if (acks_rx) {
        etx /= acks_rx;
    } else  {
        etx = 0xffff;
    }

    if ((etx_info.max_etx_update) && etx > etx_info.max_etx_update) {
        etx = etx_info.max_etx_update;
    }

    //tr_debug("Attempts %u ACK %u 1/8 update %u", attempts, acks_rx, etx);

    if (etx_info.cache_sample_requested && entry->etx_samples <= etx_info.init_etx_sample_count) {
        // skip the initial value as RSSI generated ETX is not valid
        etx = etx << 3;
    } else {
        //Add old etx 7/8 to new one
        etx += entry->etx - (entry->etx >> ETX_MOVING_AVERAGE_FRACTION);
    }

    if (etx > etx_info.max_etx) {
        etx = etx_info.max_etx;
    }

    // If real ETX value has been received do not update based on LQI or dBm
    entry->tmp_etx = false;

    entry->etx = etx;
    //Clear Drop count
    entry->drop_bad_count = 0;

    if (entry->etx_samples >= etx_info.init_etx_sample_count)
        etx_cache_entry_init(etx_neigh_info->attribute_index);
}

static void etx_cache_entry_init(uint8_t attribute_index)
{
    if (!etx_info.cache_sample_requested) {
        return;
    }

    etx_sample_storage_t *storage = etx_info.etx_cache_storage_list + attribute_index;
    storage->attempts_count = 0;
    storage->transition_count = 0;
    storage->etx_timer = etx_info.etx_min_sampling_time;
    storage->received_acks = 0;
}

static bool etx_update_possible(etx_sample_storage_t *storage, etx_storage_t *entry, uint16_t time_update)
{
    if (storage->etx_timer && time_update) {
        if (time_update >= storage->etx_timer) {
            storage->etx_timer = 0;
        } else {
            storage->etx_timer -= time_update;
        }
    }
    if (entry->etx_samples == etx_info.init_etx_sample_count && time_update == 0) {
        return true;
    }

    if (entry->etx_samples > etx_info.init_etx_sample_count) {
        //Slower ETX update phase
        if (storage->etx_timer == 0 || storage->attempts_count == 0xffff || storage->received_acks == 0xff) {
            //When time is going zero or too much sample data
            if (storage->transition_count >= etx_info.min_attempts_count) {
                //Got least min sample in requested time or max possible sample
                return true;
            } else if (storage->transition_count != storage->received_acks) {
                //Missing ack now ETX can be accelerated
                return true;
            }
        }
    }

    return false;

}


static etx_sample_storage_t *etx_cache_sample_update(uint8_t attribute_index, uint8_t attempts, bool ack_rx)
{
    etx_sample_storage_t *storage = etx_info.etx_cache_storage_list + attribute_index;
    storage->attempts_count += attempts;
    storage->transition_count++;
    if (ack_rx) {
        storage->received_acks++;
    }
    return storage;

}


static bool etx_drop_bad_sample(etx_storage_t *entry, uint8_t attempts, bool success)
{
    if (etx_info.bad_link_level == 0 || !success) {
        //Not enabled or Failure
        return false;
    }

    if (attempts < etx_info.bad_link_level) {
        //under configured value is accepted
        return false;
    }

    if (entry->drop_bad_count < etx_info.drop_bad_max) {
        //Accepted only configured max value 1-2
        entry->drop_bad_count++;
        return true;
    }

    return false;
}

/**
 * \brief A function to update ETX value based on transmission attempts
 *
 *  Update is made based on failed and successful message sending
 *  attempts for a message.
 *
 * \param attempts number of attempts to send message
 * \param success was message sending successful
 * \param addr_type address type, ADDR_802_15_4_SHORT or ADDR_802_15_4_LONG
 * \param addr_ptr PAN ID with 802.15.4 address
 */
void etx_transm_attempts_update(int8_t interface_id, uint8_t attempts, bool success, uint8_t attribute_index, const uint8_t *mac64_addr_ptr)
{
    uint8_t accumulated_failures;
    // Gets table entry
    etx_storage_t *entry = etx_storage_entry_get(interface_id, attribute_index);
    if (!entry) {
        return;
    }

    ext_neigh_info_t etx_neigh_info;
    etx_neigh_info.attribute_index = attribute_index;
    etx_neigh_info.mac64 = mac64_addr_ptr;

    if (entry->etx_samples < 7) {

        if (etx_drop_bad_sample(entry, attempts, success)) {
            tr_debug("Drop bad etx init %u", attempts);
            return;
        }
        entry->etx_samples++;
    }

    if (etx_info.cache_sample_requested) {

        etx_sample_storage_t *storage = etx_cache_sample_update(attribute_index, attempts, success);
        entry->accumulated_failures = 0;

        if (!etx_update_possible(storage, entry, 0)) {
            return;
        }

        etx_calculation(entry, storage->attempts_count, storage->received_acks, &etx_neigh_info);
        return;
    }

    accumulated_failures = entry->accumulated_failures;

    if (!success) {
        /* Stores failed attempts to estimate ETX and to calculate
           new ETX after successful sending */
        if (accumulated_failures + attempts < 32) {
            entry->accumulated_failures += attempts;
        } else {
            success = true;
        }
    }

    if (success) {
        entry->accumulated_failures = 0;
    }

    if (entry->etx) {

        if (success) {
            etx_calculation(entry, attempts + accumulated_failures, 1, &etx_neigh_info);
        }
    }
}

/**
 * \brief A function to read ETX value
 *
 *  Returns ETX value for an address
 *
 * \param interface_id network interface id
 * \param addr_type address type, ADDR_802_15_4_SHORT or ADDR_802_15_4_LONG
 * \param addr_ptr PAN ID with 802.15.4 address
 *
 * \return 0x0100 to 0xFFFF ETX value (8 bit fraction)
 * \return 0xFFFF address not associated
 * \return 0x0000 address unknown or other error
 * \return 0x0001 no ETX statistics on this interface
 */
uint16_t etx_read(int8_t interface_id, addrtype_e addr_type, const uint8_t *addr_ptr)
{
    struct net_if *interface = protocol_stack_interface_info_get_by_id(interface_id);

    if (!addr_ptr || !interface) {
        return 0;
    }

    if (interface->etx_read_override) {
        // Interface has modified ETX calculation
        return interface->etx_read_override(interface, addr_type, addr_ptr);
    }

    uint8_t attribute_index;

    //Must Support old MLE table and new still same time
    mac_neighbor_table_entry_t *mac_neighbor = mac_neighbor_table_address_discover(interface->mac_parameters.mac_neighbor_table, addr_ptr + PAN_ID_LEN, addr_type);
    if (!mac_neighbor) {
        return 0xffff;
    }
    attribute_index = mac_neighbor->index;

    etx_storage_t *entry = etx_storage_entry_get(interface_id, attribute_index);

    if (!entry) {
        return 0xffff;
    }

    uint16_t etx  = etx_current_calc(entry->etx, entry->accumulated_failures);
    etx >>= 4;

    return etx;
}

/**
 * \brief A function to read local incoming IDR value
 *
 *  Returns local incoming IDR value for an address
 *
 * \param mac64_addr_ptr long MAC address
 *
 * \return 0x0100 to 0xFFFF incoming IDR value (8 bit fraction)
 * \return 0x0000 address unknown
 */
uint16_t etx_local_etx_read(int8_t interface_id, uint8_t attribute_index)
{
    etx_storage_t *entry = etx_storage_entry_get(interface_id, attribute_index);
    if (!entry) {
        return 0;
    }

    if (etx_info.cache_sample_requested && entry->etx_samples < etx_info.init_etx_sample_count) {
        //Not ready yet
        return 0xffff;
    }

    return etx_current_calc(entry->etx, entry->accumulated_failures) >> 4;
}

/**
 * \brief A function to calculate current ETX
 *
 *  Returns current ETX value based on ETX and failed attempts. Return
 *  value is scaled by scaling factor
 *
 * \param etx ETX (12 bit fraction)
 * \param accumulated_failures failed attempts
 *
 * \return ETX value (12 bit fraction)
 */
static uint16_t etx_current_calc(uint16_t etx, uint8_t accumulated_failures)
{
    uint32_t current_etx;

    // If there is no failed attempts
    if (accumulated_failures == 0) {
        current_etx = etx;
    } else {
        /* Calculates ETX estimate based on failed attempts
           ETX = current ETX + 1/8 * (failed attempts << 12) */
        current_etx = etx + (accumulated_failures << (12 - ETX_MOVING_AVERAGE_FRACTION));
        if (current_etx > 0xffff) {
            current_etx = 0xffff;
        }
    }

    return current_etx;
}

bool etx_storage_list_allocate(int8_t interface_id, uint8_t etx_storage_size)
{
    if (!etx_storage_size) {
        free(etx_info.etx_storage_list);
        free(etx_info.etx_cache_storage_list);
        etx_info.etx_cache_storage_list = NULL;
        etx_info.cache_sample_requested = false;
        etx_info.etx_storage_list = NULL;
        etx_info.ext_storage_list_size = 0;
        return true;
    }

    if (etx_info.ext_storage_list_size == etx_storage_size) {
        return true;
    }

    free(etx_info.etx_storage_list);
    etx_info.cache_sample_requested = false;
    etx_info.ext_storage_list_size = 0;
    etx_info.etx_storage_list = malloc(sizeof(etx_storage_t) * etx_storage_size);

    if (!etx_info.etx_storage_list) {
        free(etx_info.etx_storage_list);
        etx_info.etx_storage_list = NULL;
        etx_info.ext_storage_list_size = 0;
        return false;
    }


    etx_info.ext_storage_list_size = etx_storage_size;
    etx_info.interface_id = interface_id;
    etx_storage_t *list_ptr = etx_info.etx_storage_list;
    for (uint8_t i = 0; i < etx_storage_size; i++) {
        memset(list_ptr, 0, sizeof(etx_storage_t));

        list_ptr++;
    }
    return true;

}

bool etx_cached_etx_parameter_set(uint8_t min_wait_time, uint8_t etx_min_attempts_count, uint8_t init_etx_sample_count)
{
    //No ini ETX allocation done yet
    if (etx_info.ext_storage_list_size == 0) {
        return false;
    }

    if (min_wait_time || etx_min_attempts_count) {
        if (init_etx_sample_count == 0) {
            return false;
        }

        if (!etx_info.etx_cache_storage_list) {
            //allocate
            etx_info.etx_cache_storage_list = malloc(sizeof(etx_sample_storage_t) * etx_info.ext_storage_list_size);

            if (!etx_info.etx_cache_storage_list) {
                return false;
            }
            etx_info.cache_sample_requested = true;
            etx_sample_storage_t *sample_list = etx_info.etx_cache_storage_list;
            for (uint8_t i = 0; i < etx_info.ext_storage_list_size; i++) {
                memset(sample_list, 0, sizeof(etx_sample_storage_t));
                sample_list++;
            }
        }

    } else {
        //Free Cache table we not need that anymore
        etx_info.cache_sample_requested = false;
        free(etx_info.etx_cache_storage_list);
        etx_info.etx_cache_storage_list = NULL;
    }

    etx_info.min_attempts_count = etx_min_attempts_count;
    etx_info.etx_min_sampling_time = min_wait_time;
    etx_info.init_etx_sample_count = init_etx_sample_count;

    return true;
}

bool etx_allow_drop_for_poor_measurements(uint8_t bad_link_level, uint8_t max_allowed_drops)
{
    //No ini ETX allocation done yet
    if (etx_info.ext_storage_list_size == 0) {
        return false;
    }

    if (bad_link_level == 0) {
        //Disable feature
        etx_info.bad_link_level = 0;
        etx_info.drop_bad_max = 0;
        return true;
    }

    if (bad_link_level < 2) {
        // 2 attepts is min value
        return false;
    }

    if (max_allowed_drops == 0 || max_allowed_drops > 3) {
        //Accepted values is 1-3
        return false;
    }


    etx_info.bad_link_level = bad_link_level;
    etx_info.drop_bad_max = max_allowed_drops;
    return true;
}

void etx_max_update_set(uint16_t etx_max_update)
{
    if (etx_max_update) {
        //Define MAX ETX UPDATE
        etx_info.max_etx_update = (etx_max_update / 128) << (12 - ETX_MOVING_AVERAGE_FRACTION);
    } else {
        etx_info.max_etx_update = 0;
    }
}

void etx_max_set(uint16_t etx_max)
{
    if (etx_max) {
        //Define MAX ETX possible value
        etx_info.max_etx = (etx_max / 128) << 12;
    } else {
        etx_info.max_etx = 0xffff;
    }
}

etx_storage_t *etx_storage_entry_get(int8_t interface_id, uint8_t attribute_index)
{
    if (etx_info.interface_id != interface_id || !etx_info.etx_storage_list || attribute_index >= etx_info.ext_storage_list_size) {
        return NULL;
    }

    etx_storage_t *entry = etx_info.etx_storage_list + attribute_index;
    return entry;
}

void etx_cache_timer(int seconds_update)
{
    struct net_if *interface = protocol_stack_interface_info_get();

    if (!etx_info.cache_sample_requested) {
        return;
    }

    if (!interface || !interface->mac_parameters.mac_neighbor_table) {
        return;
    }

    if (!(interface->lowpan_info & INTERFACE_NWK_ACTIVE)) {
        return;
    }

    ns_list_foreach(mac_neighbor_table_entry_t, neighbour, &interface->mac_parameters.mac_neighbor_table->neighbour_list) {

        etx_storage_t *etx_entry = etx_storage_entry_get(interface->id, neighbour->index);

        if (!etx_entry || etx_entry->tmp_etx) {
            continue;
        }
        etx_sample_storage_t *storage = etx_info.etx_cache_storage_list + neighbour->index;

        if (etx_update_possible(storage, etx_entry, seconds_update)) {
            ext_neigh_info_t etx_neigh_info;
            etx_neigh_info.attribute_index = neighbour->index;
            etx_neigh_info.mac64 = neighbour->mac64;
            etx_calculation(etx_entry, storage->attempts_count, storage->received_acks, &etx_neigh_info);
        }
    }

}
