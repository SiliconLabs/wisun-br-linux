/*
 * Copyright (c) 2015-2018, 2020, Pelion and affiliates.
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
#include "nsconfig.h"
#include "ns_types.h"
#include "ns_trace.h"
#include "fhss_api.h"
#include "fhss_config.h"
#include "fhss.h"
#include "fhss_common.h"
#include "fhss_ws.h"
#include "fhss_statistics.h"
#include "fhss_channel.h"
#include "channel_list.h"
#include "nsdynmemLIB.h"
#include "eventOS_event.h"
#include "eventOS_callback_timer.h"
#include <string.h>

#define TRACE_GROUP "fhssc"

static fhss_structure_t *fhss_struct = NULL;

fhss_structure_t *fhss_allocate_instance(fhss_api_t *fhss_api, const fhss_timer_t *fhss_timer)
{
    if (fhss_struct || !fhss_api || !fhss_timer) {
        return NULL;
    }
    fhss_struct = ns_dyn_mem_alloc(sizeof(fhss_structure_t));
    if (!fhss_struct) {
        return NULL;
    }
    memset(fhss_struct, 0, sizeof(fhss_structure_t));
    fhss_struct->fhss_api = fhss_api;
    fhss_struct->platform_functions = *fhss_timer;
    if (!fhss_struct->platform_functions.fhss_resolution_divider) {
        fhss_struct->platform_functions.fhss_resolution_divider = 1;
    }
    return fhss_struct;
}

int8_t fhss_free_instance(fhss_api_t *fhss_api)
{
    if (!fhss_struct || fhss_struct->fhss_api != fhss_api) {
        return -1;
    }
    ns_dyn_mem_free(fhss_struct);
    fhss_struct = NULL;
    return 0;
}

fhss_structure_t *fhss_get_object_with_timer_id(const int8_t timer_id)
{
    if (timer_id < 0 || !fhss_struct) {
        return NULL;
    }
    if (fhss_struct->fhss_event_timer == timer_id) {
        return fhss_struct;
    }
    return NULL;
}

fhss_structure_t *fhss_get_object_with_api(const fhss_api_t *fhss_api)
{
    if (!fhss_api || !fhss_struct) {
        return NULL;
    }
    if (fhss_struct->fhss_api == fhss_api) {
        return fhss_struct;
    }
    return NULL;
}

int8_t fhss_disable(fhss_structure_t *fhss_structure)
{
    if (!fhss_structure) {
        return -1;
    }
    fhss_structure->fhss_api->synch_state_set(fhss_structure->fhss_api, FHSS_UNSYNCHRONIZED, 0);
    ns_dyn_mem_free(fhss_structure->ws->tr51_channel_table);
    ns_dyn_mem_free(fhss_structure->ws->tr51_output_table);
    ns_dyn_mem_free(fhss_structure->ws);
    fhss_failed_list_free(fhss_structure);
    ns_dyn_mem_free(fhss_structure);
    fhss_struct = 0;
    return 0;
}

void fhss_start_timer(fhss_structure_t *fhss_structure, uint32_t time, void (*callback)(const fhss_api_t *fhss_api, uint16_t))
{
    if (callback) {
        // Don't allow starting with zero slots
        if (time < fhss_structure->platform_functions.fhss_resolution_divider) {
            time = fhss_structure->platform_functions.fhss_resolution_divider;
        }
        fhss_structure->platform_functions.fhss_timer_start(time / fhss_structure->platform_functions.fhss_resolution_divider, callback, fhss_structure->fhss_api);
    }
}

void fhss_stop_timer(fhss_structure_t *fhss_structure, void (*callback)(const fhss_api_t *fhss_api, uint16_t))
{
    if (callback) {
        fhss_structure->platform_functions.fhss_timer_stop(callback, fhss_structure->fhss_api);
    }
}

int fhss_init_callbacks_cb(const fhss_api_t *api, fhss_callback_t *callbacks)
{
    fhss_structure_t *fhss_structure = fhss_get_object_with_api(api);
    if (!fhss_structure || !callbacks) {
        return -1;
    }
    fhss_structure->callbacks = *callbacks;
    return 0;
}


fhss_failed_tx_t *fhss_failed_handle_find(fhss_structure_t *fhss_structure, uint8_t handle)
{
    ns_list_foreach(fhss_failed_tx_t, cur, &fhss_structure->fhss_failed_tx_list) {
        if (cur->handle == handle) {
            return cur;
        }
    }
    return NULL;
}

int fhss_failed_handle_add(fhss_structure_t *fhss_structure, uint8_t handle, uint8_t bad_channel)
{
    fhss_failed_tx_t *failed_tx = ns_dyn_mem_alloc(sizeof(fhss_failed_tx_t));
    if (!failed_tx) {
        return -1;
    }
    failed_tx->bad_channel = bad_channel;
    failed_tx->retries_done = 0;
    failed_tx->handle = handle;
    ns_list_add_to_end(&fhss_structure->fhss_failed_tx_list, failed_tx);
    return 0;
}

int fhss_failed_handle_remove(fhss_structure_t *fhss_structure, uint8_t handle)
{
    fhss_failed_tx_t *failed_tx = fhss_failed_handle_find(fhss_structure, handle);
    if (!failed_tx) {
        return -1;
    }
    ns_list_remove(&fhss_structure->fhss_failed_tx_list, failed_tx);
    ns_dyn_mem_free(failed_tx); // Free entry
    return 0;
}

void fhss_failed_list_free(fhss_structure_t *fhss_structure)
{
    for (uint16_t i = 0; i < 256; i++) {
        fhss_failed_handle_remove(fhss_structure, i);
    }
}

uint32_t fhss_get_tx_time(fhss_structure_t *fhss_structure, uint16_t bytes_to_send, uint8_t phy_header_length, uint8_t phy_tail_length)
{
    return ((1000000 / (fhss_structure->callbacks.read_datarate(fhss_structure->fhss_api) / 8)) * (bytes_to_send + phy_header_length + phy_tail_length));
}
