/*
 * Copyright (c) 2020, Pelion and affiliates.
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
#include "common/log_legacy.h"
#include "stack/mac/fhss_api.h"
#include "stack/mac/fhss_config.h"

#include "fhss.h"
#include "fhss_common.h"
#include "fhss_ws.h"
#include "fhss_statistics.h"
#include "fhss_channel.h"

#define TRACE_GROUP "fhta"

int8_t fhss_set_optimal_packet_length(const fhss_api_t *fhss_api, uint16_t packet_length)
{
    (void) fhss_api;
    (void) packet_length;
    fhss_structure_t *fhss_structure = fhss_get_object_with_api(fhss_api);
    if (!fhss_structure) {
        return -1;
    }
    fhss_structure->optimal_packet_length = packet_length;
    fhss_set_txrx_slot_length(fhss_structure);
    tr_debug("Setting FHSS optimal packet length to: %u", fhss_structure->optimal_packet_length);
    return 0;
}

int8_t fhss_set_number_of_channel_retries(const fhss_api_t *fhss_api, uint8_t number_of_channel_retries)
{
    (void) fhss_api;
    (void) number_of_channel_retries;
    fhss_structure_t *fhss_structure = fhss_get_object_with_api(fhss_api);
    if (!fhss_structure || !fhss_structure->ws) {
        return -1;
    }
    fhss_structure->ws->fhss_configuration.config_parameters.number_of_channel_retries = number_of_channel_retries;
    tr_debug("Setting number of channel retries to: %u", number_of_channel_retries);
    return 0;
}
