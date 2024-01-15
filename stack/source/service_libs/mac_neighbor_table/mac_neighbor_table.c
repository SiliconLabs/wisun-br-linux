/*
 * Copyright (c) 2018-2020, Pelion and affiliates.
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


#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/time_extra.h"
#include "common/log.h"
#include "common/specs/ws.h"


#include "mac_neighbor_table.h"

void mac_neighbor_table_entry_init(mac_neighbor_table_entry_t *entry, const uint8_t *mac64, uint32_t lifetime)
{
    entry->in_use = true;
    memcpy(entry->mac64, mac64, 8);
    entry->lifetime = lifetime;
    entry->expiration_s = time_current(CLOCK_MONOTONIC) + lifetime;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor add %s / %ds", tr_eui64(entry->mac64), entry->lifetime);
}

void mac_neighbor_table_trusted_neighbor(mac_neighbor_table_entry_t *neighbor_entry)
{
    if (neighbor_entry->trusted_device)
        return;

    neighbor_entry->expiration_s = time_current(CLOCK_MONOTONIC) + neighbor_entry->lifetime;
    neighbor_entry->trusted_device = true;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor trusted %s / %ds", tr_eui64(neighbor_entry->mac64), neighbor_entry->lifetime);
}

void mac_neighbor_table_refresh_neighbor(mac_neighbor_table_entry_t *neighbor, uint32_t link_lifetime)
{
    neighbor->lifetime = link_lifetime;
    neighbor->expiration_s = time_current(CLOCK_MONOTONIC) + link_lifetime;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor refresh %s / %ds", tr_eui64(neighbor->mac64), neighbor->lifetime);
}
