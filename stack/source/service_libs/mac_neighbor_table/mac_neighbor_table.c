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
#include "common/log_legacy.h"
#include "common/endian.h"
#include "common/utils.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "nwk_interface/protocol.h"
#include "6lowpan/mac/mac_common_defines.h"
#include "6lowpan/ws/ws_cfg_settings.h"

#include "core/ns_address_internal.h"

mac_neighbor_table_t *mac_neighbor_table_create(uint8_t table_size, neighbor_entry_remove_notify *remove_cb, neighbor_entry_nud_notify *nud_cb, void *user_indentifier)
{
    mac_neighbor_table_t *table_class = malloc(sizeof(mac_neighbor_table_t));
    mac_neighbor_table_entry_t *entry;

    if (!table_class)
        return NULL;

    memset(table_class, 0, sizeof(mac_neighbor_table_t));

    table_class->list_total_size = table_size;
    table_class->table_user_identifier = user_indentifier;
    table_class->user_nud_notify_cb = nud_cb;
    table_class->user_remove_notify_cb = remove_cb;

    ns_list_init(&table_class->neighbour_list);

    // The size of the neighbor table is an information given by the RCP.
    // The index field is used to set neighbor information in the RCP.
    // This early allocation process makes the maintenance of this
    // index easier.
    for (uint8_t i = 0; i < table_size; i++) {
        entry = malloc(sizeof(mac_neighbor_table_entry_t));

        if (!entry)
            return NULL;

        memset(entry, 0, sizeof(mac_neighbor_table_entry_t));
        entry->index = i;
        ns_list_add_to_end(&table_class->neighbour_list, entry);
    }

    return table_class;
}

void mac_neighbor_table_delete(mac_neighbor_table_t *table_class)
{
    mac_neighbor_table_neighbor_list_clean(table_class);
    free(table_class);
}

static mac_neighbor_table_entry_t *neighbor_table_class_entry_validate(mac_neighbor_table_t *table_class, mac_neighbor_table_entry_t *neighbor_entry)
{
    ns_list_foreach(mac_neighbor_table_entry_t, cur, &table_class->neighbour_list)
        if (cur == neighbor_entry)
            return cur;

    return NULL;
}

void neighbor_table_class_remove_entry(mac_neighbor_table_t *table_class, mac_neighbor_table_entry_t *entry)
{
    uint8_t entry_index;

    if (!neighbor_table_class_entry_validate(table_class, entry)) {
        WARN("15.4 neighbor not found");
        return;
    }

    table_class->neighbour_list_size--;
    if (entry->nud_active)
        entry->nud_active = false;

    if (table_class->user_remove_notify_cb)
        table_class->user_remove_notify_cb(entry, table_class->table_user_identifier);

    TRACE(TR_NEIGH_15_4, "15.4 neighbor del %s / %ds", tr_eui64(entry->mac64), entry->lifetime);

    entry_index = entry->index;
    memset(entry, 0, sizeof(mac_neighbor_table_entry_t) - sizeof(entry->link));
    entry->index = entry_index;
}

void mac_neighbor_table_neighbor_list_clean(mac_neighbor_table_t *table_class)
{
    if (!table_class) {
        return;
    }
    ns_list_foreach_safe(mac_neighbor_table_entry_t, cur, &table_class->neighbour_list) {
        if (!cur->in_use)
            continue;
        neighbor_table_class_remove_entry(table_class, cur);
    }
}

void mac_neighbor_table_neighbor_timeout_update(int time_update)
{
    struct net_if *interface = protocol_stack_interface_info_get();
    mac_neighbor_table_t *table_class;
    ws_neighbor_class_entry_t *ws_neighbor;

    if (!(interface->lowpan_info & INTERFACE_NWK_ACTIVE))
        return;

    table_class = interface->mac_parameters.mac_neighbor_table;
    if (!table_class) {
        return;
    }

    ns_list_foreach_safe(mac_neighbor_table_entry_t, cur, &table_class->neighbour_list) {
        if (!cur->in_use)
            continue;

        ws_neighbor = ws_neighbor_class_entry_get(&interface->ws_info.neighbor_storage, cur->mac64);

        if (!ws_neighbor)
            continue;

        if (cur->lifetime > time_update) {
            if (cur->lifetime == 0xffffffff && cur->link_lifetime == 0xffffffff) {
                continue; //Infinite Lifetime too not touch
            }

            cur->lifetime -= time_update;

            // The Wi-SUN specification does not detail the usage of NUD for LFNs.
            // According to RFC 9010 section 9.2.1, a RUL is supposed to
            // refresh a registered address periodically.
            // Therefore we disable NUD for LFNs here.
            if (!table_class->user_nud_notify_cb ||
                ws_neighbor->node_role == WS_NR_ROLE_LFN ||
                cur->nud_active)
                continue;

            if (table_class->user_nud_notify_cb(cur, table_class->table_user_identifier)) {
                cur->nud_active = true;
            }

        } else {
            neighbor_table_class_remove_entry(table_class, cur);
        }
    }
}

void mac_neighbor_table_entry_init(mac_neighbor_table_entry_t *entry, const uint8_t *mac64, uint32_t lifetime)
{
    entry->in_use = true;
    memcpy(entry->mac64, mac64, 8);
    entry->lifetime = lifetime;
    entry->link_lifetime = lifetime;
}

mac_neighbor_table_entry_t *mac_neighbor_table_entry_allocate(mac_neighbor_table_t *table_class, const uint8_t *mac64, uint8_t role)
{
    mac_neighbor_table_entry_t *entry;

    ns_list_foreach(mac_neighbor_table_entry_t, cur, &table_class->neighbour_list)
        if (!cur->in_use) {
            entry = cur;
            break;
        }

    if (!entry)
        return NULL;

    table_class->neighbour_list_size++;
    entry->in_use = true;
    memcpy(entry->mac64, mac64, 8);
    entry->lifetime = ws_cfg_neighbour_temporary_lifetime_get(role);
    entry->link_lifetime = ws_cfg_neighbour_temporary_lifetime_get(role);

    TRACE(TR_NEIGH_15_4, "15.4 neighbor add %s / %ds", tr_eui64(entry->mac64), entry->lifetime);
    return entry;
}

void mac_neighbor_table_trusted_neighbor(mac_neighbor_table_entry_t *neighbor_entry)
{
    if (neighbor_entry->trusted_device)
        return;

    neighbor_entry->lifetime = neighbor_entry->link_lifetime;
    neighbor_entry->trusted_device = true;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor trusted %s / %ds", tr_eui64(neighbor_entry->mac64), neighbor_entry->lifetime);
}

void mac_neighbor_table_refresh_neighbor(mac_neighbor_table_t *table, const uint8_t *eui64, uint32_t link_lifetime)
{
    mac_neighbor_table_entry_t *neighbor = mac_neighbor_table_get_by_mac64(table, eui64);

    if (neighbor) {
        neighbor->link_lifetime = link_lifetime;
        neighbor->lifetime = link_lifetime;
        TRACE(TR_NEIGH_15_4, "15.4 neighbor refresh %s / %ds", tr_eui64(neighbor->mac64), neighbor->lifetime);
    }
}

mac_neighbor_table_entry_t *mac_neighbor_table_get_by_mac64(mac_neighbor_table_t *table_class, const uint8_t *address)
{
    ns_list_foreach(mac_neighbor_table_entry_t, cur, &table_class->neighbour_list) {
        if (!cur->in_use)
            continue;
        if (memcmp(cur->mac64, address, 8) == 0)
            return cur;
    }

    return NULL;
}
