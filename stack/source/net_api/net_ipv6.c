/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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
#include "stack/net_ipv6.h"

#include "core/ns_address_internal.h"
#include "common_protocols/ipv6_flow.h"
#include "legacy/ipv6_fragmentation_rx.h"
#include "nwk_interface/protocol.h"

#define TRACE_GROUP "nip6"

int8_t arm_nwk_ipv6_frag_mru(uint16_t frag_mru)
{
    uint16_t set_mru = ipv6_frag_set_mru(frag_mru);
    return set_mru >= frag_mru ? 0 : -1;
}

int8_t arm_nwk_ipv6_max_cache_entries(uint16_t max_entries)
{
    return ipv6_neighbour_set_current_max_cache(max_entries);
}

int8_t arm_nwk_ipv6_destination_cache_configure(uint16_t max_entries, uint16_t short_term_threshold, uint16_t long_term_threshold, uint16_t lifetime)
{
    return ipv6_destination_cache_configure(max_entries, short_term_threshold, long_term_threshold, lifetime);
}

int8_t arm_nwk_ipv6_neighbour_cache_configure(uint16_t max_entries, uint16_t short_term_threshold, uint16_t long_term_threshold, uint16_t lifetime)
{
    return ipv6_neighbour_cache_configure(max_entries, short_term_threshold, long_term_threshold, lifetime);
}

void arm_nwk_ipv6_auto_flow_label(bool auto_flow_label)
{
    ipv6_flow_auto_label = auto_flow_label;
}
