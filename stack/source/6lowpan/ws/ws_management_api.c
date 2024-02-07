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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "nwk_interface/protocol.h"
#include "6lowpan/ws/ws_management_api.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_cfg_settings.h"

#define TRACE_GROUP "wsmg"

int ws_management_network_size_set(
    int8_t interface_id,
    uint8_t network_size)
{
    struct net_if *cur;

    cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (interface_id >= 0 && !cur)
        return -1;

    ws_gen_cfg_t cfg;
    if (ws_cfg_network_size_get(&cfg) < 0) {
        return -3;
    }

    cfg.network_size = network_size;

    if (ws_cfg_network_size_set(cur, &cfg, 0) < 0) {
        return -3;
    }

    return 0;
}
