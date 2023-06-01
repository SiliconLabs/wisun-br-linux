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
#include <stdlib.h>
#include "common/endian.h"
#include "common/rand.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "stack/ws_test_api.h"
#include "stack/ws_management_api.h"
#include "stack/mac/fhss_config.h"
#include "stack/mac/mac_api.h"

#include "6lowpan/mac/mac_helper.h"
#include "nwk_interface/protocol.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bbr_api_internal.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_cfg_settings.h"
#include "6lowpan/ws/ws_bootstrap.h"

#define TRACE_GROUP "wste"

int ws_test_version_set(int8_t interface_id, uint8_t version)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    test_pan_version = version;
    if (cur) {
        cur->ws_info.version = version;
        if (ws_version_1_0(cur)) {
            cur->ws_info.pan_information.version = WS_FAN_VERSION_1_0;
        } else if (ws_version_1_1(cur)) {
            cur->ws_info.pan_information.version = WS_FAN_VERSION_1_1;
        }
    }
    return 0;
}

int ws_test_max_child_count_set(int8_t interface_id, uint16_t child_count)
{
    test_max_child_count_override = child_count;
    return 0;
}

int ws_test_gtk_set(int8_t interface_id, uint8_t *gtk[4])
{
    return ws_pae_controller_gtk_update(interface_id, gtk);
}

int ws_test_lgtk_set(int8_t interface_id, uint8_t *lgtk[3])
{
    return ws_pae_controller_lgtk_update(interface_id, lgtk);
}

int ws_test_active_key_set(int8_t interface_id, uint8_t index)
{
    return ws_pae_controller_active_key_update(interface_id, index);
}

int ws_test_next_gtk_set(int8_t interface_id, uint8_t *gtk[4])
{
    return ws_pae_controller_next_gtk_update(interface_id, gtk);
}

int ws_test_next_lgtk_set(int8_t interface_id, uint8_t *lgtk[3])
{
    return ws_pae_controller_next_lgtk_update(interface_id, lgtk);
}

int ws_test_neighbour_temporary_lifetime_set(int8_t interface_id, uint32_t temporary_lifetime)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (!cur)
        return -1;

    ws_cfg_neighbour_temporary_lifetime_set(temporary_lifetime);
    return 0;
}

int ws_test_procedure_trigger(int8_t interface_id, ws_test_proc_e procedure, void *parameters)
{
    struct net_if *cur = NULL;;

    (void) parameters;
    if (interface_id > 0) {
        cur = protocol_stack_interface_info_get_by_id(interface_id);
        if (!cur)
            return -1;
    } else {
        cur = protocol_stack_interface_info_get_wisun_mesh();
        if (!cur) {
            if (procedure != PROC_AUTO_ON && procedure != PROC_AUTO_OFF) {
                return -1;
            }
        }
    }

    return ws_bootstrap_test_procedure_trigger(cur, procedure);
}

