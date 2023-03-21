/*
 * Copyright (c) 2016-2020, Pelion and affiliates.
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
#include "common/log_legacy.h"
#include "common/endian.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"
#include "stack/mac/mlme.h"
#include "stack/mac/mac_mcps.h"

#include "nwk_interface/protocol_abstract.h"
#include "nwk_interface/protocol.h"
#include "core/ns_address_internal.h"
#include "legacy/ns_socket.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"

#include "6lowpan/mac/mac_response_handler.h"

#define TRACE_GROUP "MRsH"
void mlme_confirm_handler(const mac_api_t *api, mlme_primitive_e id, const void *data)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(api->parent_id);
    mlme_get_conf_t *conf = (mlme_get_conf_t *)data;

    if (!cur)
        return;
    if (id != MLME_GET)
        goto err;
    if (conf->attr != macFrameCounter)
        goto err;
    if (conf->value_size != 4)
        goto err;
    cur->mac_parameters.security_frame_counter = *(uint32_t *)conf->value_pointer;
    return;

err:
    ERROR("%s: received unsupported message: %02x", __func__, id);
}

void mlme_indication_handler(const mac_api_t *api, mlme_primitive_e id, const void *data)
{
    mlme_comm_status_t *status = (mlme_comm_status_t *)data;

    if (id != MLME_COMM_STATUS)
        goto err;
    TRACE(TR_DROP, "drop %-9s: from %s: %02x", "15.4", tr_ipv6(status->SrcAddr), status->status);
    return;

err:
    ERROR("%s: received unsupported message: %02x", __func__, id);
}

