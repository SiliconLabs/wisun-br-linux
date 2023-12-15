/*
 * Copyright (c) 2015-2019, Pelion and affiliates.
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
 * \file protocol_6lowpan_interface.c
 * \brief Add short description about this file!!!
 *
 */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/log_legacy.h"
#include "common/endian.h"
#include "service_libs/mac_neighbor_table/mac_neighbor_table.h"

#include "app_wsbrd/rcp_api_legacy.h"
#include "nwk_interface/protocol.h"
#include "common_protocols/ipv6_constants.h"
#include "common_protocols/icmpv6.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/nd/nd_router_object.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/lowpan_adaptation_interface.h"
#include "6lowpan/fragmentation/cipv6_fragmenter.h"

#include "6lowpan/bootstraps/protocol_6lowpan.h"

static int8_t set_6lowpan_nwk_up(struct net_if *cur)
{
    int8_t ret_val = 1;

    if ((cur->lowpan_info & INTERFACE_NWK_ACTIVE) == 0) {
        /* Change Idle-> Active */
        cur->nwk_bootstrap_state = ER_ACTIVE_SCAN;
        cur->lowpan_info |= INTERFACE_NWK_BOOTSTRAP_ACTIVE | INTERFACE_NWK_ACTIVE; //Set Active Bootstrap
        cur->bootstrap_state_machine_cnt = 2;
        cur->interface_mode = INTERFACE_UP;
        ret_val = 0;
    }
    return ret_val;
}

int8_t nwk_6lowpan_up(struct net_if *cur)
{
    int8_t ret_val;

    ret_val = set_6lowpan_nwk_up(cur);
    if (ret_val == 0) {
        protocol_6lowpan_interface_common_init(cur);

        cur->nwk_mode = ARM_NWK_GP_IP_MODE;
    }

    return ret_val;
}
