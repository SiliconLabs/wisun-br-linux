/*
 * Copyright (c) 2013-2019, Pelion and affiliates.
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
#include "common/hal_interrupt.h"
#include "common/log_legacy.h"
#include "stack-services/common_functions.h"
#include "stack/nwk_stats_api.h"

#include "core/ns_socket.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "common_protocols/icmpv6.h"
#include "common_protocols/udp.h"
#include "common_protocols/ipv6_constants.h"
#include "rpl/rpl_data.h"
#include "6lowpan/nd/nd_router_object.h"
#include "6lowpan/iphc_decode/cipv6.h"

#include "6lowpan/bootstraps/network_lib.h"

#define TRACE_GROUP "nw"

#define MAC_MLME_SACN_PERIO_PARAM 5

/**
 * \brief Check That Network Have IPv6 Address Ready.
 *
 * \return 1 when IPv6 address is valid and 0 when it is not valid
 */

uint8_t nwk_ready(nwk_interface_id_e id)
{
    uint8_t ret_val = 0;
    protocol_interface_info_entry_t *cur = 0;
    cur = protocol_stack_interface_info_get(id);
    if (cur) {
        if ((cur->lowpan_info & INTERFACE_NWK_BOOTSTRAP_ADDRESS_REGISTER_READY)) {
            ret_val =  1;
        }
    }
    return ret_val;

}

void network_library_init(void)
{
    socket_init();
    address_module_init();
    //SET MAC_MLME Handler
    protocol_init();
}
