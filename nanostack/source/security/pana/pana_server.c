/*
 * Copyright (c) 2017-2019, 2021, Pelion and affiliates.
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
#include "eventOS_event.h"
#include "ns_trace.h"
#include "string.h"
#include "randLIB.h"
#include "nsdynmemLIB.h"
#include "core/include/ns_socket.h"
#include "nwk_interface/protocol.h"
#include "ccm.h"
#include "shalib.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#ifdef ECC
#include "libX509_V3.h"
#include "ecc.h"
#endif
#include "security/tls/tls_lib.h"
#include "security/common/sec_lib.h"
#include "net_nvm_api.h"
#include "security/pana/pana.h"
#include "security/pana/pana_internal_api.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mac_data_poll.h"
#include "6lowpan/nd/nd_router_object.h"
#include "common_protocols/udp.h"

#ifdef ECC
#include    "ecc.h"
#endif
#include "common_functions.h"
#include "security/pana/pana_nvm.h"
#include "security/pana/pana_avp.h"
#include "security/pana/pana_eap_header.h"
#include "security/pana/pana_header.h"
#include "security/pana/eap_protocol.h"
#include "net_pana_parameters_api.h"
#include "service_libs/mle_service/mle_service_api.h"
#include "6lowpan/nvm/nwk_nvm.h"

int8_t pana_server_nvm_callback_set(pana_server_update_cb *update_cb, pana_server_session_get_cb *nvm_get, pana_server_session_get_by_id_cb *nvm_session_get, uint8_t *nvm_static_buffer)
{
    (void)update_cb;
    (void)nvm_get;
    (void)nvm_session_get;
    (void)nvm_static_buffer;
    return -1;
}

int8_t pana_server_nvm_client_session_load(uint8_t *nvm_pointer)
{
    (void) nvm_pointer;
    return -1;
}

int8_t pana_server_restore_from_nvm(uint8_t *nvm_data, int8_t interface_id)
{
    (void) nvm_data;
    (void)interface_id;
    return -1;
}
