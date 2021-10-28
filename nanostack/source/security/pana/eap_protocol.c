/*
 * Copyright (c) 2017-2019, Pelion and affiliates.
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
#include "core/include/ns_socket.h"
#include "nwk_interface/protocol.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/bootstraps/protocol_6lowpan_bootstrap.h"
#ifdef ECC
#include "libX509_V3.h"
#include "ecc.h"
#endif
#include "security/common/sec_lib.h"
#include "net_nvm_api.h"
#include "security/pana/pana.h"

#include "common_functions.h"
#include "security/pana/pana_eap_header.h"
void pana_eap_fragmetation_start_filter(bool state)
{
    (void) state;
}

void pana_eap_fragmetation_force_timeout(bool state)
{
    (void) state;
}

void pana_eap_fragmetation_force_retry(bool state)
{
    (void) state;
}

