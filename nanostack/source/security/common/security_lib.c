/*
 * Copyright (c) 2013-2019, 2021, Pelion and affiliates.
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
#include <stdint.h>
#include "mbed-client-libservice/ns_trace.h"
#include <string.h>
#include "nanostack-event-loop/eventOS_event.h"
#include "mbed-client-libservice/nsdynmemLIB.h"
#include "core/include/ns_socket.h"
#include "nwk_interface/protocol.h"
#include "nanostack/shalib.h"
#include "common/rand.h"
#include "security/tls/tls_lib.h"
#include "security/tls/tls_ccm_crypt.h"
#include "security/common/sec_lib.h"
#include "nanostack/net_nvm_api.h"
#include "mbed-client-libservice/common_functions.h"



//************************ECC Certificates end
