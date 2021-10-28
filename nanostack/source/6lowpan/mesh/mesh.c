/*
 * Copyright (c) 2014-2017, 2019, Pelion and affiliates.
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
/**
 * \file mesh.c
 * \brief 6LoWPAN Mesh header handling (RFC 4944: S5.2, S11)
 *
 */

#include "nsconfig.h"
#include <string.h>
#include <ns_types.h>
#include <ns_list.h>
#include "ns_trace.h"
#include "common_functions.h"
#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "core/include/ns_socket.h"
#include "6lowpan/mesh/mesh.h"
#include "6lowpan/mac/mac_helper.h"

#define TRACE_GROUP "mesh"

