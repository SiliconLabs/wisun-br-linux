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
#include <inttypes.h>
#include "common/log_legacy.h"
#include "common/ns_list.h"

#include "net/protocol.h"
#include "security/protocols/sec_prot_cfg.h"
#include "ws/ws_config.h"

#include "ws/ws_pae_timers.h"

#define TRACE_GROUP "wspt"

#define SECONDS_IN_MINUTE                       60

#define DEFAULT_GTK_REQUEST_IMIN                4                       // 4 minutes
#define DEFAULT_GTK_REQUEST_IMAX                64                      // 64 minutes
