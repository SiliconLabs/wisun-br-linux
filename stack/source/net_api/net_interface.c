/*
 * Copyright (c) 2014-2021, Pelion and affiliates.
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
/**
 * \file net.c
 * \brief Network API for library model
 *
 * The network API functions for library model
 */
#include <stdint.h>
#include <string.h>
#include "stack/mac/mac_api.h"

#include "nwk_interface/protocol.h"
#include "nwk_interface/protocol_stats.h"
#include "legacy/ns_socket.h"
#include "rpl/rpl_of0.h"
#include "rpl/rpl_mrhof.h"
#include "rpl/rpl_data.h"
#include "6lowpan/bootstraps/protocol_6lowpan.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_pae_controller.h"
