/*
 * Copyright (c) 2015-2018, Pelion and affiliates.
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

#ifndef NWK_INTERFACE_INCLUDE_PROTOCOL_ABSTRACT_H_
#define NWK_INTERFACE_INCLUDE_PROTOCOL_ABSTRACT_H_

#include <stdint.h>

struct rpl_domain;
struct fhss_api;

struct net_if *protocol_stack_interface_info_get_by_id(int8_t nwk_id);

#endif
