/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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
#ifndef LEGACY_DHCPV6_CLIENT_H
#define LEGACY_DHCPV6_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "common/log.h"

static inline void dhcp_client_configure(int8_t interface, bool renew_uses_solicit, bool one_client_for_this_interface, bool no_address_hint)
{
    WARN();
}

#endif
