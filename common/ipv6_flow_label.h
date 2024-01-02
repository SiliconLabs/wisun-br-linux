/*
 * Copyright (c) 2016-2017, Pelion and affiliates.
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
#ifndef IPV6_FLOW_LABEL_H
#define IPV6_FLOW_LABEL_H
#include <stdbool.h>

#include "common/int24.h"

/*
 * Flow label hash computation for RFC 6437, but using algorithm 8 as
 * suggested by "Comparing Hash Function Algorithms for the IPv6 Flow Label"
 * (Anderson, Brownlee, Carpenter 2012).
 *
 * ipv6_flow_label() can used when building our own IP headers from a transport
 * module while ipv6_flow_label_tunnel() aims to be used on tunnel entry, using
 * fields from inner header.
 */

uint24_t ipv6_flow_label(const uint8_t src_addr[16], const uint8_t dst_addr[16],
                         uint16_t src_port, uint16_t dst_port, uint8_t protocol);

uint24_t ipv6_flow_label_tunnel(const uint8_t src_addr[16],
                                const uint8_t dst_addr[16],
                                uint24_t flow);

#endif
