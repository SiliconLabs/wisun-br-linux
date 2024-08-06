/*
 * Copyright (c) 2015-2017, 2019, Pelion and affiliates.
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


#ifndef IPV6_RESOLUTION_H_
#define IPV6_RESOLUTION_H_
#include <stdint.h>
#include <stdbool.h>

struct ipv6_neighbour;
struct ipv6_neighbour_cache;
struct buffer;
struct net_if;
enum addrtype;

struct ipv6_neighbour *ipv6_interface_resolve_new(struct net_if *cur, struct buffer *buf);
void ipv6_interface_resolve_send_ns(struct ipv6_neighbour_cache *cache, struct ipv6_neighbour *entry, bool unicast, uint8_t seq);
struct ipv6_neighbour_cache *ipv6_neighbour_cache_by_interface_id(int8_t interface_id);
bool ipv6_map_ip_to_ll(struct net_if *cur, struct ipv6_neighbour *n, const uint8_t ip_addr[16], enum addrtype *ll_type, const uint8_t **ll_addr_out);

#endif /* IPV6_RESOLUTION_H_ */
