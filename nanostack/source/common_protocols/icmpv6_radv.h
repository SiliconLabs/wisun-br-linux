/*
 * Copyright (c) 2014-2015, 2017, Pelion and affiliates.
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
#ifndef _ICMPV6_RADV_H
#define _ICMPV6_RADV_H

struct protocol_interface_info_entry;
struct buffer;

void icmpv6_radv_init(struct protocol_interface_info_entry *cur);
struct buffer *icmpv6_rs_handler(struct buffer *buf, struct protocol_interface_info_entry *cur);
void icmpv6_radv_timer(uint16_t ticks);
void icmpv6_restart_router_advertisements(struct protocol_interface_info_entry *cur, const uint8_t abro[16]);
void icmpv6_stop_router_advertisements(struct protocol_interface_info_entry *cur, const uint8_t *abro);
void icmpv6_trigger_ra_from_rs(struct protocol_interface_info_entry *cur, const uint8_t dest[16], const uint8_t abro[16]);

#define icmpv6_radv_enable(cur) ((void) ((cur)->adv_send_advertisements = true))
#define icmpv6_radv_disable(cur) ((void) ((cur)->adv_send_advertisements = false))
#define icmpv6_radv_is_enabled(cur) (cur)->adv_send_advertisements
#define icmpv6_radv_max_rtr_adv_interval(cur) (cur)->max_rtr_adv_interval

#endif /* _ICMPV6_RADV_H */
