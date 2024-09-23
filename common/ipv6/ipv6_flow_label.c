/*
 * Copyright (c) 2016-2019, Pelion and affiliates.
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
#include "common/endian.h"
#include "common/fnv_hash.h"

#include "ipv6_flow_label.h"

static uint24_t ipv6_flow_label_fold32(uint32_t val32)
{
    uint24_t flow = (val32 ^ (val32 >> 20)) & 0xFFFFF;

    if (!flow)
        return 1;
    return flow;
}

uint24_t ipv6_flow_label(const uint8_t src_addr[16], const uint8_t dst_addr[16],
                          uint16_t src_port, uint16_t dst_port, uint8_t protocol)
{
    const uint8_t bytes[] = { dst_port >> 8, dst_port, src_port >> 8, src_port, protocol };
    uint32_t hash;

    /* Hash algorithms suggest starting with the low-order bytes, as they're
     * most likely to vary, increasing potential dispersion. This means using
     * the "reverse" function on the IP addresses, and we use the same reverse
     * for the other 3 tuple members to re-use the code.
     */
    hash = fnv_hash_reverse_32_init(src_addr, 16);
    hash = fnv_hash_reverse_32_update(dst_addr, 16, hash);
    hash = fnv_hash_reverse_32_update(bytes, sizeof(bytes), hash);

    return ipv6_flow_label_fold32(hash);
}

uint24_t ipv6_flow_label_tunnel(const uint8_t src_addr[16],
                                const uint8_t dst_addr[16],
                                uint24_t flow)
{
    uint8_t bytes[3];
    uint32_t hash;

    write_be24(bytes, flow & 0xFFFFF);
    hash = fnv_hash_reverse_32_init(bytes, sizeof(bytes));
    hash = fnv_hash_reverse_32_update(src_addr, 16, hash);
    hash = fnv_hash_reverse_32_update(dst_addr, 16, hash);

    return ipv6_flow_label_fold32(hash);
}
