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
#ifndef FNV_HASH_H
#define FNV_HASH_H
#include <stdint.h>
#include <stddef.h>

/*
 * Implement FNV (Fowler/Noll/Vo) hash algorithm[1]. This implementation is
 * tuned to calculate IPv6 flow identifiers:
 *    - it only implements FNV-1a 32bits
 *    - it reverse data before adding them to the hash
 *
 * [1]: https://www.ietf.org/id/draft-eastlake-fnv-20.html
 */

uint32_t fnv_hash_reverse_32_init(const uint8_t *data, size_t len);
uint32_t fnv_hash_reverse_32_update(const uint8_t *data, size_t len, uint32_t hash);

#endif
