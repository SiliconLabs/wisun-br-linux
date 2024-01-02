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
#ifndef NET_INTERFACE_H_
#define NET_INTERFACE_H_
#include <stdint.h>

typedef struct arm_certificate_entry {
    const uint8_t *cert;           /**< Certificate pointer. */
    const uint8_t *key;            /**< Key pointer. */
    uint16_t cert_len;             /**< Certificate length. */
    uint16_t key_len;              /**< Key length. */
} arm_certificate_entry_s;

#endif
