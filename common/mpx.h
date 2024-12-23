/*
 * Copyright (c) 2018-2019, Pelion and affiliates.
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
#ifndef MPX_H
#define MPX_H
#include <stdint.h>
#include <stdbool.h>

struct iobuf_write;

enum {
    MPX_FT_FULL_FRAME                   = 0b000,
    MPX_FT_FULL_FRAME_SMALL_MULTILEX_ID = 0b001,
    MPX_FT_FIRST_OR_SUB_FRAGMENT        = 0b010,
    MPX_FT_LAST_FRAGMENT                = 0b100,
    MPX_FT_ABORT                        = 0b110,
};

struct mpx_ie {
    unsigned    transfer_type: 3;
    unsigned    transaction_id: 5;
    uint8_t     fragment_number;
    uint16_t    total_upper_layer_size;
    uint16_t    multiplex_id;
    const uint8_t *frame_ptr;
    uint16_t    frame_length;
};

bool mpx_ie_parse(const uint8_t *ptr, uint16_t length, struct mpx_ie *ie);
void mpx_ie_write(struct iobuf_write *buf, const struct mpx_ie *ie);

#endif
