/*
 * Copyright (c) 2015-2018, Pelion and affiliates.
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


#include "nsconfig.h"
#include "Service_Libs/fhss/channel_list.h"

#include "common_functions.h"
#include "ns_trace.h"

#include <stdint.h>
#include <string.h>

const int CHANNEL_LIST_SIZE_IN_BITS = 8 * 32;

static bool channel_list_bit_test32(uint32_t word, int_fast8_t bit_number);
static bool channel_list_bit_test(const uint32_t *list, int bit_number);

// test bit by number
static bool channel_list_bit_test32(uint32_t word, int_fast8_t bit_number)
{
    bool bitSet;

    if (word & (1U << bit_number)) {
        bitSet = true;
    } else {
        bitSet = false;
    }
    return bitSet;
}

static bool channel_list_bit_test(const uint32_t *list, int bit_number)
{
    const int_fast8_t word_index = bit_number / 32;
    const int_fast8_t bit_index = bit_number % 32;

    return channel_list_bit_test32(list[word_index], bit_index);
}

// count the amount of channels enabled in a list
int channel_list_count_channels(const uint32_t *list)
{

    int channel_count = 0;

    for (int index = 0; index < CHANNEL_LIST_SIZE_IN_BITS; index++) {

        if (channel_list_bit_test(list, index)) {
            channel_count++;
        }
    }

    return channel_count;
}
