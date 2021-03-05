/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* A subset of usefull functions from
 * nanostack/source/Service_Libs/fhss/channel_list.c
 */
#include <stdint.h>
#include <stdbool.h>

#include "nanostack/source/Service_Libs/fhss/channel_list.h"

const int CHANNEL_LIST_SIZE_IN_BITS = 8 * 32;

static bool channel_list_bit_test32(uint32_t word, int_fast8_t bit_number)
{
    bool bitSet;

    if (word & ((uint32_t) 1 << bit_number)) {
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

