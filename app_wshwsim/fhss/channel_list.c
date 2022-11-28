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
#include <stdint.h>
#include <string.h>
#include "common/log_legacy.h"
#include "common/bits.h"
#include "stack-services/common_functions.h"

#include "channel_list.h"

const int CHANNEL_LIST_SIZE_IN_BITS = 8 * 32;

// count the amount of channels enabled in a list
int channel_list_count_channels(const uint8_t *list)
{
    int channel_count = 0;

    for (int i = 0; i < CHANNEL_LIST_SIZE_IN_BITS; i++)
        if (bittest(list, i))
            channel_count++;
    return channel_count;
}
