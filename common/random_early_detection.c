/*
 * Copyright (c) 2020, Pelion and affiliates.
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "common/memutils.h"
#include "common/rand.h"

#include "random_early_detection.h"

// This value can't be bigger than 655
#define RED_PROB_SCALE 512
#define RED_PROB_SCALE_MAX (RED_PROB_SCALE * 100)
#define RED_RANDOM_PROB_MAX (RED_PROB_SCALE_MAX - 1)

struct red_info *red_allocate(uint16_t threshold_min, uint16_t threshold_max,
                              uint8_t drop_max_p, uint16_t weight)
{
    struct red_info *red_info = zalloc(sizeof(struct red_info));

    BUG_ON(weight == 0 || weight > 256);
    BUG_ON(drop_max_p == 0 || drop_max_p > 100);
    BUG_ON(threshold_max <= threshold_min);

    red_info->parameters.drop_max_probability = drop_max_p;
    red_info->parameters.threshold_max = threshold_max;
    red_info->parameters.threshold_min = threshold_min;
    red_info->parameters.weight = weight;
    return red_info;
}

void red_free(struct red_info *red_info)
{
    free(red_info);
}

uint16_t red_aq_calc(struct red_info *red_info, uint16_t sample_len)
{
    uint32_t average_sum;

    if (red_info->parameters.weight == RED_AVERAGE_WEIGHT_DISABLED || red_info->average_queue_size == 0) {
        red_info->average_queue_size = sample_len * 256;
        return sample_len;
    }

    // AQ = (1-weight) * average_queue + weight*sample_len
    // Now Sample is scaled by 256 which is not loosing so much tail at average

    // Weight Last Average part (1-weight) * average_queue with scaled 256
    average_sum = ((256 - red_info->parameters.weight) * red_info->average_queue_size) / 256;
    // Add new weighted sample lenght (weight*sample_len)
    average_sum += (red_info->parameters.weight * sample_len);

    // If sum is ODD add 1 this will help to not stuck like 1,99 average to -> 2
    if (average_sum & 1)
        average_sum++;

    // Store new average
    red_info->average_queue_size = average_sum;
    // Return always same format scaled than inn
    return red_aq_read(red_info);
}

uint16_t red_aq_read(struct red_info *red_info)
{
    return red_info->average_queue_size / 256;
}

bool red_congestion_check(struct red_info *red_info)
{
    uint16_t sample_len = red_aq_read(red_info);
    uint32_t tmp_probability;
    uint32_t probability;

    if (sample_len <= red_info->parameters.threshold_min) {
        red_info->count = 0;
        return false;
    }
    if (sample_len > red_info->parameters.threshold_max) {
        red_info->count = 0;
        return true;
    }

    // Calculate probability for packet drop
    // tmp_probability = drop_max_probability *(AQ - threshold_min) / (threshold_max - threshold_min);
    tmp_probability = (uint32_t)red_info->parameters.drop_max_probability * RED_PROB_SCALE *
                                (sample_len  - red_info->parameters.threshold_min) /
                                (red_info->parameters.threshold_max - red_info->parameters.threshold_min);

    // Next probability = tmp_probability / (1 - count*tmp_probability)
    // This will increase probability and

    // Calculate first divider part
    probability = red_info->count * tmp_probability;

    // Check that divider it is not >= 0
    if (probability >= RED_PROB_SCALE_MAX) {
        red_info->count = 0;
        return true;
    }

    // Calculate only when count * tmp_probability is smaller than scaler
    probability = (tmp_probability * RED_PROB_SCALE_MAX) / (RED_PROB_SCALE_MAX - probability);
    if (probability > rand_get_random_in_range(0, RED_RANDOM_PROB_MAX)) {
        // Drop packet
        red_info->count = 0;
        return true;
    }

    // Increment count next round check
    red_info->count++;
    return false;
}
