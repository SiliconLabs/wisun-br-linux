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

#ifndef RANDOM_EARLY_DETECTION_H
#define RANDOM_EARLY_DETECTION_H

/**
 * This mechanism is described on Wikipedia[1].
 *
 * [1]: https://en.wikipedia.org/wiki/Random_early_detection
*/

#include <stdint.h>
#include <stdbool.h>

struct red_config {
    uint16_t weight;                /*< Weight for new sample len, 256 disabled average */
    uint16_t threshold_min;         /*< Threshold Min value which start possibility start drop a packet */
    uint16_t threshold_max;         /*< Threshold Max this value give max Probability for configured value over that every new packet will be dropped*/
    uint8_t drop_max_probability;   /*< Max probability for drop packet between threshold_min and threshold_max threshold */

    uint32_t average_queue_size;    /*< Average queue size Scaled by 256 1.0 is 256 */
    uint16_t count;                 /*< Missed Packet drop's. This value is incremented when average queue is over min threshold and packet is not dropped */
};

#define RED_AVERAGE_WEIGHT_DISABLED 256     /*< Average is disabled */
#define RED_AVERAGE_WEIGHT_HALF     128     /*< Average weight for new sample is 0.5*new + 0.5 to last one */
#define RED_AVERAGE_WEIGHT_QUARTER  64      /*< Average weight for new sample is 1/4 + 3/4 to last one */
#define RED_AVERAGE_WEIGHT_EIGHTH   32      /*< Average weight for new sample is 1/8 + 7/8 to last one */

/**
 * \brief Create Random early detection data
 *
 * Function will config parameters how wide are Random Early detection drop will work.
 *
 * How to use parameters:
 *
 * Weight is definition how message queue Average (AQ) is calculated. Smaller weight will give smoother AQ update.
 *
 *  AQ = (1-weight) * average_queue + weight*sampleLen;
 *
 *  * RED_AVERAGE_WEIGHT_DISABLED disable Average by max weight to new sample length
 *  * RED_AVERAGE_WEIGHT_HALF last average*0.5 + 0.5*new sample: Smooth Average light packet filter
 *  * RED_AVERAGE_WEIGHT_QUARTER last average*0.75 + 0.25*new sample: Medium packet burst filtering
 *  * RED_AVERAGE_WEIGHT_EIGHTH last average*7/8 + 1/8*new sample: Good for filtering packet burst and big networks
 *
 * How to configure packet drop possibility:
 *
 * Define base Probability based current AQ, average length
 *
 * tmp_probability = drop_max_probability *(AQ - threshold_min) / (threshold_max - threshold_min);
 *
 * probability = tmp_probability / (1 - count*tmp_probability)
 *
 * threshold_min and threshold_max threshold define area for random early detection drop. When Average queue size go over Min threshold packet may drop by given maxProbability.
 * System will work smoother if min -max threshold range is wide. Then random drop is may cover small data burst until Max threshold Avarage is reached.
 * After Max every new packet will be dropped.
 *
 * Config Examples.
 *
 * Threshold values must be set how much device can buffer data.
 *
 * Small size data buffering:
 * red_allocate(32, 96, 10, RED_AVERAGE_WEIGHT_QUARTER)
 *
 * Medium size data buffering:
 * red_allocate(96, 256, 10, RED_AVERAGE_WEIGHT_EIGHTH)
 *
 * High size buffering:
 * red_allocate(256, 600, 10, RED_AVERAGE_WEIGHT_EIGHTH)
 *
 * \param threshold_min min average queue size which enable packet drop
 * \param threshold_max average queue size when all new packets start drop
 * \param drop_max_probability is percent probability to drop packet 100-1 are possible values
 * \param weight accepted values 256-1, 256 is 1.0 weight which mean that new queue size overwrite old. 128 is 0.5 which gives 0.5 from old + 0.5 from new.
 * \return Pointer for allocated structure, NULL if memory allocation fail
 */
struct red_config *red_allocate(uint16_t threshold_min, uint16_t threshold_max,
                            uint8_t drop_max_probability, uint16_t weight);

void red_init(struct red_config *red_config);

/**
 * \brief Free Random early detection data
 *
 *
 * \param red_info pointer to data
 */
void red_free(struct red_config *red_info);

/**
 * \brief Random early detection drop function
 *
 * \param red_info pointer, which is created user include all configurations
 * \param sampleLen Current queue length
 * \return true Drop packet
 * \return false Packet can be added to queue
 */
bool red_congestion_check(struct red_config *red_info);

/**
 * \brief Random early detection Average queue calculate
 *
 *  Call this when add or remove from queue
 *
 * \param red_info pointer, which is created user include all configurations
 * \param sampleLen Current queue length
 *
 * \return New average
 */
uint16_t red_aq_calc(struct red_config *red_info, uint16_t sample_len);

/**
 * \brief Read Random early detection Average queue size
 *
 *  Call this when add or remove from queue
 *
 * \param red_info pointer, which is created user include all configurations
 *
 * \return Current average
 */
uint16_t red_aq_get(struct red_config *red_info);

#endif
