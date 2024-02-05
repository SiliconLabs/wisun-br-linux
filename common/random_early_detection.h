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

void red_init(struct red_config *red_config);

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
