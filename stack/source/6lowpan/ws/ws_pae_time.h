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

#ifndef WS_PAE_TIME_H_
#define WS_PAE_TIME_H_
#include <stdint.h>
#include <stdbool.h>

// Maximum difference in stored and indicated system time
#define SYSTEM_TIME_MAXIMUM_DIFF   (60 * 60 * 24 * 30) // One month
/**
 * ws_pae_current_time_get gets current time
 *
 * \return current time in seconds after 1970
 *
 */
uint64_t ws_pae_current_time_get(void);

#endif
