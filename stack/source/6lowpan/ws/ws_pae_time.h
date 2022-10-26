/*
 * Copyright (c) 2020, Pelion and affiliates.
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
 * ws_pae_time_old_or_new_select selected old or new time (based on difference)
 *
 * \param old_time old time
 * \param new_time new time
 *
 * \return old or new time
 *
 */
uint64_t ws_pae_time_old_or_new_select(uint64_t old_time, uint64_t new_time);

/**
 * ws_pae_time_old_and_new_validate validate old and new time (based on difference)
 *
 * \param old_time old time
 * \param new_time new time
 *
 * \return TRUE old time is valid, FALSE old time is not valid
 *
 */
bool ws_pae_time_old_and_new_validate(uint64_t old_time, uint64_t new_time);

/**
 * ws_pae_current_time_get gets current time
 *
 * \return current time in seconds after 1970
 *
 */
uint64_t ws_pae_current_time_get(void);

/**
 * ws_pae_current_time_update updates current time
 *
 * \param seconds seconds to be added to current time
 *
 */
void ws_pae_current_time_update(uint16_t seconds);

/**
 * ws_pae_stored_time_check_and_set stored time check and set current time
 *
 * \param stored_time stored time
 *
 * \return < 0 failure
 * \return >= 0 success
 */
int8_t ws_pae_stored_time_check_and_set(uint64_t stored_time);

#endif
