/*
 * Copyright (c) 2017-2021, Pelion and affiliates.
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

#ifndef WS_PAN_INFO_STORAGE_H
#define WS_PAN_INFO_STORAGE_H

#include <stdint.h>

void ws_pan_info_storage_read(int *bsi, int *pan_id, uint16_t *pan_version, uint16_t *lfn_version, char network_name[33]);
void ws_pan_info_storage_write(uint16_t bsi, uint16_t pan_id, uint16_t pan_version, uint16_t lfn_version, const char network_name[33]);

#endif
