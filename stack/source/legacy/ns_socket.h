/*
 * Copyright (c) 2008-2017, 2019-2020, Pelion and affiliates.
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
#ifndef _NS_SOCKET_H
#define _NS_SOCKET_H

#include "common/log.h"
#include "core/ns_buffer.h"
#include "core/ns_error_types.h"

typedef struct socket socket_t;

// FIXME: this enum is referenced, but the purpose is not clear
typedef enum socket_family {
    SOCKET_FAMILY_NONE,
    SOCKET_FAMILY_IPV6,
} socket_family_e;

static inline void socket_init(void)
{
}

static inline void socket_list_print(char sep)
{
    WARN();
}

#endif
