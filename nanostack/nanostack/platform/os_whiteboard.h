/*
 * Copyright (c) 2014-2017, Arm Limited and affiliates.
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
#ifndef OS_WHITEBOARD_H
#define OS_WHITEBOARD_H

#include "ns_types.h"

/**
 * \file os_whiteboard.h
 * \brief Platform API to modify the operating system routing table.
 * API to modify the operating system routing table and neighbor cache.
 * Required on Linux. Not needed on embedded systems.
 */

/** Mode selection */
enum add_or_remove {ADD = 1, REMOVE = 0};

#define whiteboard_os_modify(x,y) ((void)(x),(void)(y))

#endif /* OS_WHITEBOARD_H */
