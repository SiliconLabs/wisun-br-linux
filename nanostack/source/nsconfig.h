/*
 * Copyright (c) 2014-2020, Pelion and affiliates.
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

/**
 * Build definitions, for now we define the default configuration here.
 */

#ifndef _NANOSTACK_SOURCE_CONFIG_H
#define _NANOSTACK_SOURCE_CONFIG_H

#include <stdint.h>

#define __ns_cfg_header(x) #x
#define _ns_cfg_header(x) __ns_cfg_header(configs/cfg_##x.h)
#define ns_cfg_header(x) _ns_cfg_header(x)

#ifndef NSCONFIG
#error "NSCONFIG is not set"
#endif

#include ns_cfg_header(NSCONFIG)

#endif // ifndef _NANOSTACK_SOURCE_CONFIG_H

