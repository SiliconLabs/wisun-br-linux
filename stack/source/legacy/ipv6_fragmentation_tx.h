/*
 * Copyright (c) 2015-2017, Pelion and affiliates.
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
#ifndef IPV6_FRAGMENTATION_TX_H
#define IPV6_FRAGMENTATION_TX_H

#ifdef HAVE_IPV6_FRAGMENT

typedef struct buffer buffer_t;

buffer_t *ipv6_frag_down(buffer_t *dgram_buf);

#else

#define ipv6_frag_down(buf) buffer_free(buf)

#endif

#endif
