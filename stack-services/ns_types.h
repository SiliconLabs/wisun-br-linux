/*
 * Copyright (c) 2014-2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * ns_types.h - Basic compiler and type setup for Nanostack libraries.
 */
#ifndef NS_TYPES_H_
#define NS_TYPES_H_

/** \file
 * \brief Basic compiler and type setup
 *
 * We currently assume C99 or later.
 *
 * C99 features being relied on:
 *
 *   - <inttypes.h> and <stdbool.h>
 *   - inline (with C99 semantics, not C++ as per default GCC);
 *   - designated initialisers;
 *   - compound literals;
 *   - restrict;
 *   - [static N] in array parameters;
 *   - declarations in for statements;
 *   - mixing declarations and statements
 *
 * Compilers should be set to C99 or later mode when building Nanomesh source.
 * For GCC this means "-std=gnu99" (C99 with usual GNU extensions).
 *
 * Also, a little extra care is required for public header files that could be
 * included from C++, especially as C++ lacks some C99 features.
 *
 * (TODO: as this is exposed to API users, do we need a predefine to distinguish
 * internal and external use, for finer control? Not yet, but maybe...)
 */


#endif /* NS_TYPES_H */
