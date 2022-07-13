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

/* Function attribute - C11 "noreturn" or C++11 "[[noreturn]]" */
#ifndef NS_NORETURN
#if defined  __cplusplus && __cplusplus >= 201103L
#define NS_NORETURN [[noreturn]]
#elif !defined  __cplusplus && __STDC_VERSION__ >= 201112L
#define NS_NORETURN _Noreturn
#elif defined __GNUC__
#define NS_NORETURN __attribute__((__noreturn__))
#elif defined __IAR_SYSTEMS_ICC__
#define NS_NORETURN __noreturn
#else
#define NS_NORETURN
#endif
#endif

/**
 * Marker for functions or objects that may be unused, suppressing warnings.
 * Place after the identifier:
 * ~~~
 *    static int X MAYBE_UNUSED = 3;
 *    static int foo(void) MAYBE_UNUSED;
 * ~~~
 */
#if defined __GNUC__
#define MAYBE_UNUSED __attribute__((unused))
#else
#define MAYBE_UNUSED
#endif

/** \brief Pragma to suppress warnings about unusual pointer values.
 *
 * Useful if using "poison" values.
 */
#ifdef __IAR_SYSTEMS_ICC__
#define NS_FUNNY_INTPTR_OK      _Pragma("diag_suppress=Pe1053")
#define NS_FUNNY_INTPTR_RESTORE _Pragma("diag_default=Pe1053")
#else
#define NS_FUNNY_INTPTR_OK
#define NS_FUNNY_INTPTR_RESTORE
#endif

/** \brief Pragma to suppress warnings about always true/false comparisons
 */
#if defined __GNUC__ && NS_GCC_VERSION >= 40600
#define NS_FUNNY_COMPARE_OK         _Pragma("GCC diagnostic push") \
                                    _Pragma("GCC diagnostic ignored \"-Wtype-limits\"")
#define NS_FUNNY_COMPARE_RESTORE    _Pragma("GCC diagnostic pop")
#else
#define NS_FUNNY_COMPARE_OK
#define NS_FUNNY_COMPARE_RESTORE
#endif

/** \brief Pragma to suppress warnings arising from dummy definitions.
 *
 * Useful when you have function-like macros that returning constants
 * in cut-down builds. Can be fairly cavalier about disabling as we
 * do not expect every build to use this macro. Generic builds of
 * components should ensure this is not included by only using it in
 * a ifdef blocks providing dummy definitions.
 */
#if defined __IAR_SYSTEMS_ICC__
// controlling expression is constant
#define NS_DUMMY_DEFINITIONS_OK _Pragma("diag_suppress=Pe236")
#else
#define NS_DUMMY_DEFINITIONS_OK
#endif


#endif /* NS_TYPES_H */
