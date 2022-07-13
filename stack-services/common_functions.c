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

/**
 *
 * We follow C99 semantics, which requires precisely one external definition.
 * the code can be structured as per the example of ns_list:
 *
 * foo.h
 * -----
 * ~~~
 *    inline int my_func(int);
 *
 *    #if defined FOO_FN
 *    #ifndef FOO_FN
 *    #define FOO_FN inline
 *    #endif
 *    FOO_FN int my_func(int a)
 *    {
 *        definition;
 *    }
 *    #endif
 * ~~~
 * foo.c
 * -----
 * ~~~
 *    #define FOO_FN extern
 *    #include "foo.h"
 * ~~~
 * Which generates:
 * ~~~
 *                 Include foo.h
 *                 -------------
 *                 inline int my_func(int);
 *
 *                 // inline definition
 *                 inline int my_func(int a)
 *                 {
 *                     definition;
 *                 }
 *
 *                 Compile foo.c
 *                 -------------
 *    (from .h)    inline int my_func(int);
 *
 *                 // external definition
 *                 // because of no "inline"
 *                 extern int my_func(int a)
 *                 {
 *                     definition;
 *                 }
 * ~~~
 *
 * Note that even with inline keywords, whether the compiler inlines or not is
 * up to it. For example, gcc at "-O0" will not inline at all, and will always
 * call the real functions in foo.o.
 * At "-O2", gcc could potentially inline everything, meaning that foo.o is not
 * referenced at all.
 *
 * Alternatively, you could use "static inline", which gives every caller its
 * own internal definition. This is compatible with C++ inlining (which expects
 * the linker to eliminate duplicates), but in C it's less efficient if the code
 * ends up non-inlined, and it's harder to breakpoint. I don't recommend it
 * except for the most trivial functions (which could then probably be macros).
 */
#define COMMON_FUNCTIONS_FN extern

#include "stack-services/common_functions.h"
