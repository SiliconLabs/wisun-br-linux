/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>

#define __PRINT(msg, ...) \
    fprintf(stderr, "%s: " msg "[0m\n", __func__, ##__VA_ARGS__)

#define TRACE(...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT("[36m" __VA_ARGS__);                           \
        else                                                         \
            __PRINT("[36m" "trace");                               \
    } while (0)

#define WARN(...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT("[93m" __VA_ARGS__);                           \
        else                                                         \
            __PRINT("[93m" "warning");                             \
    } while (0)

#define WARN_ON(cond, ...) \
    ({                                                               \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                WARN(__VA_ARGS__);                                   \
            else                                                     \
                WARN("warning: \"%s\"", #cond);                      \
        }                                                            \
        __ret;                                                       \
    })

#define FATAL(code, ...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT("[31m" __VA_ARGS__);                           \
        else                                                         \
            __PRINT("[31m" "fatal");                               \
        exit(code);                                                  \
    } while (0)

#define FATAL_ON(cond, code, ...) \
    do {                                                             \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                FATAL(code, __VA_ARGS__);                            \
            else                                                     \
                FATAL(code, "fatal: \"%s\"", #cond);                 \
        }                                                            \
    } while (0)

#define BUG(...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT("[91m" __VA_ARGS__);                           \
        else                                                         \
            __PRINT("[91m" "bug");                                 \
        raise(SIGTRAP);                                              \
    } while (0)

#define BUG_ON(cond, ...) \
    do {                                                             \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                BUG(__VA_ARGS__);                                    \
            else                                                     \
                BUG("bug: \"%s\"", #cond);                           \
        }                                                            \
    } while (0)

#endif
