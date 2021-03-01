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

#define WARN(msg, ...) \
    do {                                                             \
        fprintf(stderr, "%s: " msg "\n", __func__, ##__VA_ARGS__);   \
    } while (0)

#define WARN_ON(cond, ...) \
    ({ \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                WARN(__VA_ARGS__);                                   \
            else                                                     \
                WARN("warning: \"%s\"", #cond);                      \
        }                                                            \
        __ret;                                                       \
    })

#define FATAL(code, msg, ...) \
    do {                                                             \
        fprintf(stderr, "%s: " msg "\n", __func__, ##__VA_ARGS__);   \
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

#define BUG(msg, ...) \
    do {                                                             \
        fprintf(stderr, "%s: " msg "\n", __func__, ##__VA_ARGS__);   \
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
