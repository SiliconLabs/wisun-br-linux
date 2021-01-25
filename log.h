/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>

#define WARN(msg, ...) \
    do {                                                             \
        fprintf(stderr, "%s: " msg "\n", __func__, ##__VA_ARGS__);   \
    } while (0)

#define WARN_ON(cond) ({ \
    int __ret = !!(cond);                                            \
    if (__ret)                                                       \
        fprintf(stderr, "%s: warning: \"%s\"\n", __func__, #cond);   \
    __ret;                                                           \
})

#define FATAL(code, msg, ...) \
    do {                                                             \
        fprintf(stderr, "%s: " msg "\n", __func__, ##__VA_ARGS__);   \
        exit(code);                                                  \
    } while (0)

#define FATAL_ON(cond, code) \
    do {                                                             \
        if (cond) {                                                  \
            fprintf(stderr, "%s: fatal: \"%s\"\n", __func__, #cond); \
            exit(code);                                              \
        }                                                            \
    } while (0)

#define BUG(msg, ...) \
    do {                                                             \
        fprintf(stderr, "%s: " msg "\n", __func__, ##__VA_ARGS__);   \
        exit(-1);                                                    \
    } while (0)

#define BUG_ON(cond) \
    do {                                                             \
        if (cond) {                                                  \
            fprintf(stderr, "%s: bug: \"%s\"\n", __func__, #cond);   \
            exit(-1);                                                \
        }                                                            \
    } while (0)

#endif
