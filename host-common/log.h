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
#include <string.h>
#include <signal.h>
#include <time.h>

#define __PRINT(color, msg, ...) \
    fprintf(stderr, "[" #color "m" msg "[0m\n", ##__VA_ARGS__)

#define __PRINT_WITH_LINE(color, msg, ...) \
    __PRINT(color, "%s():%d: " msg, __func__, __LINE__, ##__VA_ARGS__)

#define __PRINT_WITH_TIME(color, msg, ...) \
    do {                                                             \
        struct timespec tp;                                          \
        clock_gettime(CLOCK_REALTIME, &tp);                          \
        __PRINT(color, "%jd.%06jd: " msg, tp.tv_sec, tp.tv_nsec / 1000, ##__VA_ARGS__); \
    } while (0)

extern unsigned int g_enabled_traces;

enum {
    TR_BUS  = 0x01,
    TR_HDLC = 0x02,
    TR_RF   = 0x04,
};

#define TRACE2(COND, ...) \
    do {                                                             \
        if (g_enabled_traces & (COND)) {                             \
            if (__VA_OPT__(!) false)                                 \
                __PRINT_WITH_TIME(90, __VA_ARGS__);                  \
            else                                                     \
                __PRINT_WITH_TIME(90, "%s:%d", __FILE__, __LINE__);  \
        }                                                            \
    } while (0)

#define TRACE(...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT_WITH_LINE(94, __VA_ARGS__);                      \
        else                                                         \
            __PRINT_WITH_LINE(94, "trace");                          \
    } while (0)

#define INFO(...) \
    do {                                                             \
        __PRINT(0, __VA_ARGS__);                                     \
    } while (0)

#define WARN(...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT(93, "warning: " __VA_ARGS__);                    \
        else                                                         \
            __PRINT_WITH_LINE(93, "warning");                        \
    } while (0)

#define WARN_ON(cond, ...) \
    ({                                                               \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                __PRINT(93, "warning: " __VA_ARGS__);                \
            else                                                     \
                __PRINT_WITH_LINE(93, "warning: \"%s\"", #cond);     \
        }                                                            \
        __ret;                                                       \
    })

#define FATAL(code, ...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT(31, __VA_ARGS__);                                \
        else                                                         \
            __PRINT_WITH_LINE(31, "fatal error");                    \
        exit(code);                                                  \
    } while (0)

#define FATAL_ON(cond, code, ...) \
    do {                                                             \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                __PRINT(31, __VA_ARGS__);                            \
            else                                                     \
                __PRINT_WITH_LINE(31, "fatal error: \"%s\"", #cond); \
            exit(code);                                              \
        }                                                            \
    } while (0)

#define BUG(...) \
    do {                                                             \
        if (__VA_OPT__(!) false)                                     \
            __PRINT_WITH_LINE(91, "bug: " __VA_ARGS__);              \
        else                                                         \
            __PRINT_WITH_LINE(91, "bug");                            \
        raise(SIGTRAP);                                              \
    } while (0)

#define BUG_ON(cond, ...) \
    do {                                                             \
        typeof(cond) __ret = (cond);                                 \
        if (__ret) {                                                 \
            if (__VA_OPT__(!) false)                                 \
                __PRINT_WITH_LINE(91, "bug: " __VA_ARGS__);          \
            else                                                     \
                __PRINT_WITH_LINE(91, "bug: \"%s\"", #cond);         \
            raise(SIGTRAP);                                          \
        }                                                            \
    } while (0)

enum bytes_str_options {
    DELIM_SPACE     = 0x01, // Add space between each bytes
    DELIM_COLON     = 0x02, // Add colon between each bytes
    ELLIPSIS_ABRT   = 0x04, // Assert if output is too small
    ELLIPSIS_STAR   = 0x08, // End output with * if too small
    ELLIPSIS_DOTS   = 0x10, // End output with ... if too small
};
char *bytes_str(const void *in_start, int in_len, const void **in_done, char *out_start, int out_len, int opt);

#endif
