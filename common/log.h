/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#ifndef COMMON_LOG_H
#define COMMON_LOG_H
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include "common/backtrace_show.h"

/*
 * Use BUG() and BUG_ON() in the same ways than assert(). Consider this
 * statement as a part of the developer documentation. If the user encounter
 * this error, it means he won't be able to solve it himself and he should
 * send a bug report to the developer. For errors resulting from the user
 * environment, consider FATAL().
 *
 * Use FATAL() and FATAL_ON() if you have detected something wrong in the
 * environment. You consider it make no sense to continue, but it is not the
 * developper fault. You should always provide an explanation as precise as
 * possible to help the user. Typically:
 *     fd = open(filename, O_RDWR);
 *     FATAL_ON(fd < 0, 1, "open: %s: %m", filename);
 *
 * Use ERROR() and ERROR_ON() if you think there is a bug in a third-party
 * component and you are able to recover the error on your side (typically, you
 * are going to throw the request).
 *
 * Use WARN() and WARN_ON() to log unexpected events but you are able to
 * recover. They are not (yet) a bug and not (yet) fatal. It can also be used to
 * warn user about a degraded environment.
 *
 * Use INFO() to log some useful information for user. Use it thrifty. Only log
 * useful information for final user. Some people may consider these logs as a
 * part of the API.
 *
 * Use DEBUG() to add a temporary trace. DEBUG() shouldn't appears in final
 * code.
 *
 * Use TRACE() to provide debug traces in final code. TRACE() is always
 * conditional. The user have to set g_enabled_traces to make some traces
 * appear.
 *
 * BUG_ON(), FATAL_ON(), ERROR_ON() and WARN_ON(), allow to keep error handling
 * small enough. However, as soon as you add a description of the error, the
 * code will be probably clearer if you use the unconditional versions of these
 * macros.
 *
 * About the exit code used in FATAL(), for now the norm is:
 *   1: Error in the configuration file or command line
 *   2: A system call returned an error
 *   3: RCP not supported or corrupted
 */

extern FILE *g_trace_stream;
extern unsigned int g_enabled_traces;
extern bool g_enable_color_traces;

enum {
    TR_BUS        = 0x00000001,
    TR_HDLC       = 0x00000002,
    TR_CPC        = 0x00000004,
    TR_HIF        = 0x00000008,
    TR_HIF_EXTRA  = 0x00000010,
    TR_TUN        = 0x00000020,
    TR_TIMERS     = 0x00000100,
    TR_TRICKLE    = 0x00000200,
    TR_15_4_MNGT  = 0x00001000,
    TR_15_4_DATA  = 0x00002000,
    TR_EAP        = 0x00004000,
    TR_ICMP       = 0x00008000,
    TR_DHCP       = 0x00010000,
    TR_RPL        = 0x00020000,
    TR_IPV6       = 0x00040000,
    TR_QUEUE      = 0x00080000,
    TR_DROP       = 0x00100000,
    TR_TX_ABORT   = 0x00200000,
    TR_IGNORE     = 0x00400000,
    TR_NEIGH_15_4 = 0x01000000,
    TR_NEIGH_IPV6 = 0x02000000,
};
#define TRACE(COND, ...)          __TRACE(COND, "" __VA_ARGS__)
#define DEBUG(...)                __DEBUG("" __VA_ARGS__)
#define WARN(...)                 __WARN("" __VA_ARGS__)
#define WARN_ON(COND, ...)        __WARN_ON(COND, "" __VA_ARGS__)
#define ERROR(...)                __ERROR("" __VA_ARGS__)
#define ERROR_ON(COND, ...)       __ERROR_ON(COND, "" __VA_ARGS__)
#define FATAL(CODE, ...)          __FATAL(CODE, "" __VA_ARGS__)
#define FATAL_ON(COND, CODE, ...) __FATAL_ON(COND, CODE, "" __VA_ARGS__)
#define BUG(...)                  __BUG("" __VA_ARGS__)
#define BUG_ON(COND, ...)         __BUG_ON(COND, "" __VA_ARGS__)

#define STR_MAX_LEN_IPV6         46
#define STR_MAX_LEN_IPV6_NET     50
#define STR_MAX_LEN_IPV4         16
#define STR_MAX_LEN_IPV4_NET     19
#define STR_MAX_LEN_EUI64        24
#define STR_MAX_LEN_EUI48        18
#define STR_MAX_LEN_DATE         29

enum str_bytes_options {
    DELIM_SPACE     = 0x001, // Add space between each bytes
    DELIM_COLON     = 0x002, // Add colon between each bytes
    DELIM_COMMA     = 0x004, // Add comma and a space between each bytes
    ELLIPSIS_ABRT   = 0x008, // Assert if output is too small
    ELLIPSIS_STAR   = 0x010, // End output with * if too small
    ELLIPSIS_DOTS   = 0x020, // End output with ... if too small
    FMT_LHEX        = 0x040, // Use lower hexadecimal digits (%02x) (default)
    FMT_UHEX        = 0x080, // Use upper hexadecimal digits (%02X)
    FMT_DEC         = 0x100, // Use decimal digits (%u)
    FMT_DEC_PAD     = 0x200, // Use padded decimal digits (%3u)
    FMT_ASCII_ALNUM = 0x400, // Use plain chars and escaped values for non-alphanum values (%c or \\x%02x)
    FMT_ASCII_PRINT = 0x800, // Use plain chars and escaped values for non-printable values (%c or \\x%02x)
};

char *str_key(const uint8_t *in, int in_len, char *out, int out_len);
char *str_eui48(const uint8_t in[6], char out[STR_MAX_LEN_EUI48]);
char *str_eui64(const uint8_t in[8], char out[STR_MAX_LEN_EUI64]);
char *str_ipv4(uint8_t in[4], char out[STR_MAX_LEN_IPV4]);
char *str_ipv6(const uint8_t in[16], char out[STR_MAX_LEN_IPV6]);
char *str_ipv4_prefix(uint8_t in[], int prefix_len, char out[STR_MAX_LEN_IPV4_NET]);
char *str_ipv6_prefix(const uint8_t in[], int prefix_len, char out[STR_MAX_LEN_IPV6_NET]);
char *str_bytes(const void *in_start, size_t in_len, const void **in_done, char *out_start, size_t out_len, int opt);
char *str_date(time_t tstamp, char out[STR_MAX_LEN_DATE]);

const char *tr_key(const uint8_t in[], int in_len);
const char *tr_eui48(const uint8_t in[6]);
const char *tr_eui64(const uint8_t in[8]);
const char *tr_ipv4(uint8_t in[4]);
const char *tr_ipv6(const uint8_t in[16]);
const char *tr_ipv4_prefix(uint8_t in[], int prefix_len);
const char *tr_ipv6_prefix(const uint8_t in[], int prefix_len);
const char *tr_bytes(const void *in, int len, const void **in_done, int max_out, int opt);
const char *tr_mbedtls_err(int err);

void __tr_enter();
void __tr_exit();
__attribute__ ((format(printf, 2, 3)))
void __tr_printf(const char *color, const char *fmt, ...);
__attribute__ ((format(printf, 2, 0)))
void __tr_vprintf(const char *color, const char *fmt, va_list ap);

#define __TRACE(COND, MSG, ...) \
    do {                                                             \
        if (g_enabled_traces & (COND)) {                             \
            if (MSG[0] != '\0')                                      \
                __PRINT_WITH_TIME(90, MSG, ##__VA_ARGS__);           \
            else                                                     \
                __PRINT_WITH_TIME(90, "%s:%d", __FILE__, __LINE__);  \
        }                                                            \
    } while (0)

#define __DEBUG(MSG, ...) \
    do {                                                             \
        if (MSG[0] != '\0')                                          \
            __PRINT_WITH_LINE(94, MSG, ##__VA_ARGS__);               \
        else                                                         \
            __PRINT_WITH_LINE(94, "trace");                          \
    } while (0)

#define INFO(MSG, ...) \
    do {                                                             \
        __PRINT(0, MSG, ##__VA_ARGS__);                              \
    } while (0)

#define __WARN(MSG, ...) \
    do {                                                             \
        if (MSG[0] != '\0')                                          \
            __PRINT(93, "warning: " MSG, ##__VA_ARGS__);             \
        else                                                         \
            __PRINT_WITH_LINE(93, "warning");                        \
    } while (0)

#define __WARN_ON(COND, MSG, ...) \
    ({                                                               \
        bool __ret = (COND);                                         \
        if (__ret) {                                                 \
            if (MSG[0] != '\0')                                      \
                __PRINT(93, "warning: " MSG, ##__VA_ARGS__);         \
            else                                                     \
                __PRINT_WITH_LINE(93, "warning: \"%s\"", #COND);     \
        }                                                            \
        __ret;                                                       \
    })

#define __ERROR(MSG, ...) \
    do {                                                             \
        if (MSG[0] != '\0')                                          \
            __PRINT(31, "error: " MSG, ##__VA_ARGS__);               \
        else                                                         \
            __PRINT_WITH_LINE(31, "error");                          \
    } while (0)

#define __ERROR_ON(COND, MSG, ...) \
    ({                                                               \
        bool __ret = (COND);                                         \
        if (__ret) {                                                 \
            if (MSG[0] != '\0')                                      \
                __PRINT(31, "error: " MSG, ##__VA_ARGS__);           \
            else                                                     \
                __PRINT_WITH_LINE(31, "error: \"%s\"", #COND);       \
        }                                                            \
        __ret;                                                       \
    })

#define __FATAL(CODE, MSG, ...) \
    do {                                                             \
        if (MSG[0] != '\0')                                          \
            __PRINT(31, MSG, ##__VA_ARGS__);                         \
        else                                                         \
            __PRINT_WITH_LINE(31, "fatal error");                    \
        exit(CODE);                                                  \
    } while (0)

#define __FATAL_ON(COND, CODE, MSG, ...) \
    do {                                                             \
        if (COND) {                                                  \
            if (MSG[0] != '\0')                                      \
                __PRINT(31, MSG, ##__VA_ARGS__);                     \
            else                                                     \
                __PRINT_WITH_LINE(31, "fatal error: \"%s\"", #COND); \
            exit(CODE);                                              \
        }                                                            \
    } while (0)

#define __BUG(MSG, ...) \
    do {                                                             \
        if (MSG[0] != '\0')                                          \
            __PRINT_WITH_LINE(91, "bug: " MSG, ##__VA_ARGS__);       \
        else                                                         \
            __PRINT_WITH_LINE(91, "bug");                            \
        backtrace_show();                                            \
        raise(SIGTRAP);                                              \
        __builtin_unreachable();                                     \
    } while (0)

#define __BUG_ON(COND, MSG, ...) \
    do {                                                             \
        if (COND) {                                                  \
            if (MSG[0] != '\0')                                      \
                __PRINT_WITH_LINE(91, "bug: " MSG, ##__VA_ARGS__);   \
            else                                                     \
                __PRINT_WITH_LINE(91, "bug: \"%s\"", #COND);         \
            backtrace_show();                                        \
            raise(SIGTRAP);                                          \
            __builtin_unreachable();                                 \
        }                                                            \
    } while (0)

#define __PRINT(COLOR, MSG, ...) \
    do {                                                             \
        __tr_enter();                                                \
        __tr_printf(#COLOR, MSG, ##__VA_ARGS__);                     \
        __tr_exit();                                                 \
    } while(0)

#define __PRINT_WITH_TIME(COLOR, MSG, ...) \
    do {                                                             \
        struct timespec tp;                                          \
        clock_gettime(CLOCK_REALTIME, &tp);                          \
        __PRINT(COLOR, "%ju.%06ju: " MSG,                            \
                (uintmax_t)tp.tv_sec, (uintmax_t)tp.tv_nsec / 1000,  \
                ##__VA_ARGS__);                                      \
    } while (0)

#define __PRINT_WITH_LINE(COLOR, MSG, ...) \
    __PRINT(COLOR, "%s():%d: " MSG, __func__, __LINE__, ##__VA_ARGS__)

#define __PRINT_WITH_TIME_LINE(COLOR, MSG, ...) \
    __PRINT_WITH_TIME(COLOR, "%s():%d: " MSG, __func__, __LINE__, ##__VA_ARGS__)

#endif
