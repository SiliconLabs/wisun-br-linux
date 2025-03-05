/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>

#include "common/crypto/ws_keys.h"
#include "common/mbedtls_extra.h"
#include "common/bits.h"

#include "log.h"

FILE *g_trace_stream = NULL;
unsigned int g_enabled_traces = 0;
bool g_enable_color_traces = true;

char *str_bytes(const void *in_start, size_t in_len, const void **in_done, char *out_start, size_t out_len, int opt)
{
    const char *delim = "";
    const char *ellipsis = "";
    const char *fmt = "%s%02x";
    const uint8_t *in = in_start;
    const uint8_t *in_end = in + in_len;
    char *out = out_start;
    char *out_end = out + out_len;
    char *ellipsis_ptr;
    int entry_len;

    BUG_ON(!out);
    BUG_ON(!out_len);

    if (opt & DELIM_SPACE)
        delim = " ";
    if (opt & DELIM_COLON)
        delim = ":";
    if (opt & DELIM_COMMA)
        delim = ", ";
    if (opt & FMT_LHEX)
        fmt = "%s%02x";
    if (opt & FMT_UHEX)
        fmt = "%s%02X";
    if (opt & FMT_DEC)
        fmt = "%s%d";
    if (opt & FMT_DEC_PAD)
        fmt = "%s%3d";
    if (opt & FMT_ASCII_PRINT)
        fmt = "%s\\x%02x";
    if (opt & FMT_ASCII_ALNUM)
        fmt = "%s\\x%02x";
    if (opt & ELLIPSIS_STAR)
        ellipsis = "*";
    if (opt & ELLIPSIS_DOTS)
        ellipsis = "...";

    if (in_done)
        *in_done = in;

    if (!in) {
        snprintf(out, out_len, "<null>");
        return out;
    }

    if (!in_len) {
        out[0] = '\0';
        return out;
    }

    ellipsis_ptr = NULL;
    while (in < in_end) {
        if ((opt & FMT_ASCII_ALNUM && isalnum(*in)) ||
            (opt & FMT_ASCII_PRINT && isprint(*in) && *in != '\\'))
            entry_len = snprintf(out, out_end - out, "%s%c", in == in_start ? "" : delim, *in);
        else
            entry_len = snprintf(out, out_end - out, fmt, in == in_start ? "" : delim, *in);
        if (out + entry_len + strlen(ellipsis) >= out_end && !ellipsis_ptr) {
            if (in_done)
                *in_done = in;
             ellipsis_ptr = out;
        }
        if (out + entry_len >= out_end) {
            if (opt & ELLIPSIS_ABRT)
                BUG("buffer is too small");
            snprintf(ellipsis_ptr, out_end - ellipsis_ptr, "%s", ellipsis);
            return out;
        }
        out += entry_len;
        in++;
    }
    if (in_done)
        *in_done = in;
    return out;
}

char *str_key(const uint8_t *in, int in_len, char *out, int out_len)
{
    return str_bytes(in, in_len, NULL, out, out_len, DELIM_COLON);
}

char *str_eui64(const uint8_t in[8], char out[STR_MAX_LEN_EUI64])
{
    return str_bytes(in, 8, NULL, out, STR_MAX_LEN_EUI64, DELIM_COLON);
}

char *str_ipv4(uint8_t in[4], char out[STR_MAX_LEN_IPV4])
{
    sprintf(out, "%d.%d.%d.%d", in[0], in[1], in[2], in[3]);
    return out;
}

char *str_ipv6(const uint8_t in[16], char out[STR_MAX_LEN_IPV6])
{
    inet_ntop(AF_INET6, in, out, STR_MAX_LEN_IPV6);
    return out;
}

char *str_ipv4_prefix(uint8_t in[], int prefix_len, char out[STR_MAX_LEN_IPV4_NET])
{
    uint8_t tmp[4] = { };

    bitcpy(tmp, in, prefix_len);
    str_ipv4(tmp, out);
    sprintf(out + strlen(out), "/%d", prefix_len);
    return out;
}

char *str_ipv6_prefix(const uint8_t in[], int prefix_len, char out[STR_MAX_LEN_IPV6_NET])
{
    uint8_t tmp[16] = { };

    bitcpy(tmp, in, prefix_len);
    str_ipv6(tmp, out);
    sprintf(out + strlen(out), "/%d", prefix_len);
    return out;
}

char *str_date(time_t tstamp, char out[STR_MAX_LEN_DATE])
{
    struct tm *tm;

    tm = localtime(&tstamp);
    strftime(out, STR_MAX_LEN_DATE, "%c %Z", tm);
    return out;
}

static __thread char trace_buffer[256];
static __thread int trace_idx = 0;
/*
 * trace_nested_counter allow to handle nested trace calls. For exemple:
 *  char *a() {
 *      DEBUG();
 *      ...;
 *  }
 *  ...
 *  DEBUG("%d", tr_bytes(...), tr_bytes(a()));
 */
static __thread int trace_nested_counter = 0;

void __tr_enter()
{
    trace_nested_counter++;
}

void __tr_exit()
{
    trace_nested_counter--;
    if (!trace_nested_counter)
        trace_idx = 0;
}

void __tr_vprintf(const char *color, const char *fmt, va_list ap)
{
    if (!g_trace_stream) {
        g_trace_stream = stdout;
        setlinebuf(stdout);
        g_enable_color_traces = isatty(fileno(g_trace_stream));
    }

    if (color && strcmp(color, "0") && g_enable_color_traces) {
        fprintf(g_trace_stream, "\x1B[%sm", color);
        vfprintf(g_trace_stream, fmt, ap);
        fprintf(g_trace_stream, "\x1B[0m\n");
    } else {
        vfprintf(g_trace_stream, fmt, ap);
        fprintf(g_trace_stream, "\n");
    }
}

void __tr_printf(const char *color, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    __tr_vprintf(color, fmt, ap);
    va_end(ap);
}

const char *tr_bytes(const void *in, int len, const void **in_done, int max_out, int opt)
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + max_out > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_bytes(in, len, in_done, out, max_out, opt);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_key(const uint8_t in[], int in_len)
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + in_len * 3 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_key(in, in_len, out, in_len * 3);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_eui64(const uint8_t in[8])
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + STR_MAX_LEN_EUI64 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_eui64(in, out);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv4(uint8_t in[4])
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + STR_MAX_LEN_IPV4 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv4(in, out);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv6(const uint8_t in[16])
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + STR_MAX_LEN_IPV6 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv6(in, out);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv4_prefix(uint8_t in[], int prefix_len)
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + STR_MAX_LEN_IPV4_NET > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv4_prefix(in, prefix_len, out);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv6_prefix(const uint8_t in[], int prefix_len)
{
    char *out = trace_buffer + trace_idx;

    BUG_ON(!trace_nested_counter, "%s must be called within a trace", __func__);
    if (trace_idx + STR_MAX_LEN_IPV6_NET > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv6_prefix(in, prefix_len, out);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_mbedtls_err(int err)
{
    char *out = trace_buffer + trace_idx;

    mbedtls_strerror(err, out, sizeof(trace_buffer) - trace_idx);
    trace_idx += strlen(out) + 1;
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_gtkname(uint8_t slot)
{
    char *out = trace_buffer + trace_idx;
    int len;

    len = snprintf(out, sizeof(trace_buffer) - trace_idx, "%s[%i]",
                   slot < WS_GTK_COUNT ? "gtk" : "lgtk",
                   slot < WS_GTK_COUNT ? slot : slot - WS_GTK_COUNT);
    if (len >= sizeof(trace_buffer) - trace_idx)
        return "[OVERFLOW]";
    trace_idx += len + 1;
    return out;
}
