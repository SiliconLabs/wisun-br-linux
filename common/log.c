/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "bits.h"
#include "log.h"

unsigned int g_enabled_traces = 0;
bool g_enable_color_traces = true;

char *str_bytes(const void *in_start, size_t in_len, const void **in_done, char *out_start, size_t out_len, int opt)
{
    static const char *hex_l = "0123456789abcdef";
    static const char *hex_u = "0123456789ABCDEF";
    const char *hex = hex_l;
    const uint8_t *in = in_start;
    const uint8_t *in_end = in + in_len;
    char *out = out_start;
    char *out_end;

    char *ellipsis = "\0";
    char delim = '\0';
    bool fit = true;

    BUG_ON(!out);
    BUG_ON(!out_len);
    if (opt & UPPER_HEX)
        hex = hex_u;
    if (opt & DELIM_SPACE)
        delim = ' ';
    if (opt & DELIM_COLON)
        delim = ':';
    if (delim && out_len < in_len * 3)
        fit = false;
    if (!delim && out_len < in_len * 2 + 1)
        fit = false;

    if (!fit) {
        if (opt & ELLIPSIS_ABRT)
            BUG("buffer is too small");
        if (opt & ELLIPSIS_STAR)
            ellipsis = "*";
        if (opt & ELLIPSIS_DOTS)
            ellipsis = "...";
    }

    // Input buffer is null
    if (!in) {
        strncpy(out, "<null>", out_len - 1);
        goto out;
    }

    // Nothing to display just return empty string
    if (!in_len)
        goto out;

    // We can't write at least one byte
    if (out_len <= strlen(ellipsis) + 3) {
        strncpy(out, ellipsis, out_len - 1);
        goto out;
    }

    // Keep one byte for '\0'
    out_end = out + out_len - strlen(ellipsis) - 1;
    while (true) {
        *out++ = hex[*in >> 4];
        *out++ = hex[*in & 0xF];
        in++;
        if (in == in_end)
            break;
        if (delim && out_end - out < 3)
            break;
        if (!delim && out_end - out < 2)
            break;
        if (delim)
            *out++ = delim;
    }
    strcpy(out, ellipsis);

out:
    out_start[out_len - 1] = '\0';
    if (in_done)
        *in_done = in;
    return out_start;
}
char *str_bytes_ascii(const void *in_start, int in_len, char *out, int out_len, int opt)
{
    static const char *hex = "0123456789ABCDEF";
    const char *in = in_start;
    bool print_direct;
    bool fit = true;
    int i, j = 0;

    for (i = 0; i < in_len; i++) {
        print_direct = false;
        if (isalnum(in[i]))
            print_direct = true;
        else if (!(opt & ONLY_ALNUM) && isprint(in[i]) && in[i] != '\\')
            print_direct = true;
        if (print_direct && out_len - j > 1) {
            out[j++] = in[i];
        } else if (!print_direct && out_len - j > 4) {
            out[j++] = '\\';
            out[j++] = 'x';
            out[j++] = hex[in[i] / 8];
            out[j++] = hex[in[i] % 8];
        } else {
            fit = false;
            break;
        }
    }
    if (!fit && opt & ELLIPSIS_ABRT)
        BUG("buffer is too small");
    out[j++] = '\0';
    return out;
}

char *str_eui48(const uint8_t in[static 6], char out[static STR_MAX_LEN_EUI48])
{
    return str_bytes(in, 6, NULL, out, STR_MAX_LEN_EUI64, DELIM_COLON);
}

char *str_eui64(const uint8_t in[static 8], char out[static STR_MAX_LEN_EUI64])
{
    return str_bytes(in, 8, NULL, out, STR_MAX_LEN_EUI64, DELIM_COLON);
}

char *str_ipv4(uint8_t in[static 4], char out[static STR_MAX_LEN_IPV4])
{
    sprintf(out, "%d.%d.%d.%d", in[0], in[1], in[2], in[3]);
    return out;
}

char *str_ipv6(const uint8_t in[static 16], char out[static STR_MAX_LEN_IPV6])
{
    int zero_start = -1;
    int zero_len = 0;
    int last_zero_start = -1;
    int last_zero_len = 0;
    int i, j;

    // Find largest 0 sequence
    for (i = 0; i <= 8; i++) {
        if (i == 8 || in[i * 2] || in[i * 2 + 1]) {
            if (last_zero_len > zero_len) {
                zero_len = last_zero_len;
                zero_start = last_zero_start;
            }
            last_zero_start = -1;
            last_zero_len = 0;;
        } else {
            if (last_zero_start < 0)
                last_zero_start = i;
            last_zero_len++;
        }
    }

    i = j = 0;
    while (i < 8) {
        if (i == zero_start) {
            out[j++] = ':';
            i += zero_len;
        } else {
            if (i)
                out[j++] = ':';
            j += sprintf(out + j, "%x", in[i * 2] * 256 + in[i * 2 + 1]);
            i++;
        }
    }
    out[j] = '\0';
    return out;
}

char *str_ipv4_prefix(uint8_t in[], int prefix_len, char out[static STR_MAX_LEN_IPV4_NET])
{
    uint8_t tmp[4];

    bitcpy(tmp, in, prefix_len);
    str_ipv4(tmp, out);
    sprintf(out + strlen(out), "/%d", prefix_len);
    return out;
}

char *str_ipv6_prefix(const uint8_t in[], int prefix_len, char out[static STR_MAX_LEN_IPV6_NET])
{
    uint8_t tmp[16];

    bitcpy(tmp, in, prefix_len);
    str_ipv6(tmp, out);
    sprintf(out + strlen(out), "/%d", prefix_len);
    return out;
}

static __thread char trace_buffer[256];
static __thread int trace_idx = 0;

void tr_reset()
{
    trace_idx = 0;
}

const char *tr_bytes(const void *in, int len, const void **in_done, int max_out, int opt)
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + max_out > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_bytes(in, len, in_done, out, max_out, opt);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_bytes_ascii(const void *in, int len, int opt)
{
    char *out = trace_buffer + trace_idx;

    str_bytes_ascii(in, len, out, sizeof(trace_buffer) - trace_idx, opt);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_eui48(const uint8_t in[static 6])
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + STR_MAX_LEN_EUI48 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_eui48(in, out);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_eui64(const uint8_t in[static 8])
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + STR_MAX_LEN_EUI64 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_eui64(in, out);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv4(uint8_t in[static 4])
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + STR_MAX_LEN_IPV4 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv4(in, out);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv6(const uint8_t in[static 16])
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + STR_MAX_LEN_IPV6 > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv6(in, out);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv4_prefix(uint8_t in[], int prefix_len)
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + STR_MAX_LEN_IPV4_NET > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv4_prefix(in, prefix_len, out);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}

const char *tr_ipv6_prefix(const uint8_t in[], int prefix_len)
{
    char *out = trace_buffer + trace_idx;

    if (trace_idx + STR_MAX_LEN_IPV6_NET > sizeof(trace_buffer))
        return "[OVERFLOW]";
    str_ipv6_prefix(in, prefix_len, out);
    trace_idx += strlen(out);
    BUG_ON(trace_idx > sizeof(trace_buffer));
    return out;
}
