/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdint.h>
#include <string.h>

#include "log.h"

unsigned int g_enabled_traces = 0;
bool g_enable_color_traces = true;

char *bytes_str(const void *in_start, size_t in_len, const void **in_done, char *out_start, size_t out_len, int opt)
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
