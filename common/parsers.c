/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include "parsers.h"
#include "log.h"

static int set_bitmask(uint32_t *out, int size, int shift)
{
    int word_nr = shift / 32;
    int bit_nr = shift % 32;

    if (word_nr >= size)
        return -1;
    out[word_nr] |= 1u << bit_nr;
    return 0;
}

int parse_bitmask(uint32_t *out, int size, const char *str)
{
    char *endptr;
    uint32_t cur, end;

    memset(out, 0, size * sizeof(uint32_t));
    do {
        if (!*str) /* empty string or string terminated by ',' */
            return -1;
        cur = strtoul(str, &endptr, 0);
        if (*endptr == '-') {
            str = endptr + 1;
            end = strtoul(str, &endptr, 0);
        } else {
            end = cur;
        }
        if (*endptr != '\0' && *endptr != ',')
            return -1;
        if (cur > end)
            return -1;
        for (; cur <= end; cur++)
            if (set_bitmask(out, size, cur) < 0)
                return -1;
        str = endptr + 1;
    } while (*endptr != '\0');
    return 0;
}

int parse_escape_sequences(char *out, const char *in)
{
    char tmp[3], conv, *end_ptr;
    int i, j;

    j = 0;
    for (i = 0; in[i]; ) {
        if (in[i] == '\\') {
            if (in[i + 1] != 'x')
                return -1;
            tmp[0] = in[i + 2];
            tmp[1] = in[i + 3];
            tmp[2] = '\0';
            conv = strtol(tmp, &end_ptr, 16);
            out[j++] = conv;
            if (*end_ptr || !conv)
                return -1;
            i += 4;
        } else {
            out[j++] = in[i++];
        }
    }
    out[j++] = '\0';
    return 0;
}

int parse_byte_array(uint8_t *out, int size, const char *str)
{
    for (int i = 0; i < size; i++) {
        if (str[2] != '\0' && str[2] != ':')
            return -1;
        if (sscanf(str, "%hhx", out + i) != 1)
            return -2;
        str += 3;
    }
    if (str[-1] != '\0')
        return -3;
    return 0;
}

void parse_netaddr(struct sockaddr_storage *out, const char *str)
{
    int s;
    struct addrinfo *results;

    if ((s = getaddrinfo(str, NULL, NULL, &results)) != 0)
        FATAL(1, "%s: %s", str, gai_strerror(s));

    BUG_ON(!results);
    memcpy(out, results->ai_addr, results->ai_addrlen);

    freeaddrinfo(results);
}
