/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include "parsers.h"
#include "log.h"

static int set_bitmask(int shift, uint32_t *out, int size)
{
    int word_nr = shift / 32;
    int bit_nr = shift % 32;

    if (word_nr >= size)
        return -1;
    out[word_nr] |= 1 << bit_nr;
    return 0;
}

int parse_bitmask(char *str, uint32_t *out, int size)
{
    char *range;
    char *endptr;
    unsigned long cur, end;

    memset(out, 0, size * sizeof(uint32_t));
    range = strtok(str, ",");
    do {
        cur = strtoul(range, &endptr, 0);
        if (*endptr == '-') {
            range = endptr + 1;
            end = strtol(range, &endptr, 0);
        } else {
            end = cur;
        }
        if (*endptr != '\0')
            return -1;
        if (cur > end)
            return -1;
        for (; cur <= end; cur++)
            if (set_bitmask(cur, out, size) < 0)
                return -1;
    } while ((range = strtok(NULL, ",")));
    return 0;
}

int parse_escape_sequences(char *out, char *in)
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

int parse_byte_array(const char *in, uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        if (in[2] != '\0' && in[2] != ':')
            return -1;
        if (sscanf(in, "%hhx", out + i) != 1)
            return -2;
        in += 3;
    }
    if (in[-1] != '\0')
        return -3;
    return 0;
}

void get_ip_addr_from_arg(char *arg, struct sockaddr_storage *addr) {
    int s;
    struct addrinfo *results;

    if ((s = getaddrinfo(arg, NULL, NULL, &results)) != 0)
        FATAL(1, "%s: %s", arg, gai_strerror(s));

    BUG_ON(!results);
    memcpy(addr, results->ai_addr, results->ai_addrlen);

    freeaddrinfo(results);
}
