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
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#include "common/bits.h"
#include "common/log.h"

#include "parsers.h"

/*
 * Accepted input string is more or less the same than pages selection for
 * printers: 1,4-6,24
 */
int parse_bitmask(uint8_t *out, int size, const char *str)
{
    unsigned long int cur, end;
    char *endptr;

    memset(out, 0, size);
    do {
        if (!*str) /* empty string or string terminated by ',' */
            return -EINVAL;
        cur = strtoul(str, &endptr, 0);
        if (*endptr == '-') {
            str = endptr + 1;
            end = strtoul(str, &endptr, 0);
            /* FIXME: support for open ranges: "10-" */
        } else {
            end = cur;
        }
        if (*endptr != '\0' && *endptr != ',')
            return -EINVAL;
        if (cur > end)
            return -EINVAL;
        if (end / 8 >= size)
            return -ERANGE;
        bitfill(out, true, cur, end);
        str = endptr + 1;
    } while (*endptr != '\0');
    return 0;
}

int parse_escape_sequences(char *out, const char *in, size_t max_len)
{
    char tmp[3], conv, *end_ptr;
    int i, j;

    BUG_ON(!max_len);
    j = 0;
    for (i = 0; in[i]; ) {
        if (j >= max_len - 1) {
            out[j] = '\0';
            return -ERANGE;
        }
        if (in[i] == '\\') {
            if (in[i + 1] != 'x')
                return -1;
            tmp[0] = in[i + 2];
            tmp[1] = in[i + 3];
            tmp[2] = '\0';
            conv = strtol(tmp, &end_ptr, 16);
            out[j++] = conv;
            if (*end_ptr || !conv) {
                out[j] = '\0';
                return -EINVAL;
            }
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
            return -EINVAL;
        if (sscanf(str, "%hhx", out + i) != 1)
            return -EINVAL;
        str += 3;
    }
    if (str[-1] != '\0')
        return -EINVAL;
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
