/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef PARSERS_H
#define PARSERS_H
#include <stdint.h>
#include <sys/socket.h>

int parse_bitmask(uint32_t *out, int size, const char *str);
int parse_escape_sequences(char *out, const char *in);
int parse_byte_array(uint8_t *out, int size, const char *str);
void parse_netaddr(struct sockaddr_storage *out, const char *str);

#endif
