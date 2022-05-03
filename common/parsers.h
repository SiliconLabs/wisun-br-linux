/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef PARSERS_H
#define PARSERS_H
#include <stdint.h>
#include <sys/socket.h>

int parse_bitmask(char *str, uint32_t *out, int size);
int parse_escape_sequences(char *out, char *in);
int parse_byte_array(const char *in, uint8_t *out, int len);
void get_ip_addr_from_arg(char *arg, struct sockaddr_storage *addr);

#endif
