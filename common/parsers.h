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
#ifndef COMMON_PARSERS_H
#define COMMON_PARSERS_H
#include <stdint.h>
#include <sys/socket.h>

/*
 * A collection of functions to convert strings in binary structures.
 */

int parse_bitmask(uint8_t *out, int size, const char *str);
int parse_escape_sequences(char *out, const char *in, size_t max_len);
int parse_byte_array(uint8_t *out, int size, const char *str);
void parse_netaddr(struct sockaddr_storage *out, const char *str);

#endif
