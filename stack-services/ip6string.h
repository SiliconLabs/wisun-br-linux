/*
 * Copyright (c) 2014-2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef IP6STRING_H
#define IP6STRING_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Print binary IPv6 address to a string.
 *
 * String must contain enough room for full address, 40 bytes exact.
 * IPv4 tunneling addresses are not covered.
 *
 * \param ip6addr IPv6 address.
 * \param p buffer to write string to.
 * \return length of generated string excluding the terminating null character
 */
uint_fast8_t ip6tos(const void *ip6addr, char *p);

/**
 * Print binary IPv6 prefix to a string.
 *
 * String buffer `p` must contain enough room for a full address and prefix length, 44 bytes exact.
 * Bits in the `prefix` buffer beyond `prefix_len` bits are not shown and only the bytes containing the
 * prefix bits are read. I.e. for a 20 bit prefix 3 bytes are read, and for a 0 bit prefix 0 bytes are
 * read (thus if `prefix_len` is zero, `prefix` can be NULL).
 * `prefix_len` must be 0 to 128.
 *
 * \param prefix IPv6 prefix.
 * \param prefix_len length of `prefix` in bits.
 * \param p buffer to write string to.
 * \return length of generated string excluding the terminating null character, or 0 for an error, such as 'prefix_len' > 128
 */
uint_fast8_t ip6_prefix_tos(const void *prefix, uint_fast8_t prefix_len, char *p);

#endif
