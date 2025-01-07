/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef EAPOL_RELAY_H
#define EAPOL_RELAY_H

#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

struct eui64;
struct in6_addr;

// Wi-SUN FAN 1.1v08 6.2.1 Constants
#define EAPOL_RELAY_PORT 10253

int eapol_relay_start(const char ifname[IF_NAMESIZE]);
ssize_t eapol_relay_recv(int fd, void *buf, size_t buf_len, struct in6_addr *src,
                         struct eui64 *supp_eui64, uint8_t *kmp_id);
void eapol_relay_send(int fd, const void *buf, size_t buf_len,
                      const struct in6_addr *dst,
                      const struct eui64 *supp_eui64, uint8_t kmp_id);

#endif
