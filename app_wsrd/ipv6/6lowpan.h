/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef LOWPAN_H
#define LOWPAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ipv6_ctx;
struct pktbuf;

void lowpan_recv(struct ipv6_ctx *ipv6,
                 const uint8_t *buf, size_t buf_len,
                 const uint8_t src[8], const uint8_t dst[8]);

int lowpan_send(struct ipv6_ctx *ipv6,
                struct pktbuf *pktbuf,
                const uint8_t src[8],
                const uint8_t dst[8]);

#endif
