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
#ifndef ICMPV6_ERR_H
#define ICMPV6_ERR_H

#include <stdint.h>

#include "common/timer.h"

struct pktbuf;

struct icmpv6_err_ctx {
    int fd;
    int tokens;
    struct timer_entry ratelimit_timer;
};

void icmpv6_err_init(struct icmpv6_err_ctx *ctx, const char *ifname);
void icmpv6_err_send(struct icmpv6_err_ctx *ctx,
                     const void *buf, size_t buf_len,
                     uint8_t type, uint8_t code, uint32_t ptr);

#endif
