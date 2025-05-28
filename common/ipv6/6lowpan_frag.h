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
#ifndef LOWPAN_FRAG_H
#define LOWPAN_FRAG_H

#include "common/timer.h"
#include "common/eui64.h"

struct lowpan_reasm;
struct ipv6_ctx;
struct pktbuf;

// Declare struct lowpan_reasm_list
SLIST_HEAD(lowpan_reasm_list, lowpan_reasm);

struct lowpan_frag_ctx {
    uint64_t reasm_timeout_ms;
    struct lowpan_reasm_list reasm_list;
    struct timer_group timer_group;
};

void lowpan_frag_init(struct lowpan_frag_ctx *ctx);

/*
 * Receive a 6LoWPAN frame starting with a FRAG1 or FRAGN header. Returns 0 if
 * the full packet is reassembled, and fills pktbuf with the reassembly.
 * Returns -EAGAIN if more fragments await. Returns a negative errno on errors.
 */
int lowpan_frag_recv(struct lowpan_frag_ctx *ctx,
                     struct pktbuf *pktbuf,
                     const struct eui64 *src,
                     const struct eui64 *dst);

#endif
