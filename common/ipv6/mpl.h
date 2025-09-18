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
#ifndef MPL_H
#define MPL_H
#include <stddef.h>
#include <stdint.h>

#include "common/trickle.h"

struct in6_addr;
struct ip6_hdr;
struct ip6_opt;
struct pktbuf;

// Declare mpl_seed_set
SLIST_HEAD(mpl_seed_set, mpl_seed);

struct mpl_ctx {
    struct timer_group timer_group;
    struct mpl_seed_set seed_set;

    // RFC 7731 5.4. MPL Parameters
    uint64_t seed_lifetime_ms;
    struct trickle_cfg tkl_data_cfg;
    uint8_t tkl_data_e_max;
    uint8_t s;

    /*
     * Submit a transmission request to the MAC layer. Returns a unique context
     * identifying the request, which needs to be passed to mpl_msg_confirm()
     * when the transmission is done, even if unsuccessful.
     */
    void *(*send)(struct mpl_ctx *mpl, const void *buf, size_t buf_len);
    void (*abort)(struct mpl_ctx *mpl, void *tx_ctx);
};

int mpl_msg_gen(struct mpl_ctx *mpl,
                const struct in6_addr *src,
                struct pktbuf *pktbuf);
void mpl_msg_confirm(struct mpl_ctx *mpl, const void *tx_ctx);
int mpl_opt_process(struct mpl_ctx *mpl,
                    const struct ip6_hdr *hdr,
                    const struct ip6_opt *opt);
void mpl_init(struct mpl_ctx *mpl);

#endif
