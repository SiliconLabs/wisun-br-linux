/*
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef RPL_GLUE_H
#define RPL_GLUE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct buffer;
struct net_if;
struct rpl_root;

// These functions handle the RPL IPv6 extensions in the legacy nanostack IPv6
// implementation.

void rpl_glue_init(struct net_if *net_if);

bool rpl_glue_process_rpi(struct rpl_root *root, struct buffer *buf,
                          const uint8_t *opt, uint8_t opt_len);

#endif
