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
#ifndef AUTHENTICATOR_KEY_H
#define AUTHENTICATOR_KEY_H

#include <stddef.h>

struct auth_ctx;
struct auth_supp_ctx;
struct pktbuf;

void auth_key_recv(struct auth_ctx *auth, struct auth_supp_ctx *supp,
                   const void *buf, size_t buf_len);
void auth_key_pairwise_message_1_send(struct auth_ctx *auth, struct auth_supp_ctx *supp);
void auth_key_refresh_rt_buffer(struct auth_supp_ctx *supp);

#endif
