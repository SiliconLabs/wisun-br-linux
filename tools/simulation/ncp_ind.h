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
#ifndef NCP_IND_H
#define NCP_IND_H

#include <sl_wisun_events.h>

struct sockaddr_in6;

// Pass a NCP indication from the Linux stub to the simulation core.
void ncp_send(const sl_wisun_evt_t *ind);

// Send a SOCKET_DATA_IND packet.
void ncp_send_sk_data(int fd, const void *buf, size_t buf_len,
                      const struct sockaddr_in6 *sin6);

#endif
