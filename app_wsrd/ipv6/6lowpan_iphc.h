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
#ifndef LOWPAN_IPHC_H
#define LOWPAN_IPHC_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct pktbuf;

void lowpan_iphc_decmpr(struct pktbuf *pktbuf,
                        const uint8_t src_iid[8],
                        const uint8_t dst_iid[8]);

void lowpan_iphc_cmpr(struct pktbuf *pktbuf,
                      const uint8_t src_iid[8],
                      const uint8_t dst_iid[8]);

#endif
