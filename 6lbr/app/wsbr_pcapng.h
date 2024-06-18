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
#ifndef WSBR_PCAPNG_H
#define WSBR_PCAPNG_H

#include <stddef.h>
#include <stdint.h>

struct wsbr_ctxt;
struct mcps_data_ind;
struct mcps_data_rx_ie_list;

void wsbr_pcapng_init(struct wsbr_ctxt *ctxt);
void wsbr_pcapng_closed(struct wsbr_ctxt *ctxt);
void wsbr_pcapng_write_frame(struct wsbr_ctxt *ctxt, uint64_t timestamp_us,
                             const void *frame, size_t frame_len);

#endif
