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
#ifndef FRAME_HELPERS_H
#define FRAME_HELPERS_H

#include <stdint.h>
#include <stddef.h>

struct mcps_data_cnf;
struct mcps_data_rx_ie_list;

int wsbr_data_cnf_parse(const uint8_t *frame, size_t frame_len,
                        struct mcps_data_cnf *cnf,
                        struct mcps_data_rx_ie_list *ie);

#endif
