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
#ifndef RCP_API_H
#define RCP_API_H
#include <stdint.h>
#include "stack/mac/fhss_ws_extension.h"

struct fhss_ws_configuration;

void rcp_set_fhss_timings(const struct fhss_ws_configuration *timing_info);
void rcp_set_fhss_parent(const uint8_t parent[8],
                         const struct broadcast_timing_info *timing_info,
                         bool force_synch);
void rcp_set_fhss_neighbor(const uint8_t neigh[8],
                           const struct fhss_ws_neighbor_timing_info *timing_info);
void rcp_drop_fhss_neighbor(const uint8_t eui64[8]);
void rcp_set_fhss_hop_count(int hop_count);
void rcp_set_tx_allowance_level(fhss_ws_tx_allow_level_e normal,
                                fhss_ws_tx_allow_level_e expedited_forwarding);

#endif
