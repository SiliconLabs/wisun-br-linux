/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WS_MNGT_H
#define WS_MNGT_H

#include <stdbool.h>
#include <stdint.h>
#include "common/trickle.h"

struct mcps_data_rx_ie_list;
struct mcps_data_ind;
struct net_if;

struct ws_mngt {
    trickle_params_t trickle_params;
    trickle_t trickle_pa;
    trickle_t trickle_pc;
    uint8_t lpa_dst[8];
};

/* Processing of Wi-SUN management frames
 *   - PAN Advertisement (PA)
 *   - PAN Advertisement Solicit (PAS)
 *   - PAN Configuration (PC)
 *   - PAN Configuration Solicit (PCS)
 *   - LFN PAN Advertisement (LPA)
 *   - LFN PAN Advertisement Solicit (LPAS)
 *   - LFN PAN Configuration (LPC)
 *   - LFN PAN Configuration Solicit (LPCS)
 *   - LFN Time Sync (LTS)
 */
void ws_mngt_ind(struct net_if *cur, const struct mcps_data_ind *data,
                 const struct mcps_data_rx_ie_list *ie_ext, uint8_t message_type);

void ws_mngt_cnf(struct net_if *interface, uint8_t asynch_message);

void ws_mngt_pa_send(struct net_if *cur);
void ws_mngt_pc_send(struct net_if *cur);

void ws_mngt_async_trickle_start(struct net_if *cur);
void ws_mngt_async_trickle_stop(struct net_if *cur);
void ws_mngt_async_trickle_reset_pc(struct net_if *cur);
void ws_mngt_async_trickle_timer_cb(struct net_if *cur, uint16_t ticks);

void ws_mngt_lpa_timer_cb(int ticks);
void ws_mngt_lts_timer_cb(int ticks);

// Broadcast an LPC frame on LGTK hash, or active LGTK index change
void ws_mngt_lpc_pae_cb(struct net_if *net_if);

void ws_mngt_pan_version_increase(struct net_if *cur);
void ws_mngt_lfn_version_increase(struct net_if *cur);

#endif
