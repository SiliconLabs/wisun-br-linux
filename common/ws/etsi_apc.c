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
#include "common/ws/ws_neigh.h"
#include "common/ws/ws_regdb.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/log.h"

#include "etsi_apc.h"

// ETSI EN 300 220-1 v3.1.1 - 5.13 Adaptive Power Control
#define ETSI_APC_ATTENUATION_DB 75
#define ETSI_APC_POWER_LIMIT_DBM 7

// HACK: This module depends on ws_neigh.h to log the EUI-64
static void etsi_apc_trace(struct etsi_apc_ctx *apc,
                           const struct phy_params *phy,
                           int attenuation_db)
{
    struct ws_neigh *neigh = container_of(apc, struct ws_neigh, apc);

    TRACE(TR_NEIGH_15_4, "neigh-15.4 set %s txpow-%s=%idBm (attenuation=%idB)",
          tr_eui64(neigh->eui64.u8), tr_modulation(phy->modulation),
          phy->modulation == MODULATION_OFDM ? apc->txpow_dbm_ofdm : apc->txpow_dbm_fsk,
          attenuation_db);
}

/*
 * Adapt TX power linearly based on the measured attenuation.
 *
 *  TX   ^
 * power |                ,---------
 *       |  1dBm per dB  /   configured
 *       |            \ /       power
 *       |             /
 *  7dBm +   ---------'
 *       |  APC limit
 *       +------------+---------------->
 *                  75dB           attenuation
 *
 * Some margins are applied for safety. One reason for this is that RAIL
 * reports the average power and not the peak.
 */
static int etsi_apc_calc_txpow(int attenuation_db,
                               int max_txpow_dbm,
                               int margin_db)
{
    const int attenuation_threshold_db = ETSI_APC_ATTENUATION_DB + 1; // Safety margin
    const int limit_dbm = ETSI_APC_POWER_LIMIT_DBM - margin_db;

    if (attenuation_db < attenuation_threshold_db)
        return MIN(max_txpow_dbm, limit_dbm);
    else
        return MIN(max_txpow_dbm, limit_dbm + attenuation_db - attenuation_threshold_db);
}

void etsi_apc_update(struct etsi_apc_ctx *apc, uint8_t phy_mode_id,
                     int txpow_dbm, int rsl_dbm, int max_txpow_dbm)
{
    const int attenuation_db = txpow_dbm - rsl_dbm;
    const struct phy_params *phy;

    phy = ws_regdb_phy_params(phy_mode_id, 0);
    if (phy && phy->modulation == MODULATION_OFDM) {
        // 10dB average-to-peak + 1dB margin
        apc->txpow_dbm_ofdm = etsi_apc_calc_txpow(attenuation_db, max_txpow_dbm, 11);
    } else {
        // 1dB margin
        apc->txpow_dbm_fsk  = etsi_apc_calc_txpow(attenuation_db, max_txpow_dbm, 1);
    }
    etsi_apc_trace(apc, phy, attenuation_db);
}
