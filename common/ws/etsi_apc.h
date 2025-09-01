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
#ifndef ETSI_APC_H
#define ETSI_APC_H

/*
 * Adaptive Power Control (APC) is a requirement by ETSI EN 300 220-1 [1]. This
 * module provides a mechanism to update TX power dynamically based on the
 * measured attenuation. This is done per modulation because:
 *
 * - Different Power Amplifiers (PA) can be used for different modulations.
 * - RAIL sets the average TX power, but APC controls the peak power, and
 *   average-to-peak varies greatly with the modulation used.
 *
 * [1]: https://www.etsi.org/deliver/etsi_en/300200_300299/30022001/03.01.01_60/en_30022001v030101p.pdf
 */

struct etsi_apc_ctx {
    int txpow_dbm_fsk;
    int txpow_dbm_ofdm;
};

// Compute the attenuation and adjust the TX power accordingly.
void etsi_apc_update(struct etsi_apc_ctx *apc, uint8_t phy_mode_id,
                     int txpow_dbm, int rsl_dbm, int max_txpow_dbm);

#endif
