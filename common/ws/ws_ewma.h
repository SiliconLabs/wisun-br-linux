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
#ifndef WS_EWMA_H
#define WS_EWMA_H

#include <math.h>

/*
 *   Wi-SUN FAN 1.1v08 3.1 Definitions
 * Exponentially Weighted Moving Average
 *
 *   Wi-SUN FAN 1.1v08 6.2.1 Constants
 * ETX_EWMA_SF    ETX EWMA Smoothing Factor   1/8
 * RSL_EWMA_SF    RSL EWMA Smoothing Factor   1/8
 */
static inline float ws_ewma_next(float cur, float val, float smoothing_factor)
{
    // EWMA(0) = X(0)
    if (isnan(cur))
        return val;
    // EWMA(t) = S(X(t)) + (1-S)(EWMA(t-1))
    return smoothing_factor * (val - cur) + cur;
}

#endif
