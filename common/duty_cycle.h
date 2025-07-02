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
#ifndef DUTY_CYCLE_H
#define DUTY_CYCLE_H
#include <stdint.h>

#include "common/log.h"

/*
 * Some regional regulations require devices to monitor their time spent
 * transmitting. This modules computes an indicator from:
 *   - The current TX duration reported over the last hour.
 *   - A maximum TX duration allowed (budget), defined for all transmissions,
 *     and also per channel.
 *   - Thresholds expressed as a percentage of the budgets, to define the
 *     transitions between levels.
 */

#define DUTY_CYCLE_LEVEL_MAX 2

struct duty_cycle_cfg {
    int budget_ms;
    int threshold[DUTY_CYCLE_LEVEL_MAX];
    int chan_budget_ms;
    int chan_threshold[DUTY_CYCLE_LEVEL_MAX];
};

void duty_cycle_cfg_check(const struct duty_cycle_cfg *cfg);
int duty_cycle_level(const struct duty_cycle_cfg *cfg,
                     uint32_t tx_duration_ms,
                     uint16_t chan_count);

#endif
