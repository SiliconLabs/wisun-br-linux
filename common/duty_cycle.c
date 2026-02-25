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
#include <stddef.h>

#include "common/key_value_storage.h"
#include "common/log.h"

#include "duty_cycle.h"

static const struct number_limit duty_cycle_valid_budget = {
    0, 60 * 60 * 1000, // 1h
};

static void duty_cycle_set_threshold(const struct storage_parse_info *info, void *raw_dest, const void *raw_param)
{
    uintptr_t count = (uintptr_t)raw_param;
    int *dest = raw_dest;

    if (info->key_array_index >= count)
        FATAL(1, "%s:%d: invalid key index: %d", info->filename, info->linenr, info->key_array_index);
    conf_set_number(info, &dest[info->key_array_index], &valid_percent);
}

struct option_struct duty_cycle_opts[] = {
    { "duty_cycle_budget",              offsetof(struct duty_cycle_cfg, budget_ms),      conf_set_number,          &duty_cycle_valid_budget },
    { "duty_cycle_threshold\\[*]",      offsetof(struct duty_cycle_cfg, threshold),      duty_cycle_set_threshold, (void *)DUTY_CYCLE_LEVEL_MAX },
    { "duty_cycle_chan_budget",         offsetof(struct duty_cycle_cfg, chan_budget_ms), conf_set_number,          &duty_cycle_valid_budget },
    { "duty_cycle_chan_threshold\\[*]", offsetof(struct duty_cycle_cfg, chan_threshold), duty_cycle_set_threshold, (void *)DUTY_CYCLE_LEVEL_MAX },
    { }
};

void duty_cycle_cfg_check(const struct duty_cycle_cfg *cfg)
{
    int threshold;

    threshold = -1;
    if (cfg->budget_ms) {
        for (int i = 0; i < DUTY_CYCLE_LEVEL_MAX; i++) {
            if (cfg->threshold[i] < threshold)
                FATAL(1, "invalid duty_cycle_threshold[%i] = %i", i, cfg->threshold[i]);
            threshold = cfg->threshold[i];
        }
    } else {
        for (int i = 0; i < DUTY_CYCLE_LEVEL_MAX; i++)
            if (cfg->threshold[i])
                FATAL(1, "duty_cycle_threshold[%i] requires duty_cycle_budget", i);
    }

    threshold = -1;
    if (cfg->chan_budget_ms) {
        for (int i = 0; i < DUTY_CYCLE_LEVEL_MAX; i++) {
            if (cfg->chan_threshold[i] < threshold)
                FATAL(1, "invalid duty_cycle_chan_threshold[%i] = %i", i, cfg->chan_threshold[i]);
            threshold = cfg->chan_threshold[i];
        }
    } else {
        for (int i = 0; i < DUTY_CYCLE_LEVEL_MAX; i++)
            if (cfg->chan_threshold[i])
                FATAL(1, "duty_cycle_chan_threshold[%i] requires duty_cycle_chan_budget", i);
    }
}

int duty_cycle_level(const struct duty_cycle_cfg *cfg,
                     uint32_t tx_duration_ms,
                     uint16_t chan_count)
{
    const uint32_t chan_tx_duration_ms = tx_duration_ms / chan_count;

    for (int i = 0; i < DUTY_CYCLE_LEVEL_MAX; i++)
        if ((!cfg->budget_ms      || tx_duration_ms < cfg->budget_ms * cfg->threshold[i] / 100) &&
            (!cfg->chan_budget_ms || chan_tx_duration_ms < cfg->chan_budget_ms * cfg->chan_threshold[i] / 100))
            return i;
    return DUTY_CYCLE_LEVEL_MAX;
}

