/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include <stdio.h>
#include <stdint.h>

#include "hal_timer.h"

void platform_timer_enable(void)
{
    printf("%s: FIXME\n", __func__);
}

void platform_timer_set_cb(platform_timer_cb new_fp)
{
    printf("%s: FIXME\n", __func__);
}

void platform_timer_disable(void)
{
    printf("%s: FIXME\n", __func__);
}

// This is called from inside platform_enter_critical - IRQs can't happen
void platform_timer_start(uint16_t slots)
{
    printf("%s: FIXME\n", __func__);
}

// This is called from inside platform_enter_critical - IRQs can't happen
uint16_t platform_timer_get_remaining_slots(void)
{
    printf("%s: FIXME\n", __func__);
    return 0;
}
