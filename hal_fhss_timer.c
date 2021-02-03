/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "hal_fhss_timer.h"

static int wsbr_fhss_timer_start(uint32_t slots, void (*callback)(const fhss_api_t *api, uint16_t), const fhss_api_t *callback_param)
{
    return 0;
}

static int wsbr_fhss_timer_stop(void (*callback)(const fhss_api_t *api, uint16_t), const fhss_api_t *api)
{
    return 0;
}

static uint32_t wsbr_fhss_get_remaining_slots(void (*callback)(const fhss_api_t *api, uint16_t), const fhss_api_t *api)
{
    return 0;
}

static uint32_t wsbr_fhss_get_timestamp(const fhss_api_t *api)
{
    return 0;
}

struct fhss_timer wsbr_fhss = {
  .fhss_timer_start = wsbr_fhss_timer_start,
  .fhss_timer_stop = wsbr_fhss_timer_stop,
  .fhss_get_remaining_slots = wsbr_fhss_get_remaining_slots,
  .fhss_get_timestamp = wsbr_fhss_get_timestamp,
  .fhss_resolution_divider = 1
};
