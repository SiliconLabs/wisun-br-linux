/***************************************************************************//**
 * @file ws_regulation_arib.c
 * @brief Wi-SUN regional regulation API
 *******************************************************************************
 * # License
 * <b>Copyright 2022 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#include "nsconfig.h"
#include <assert.h>
#include <stdint.h>
#include "mbed-client-libservice/ns_trace.h"
#include "nanostack/ws_management_api.h"

#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_regulation.h"

#define TRACE_GROUP "wsreg"

int ws_regulation_init_arib(struct protocol_interface_info_entry *cur)
{
  int retval = 0;
  if (cur->ws_info->hopping_schedule.regulatory_domain != REG_DOMAIN_JP) {
    tr_error("ARIB regulation can only be applied to regulatory domain JP");
    retval = -1;
  }
  return retval;
}

static void ws_regulation_disable_channels_in_range(uint16_t range_start, uint16_t range_stop, uint32_t *channel_mask)
{
    for (uint16_t i = range_start; i <= range_stop; i++) {
        channel_mask[i / 32] &= ~(1 << (i % 32));
    }
}

int ws_regulation_update_channel_mask_arib(const struct protocol_interface_info_entry *cur, uint32_t *channel_mask)
{
  if (cur->ws_info->hopping_schedule.channel_plan_id == 255) {
    if (cur->ws_info->hopping_schedule.operating_class == 1) {
      ws_regulation_disable_channels_in_range(0, 8, channel_mask);
    } else if (cur->ws_info->hopping_schedule.operating_class == 2) {
      ws_regulation_disable_channels_in_range(0, 3, channel_mask);
    } else if (cur->ws_info->hopping_schedule.operating_class == 3) {
      ws_regulation_disable_channels_in_range(0, 2, channel_mask);
    }
  } else {
    if (cur->ws_info->hopping_schedule.channel_plan_id == 21) {
      ws_regulation_disable_channels_in_range(0, 8, channel_mask);
    } else if (cur->ws_info->hopping_schedule.channel_plan_id == 22) {
      ws_regulation_disable_channels_in_range(0, 3, channel_mask);
    } else if (cur->ws_info->hopping_schedule.channel_plan_id == 23) {
      ws_regulation_disable_channels_in_range(0, 2, channel_mask);
    } else if (cur->ws_info->hopping_schedule.channel_plan_id == 24) {
      ws_regulation_disable_channels_in_range(0, 1, channel_mask);
    }
  }
  return 0;
}
