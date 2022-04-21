/***************************************************************************//**
 * @file ws_regulation_none.c
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

#include <stdint.h>
#include "nsconfig.h"
#include "ws_common.h"
#include "ws_regulation.h"

int ws_regulation_init_none(struct protocol_interface_info_entry *cur)
{
  (void)cur;
  // Nothing to do.
  return 0;
}

int ws_regulation_update_channel_mask_none(const struct protocol_interface_info_entry *cur, uint32_t *channel_mask)
{
  (void)cur;
  (void)channel_mask;
  // Nothing to do.
  return 0;
}
