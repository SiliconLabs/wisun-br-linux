/***************************************************************************//**
 * @file ws_regulation.c
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

#include <string.h>
#include "nsconfig.h"
#include "ws_common.h"
#include "ws_regulation.h"
#include "6lowpan/mac/mac_helper.h"
#include "nwk_interface/protocol.h"
#include "common/utils.h"

/** Represent API for one regional regulation. */
typedef struct ws_regulation_entry_s {
  /** Initialize the memory. */
  int (*init)(struct protocol_interface_info_entry *cur);
  /** Get the channel mask. */
  int (*update_channel_mask)(const struct protocol_interface_info_entry *cur, uint32_t *channel_mask);
} ws_regulation_entry_t;

int ws_regulation_init_none(struct protocol_interface_info_entry *cur);
int ws_regulation_init_arib(struct protocol_interface_info_entry *cur);
int ws_regulation_update_channel_mask_none(const struct protocol_interface_info_entry *cur, uint32_t *channel_mask);
int ws_regulation_update_channel_mask_arib(const struct protocol_interface_info_entry *cur, uint32_t *channel_mask);

/** Regional regulation APIs. */
static const ws_regulation_entry_t ws_regulations[] = {
  [0] = {
    .init = ws_regulation_init_none,
    .update_channel_mask = ws_regulation_update_channel_mask_none
  },
  [1] = {
    .init = ws_regulation_init_arib,
    .update_channel_mask = ws_regulation_update_channel_mask_arib
  }
};

int ws_regulation_init(int8_t interface_id)
{
  return ws_regulation_set(interface_id, 0);
}

int ws_regulation_set(int8_t interface_id, uint32_t regulation)
{
  protocol_interface_info_entry_t *cur;
  cur = protocol_stack_interface_info_get_by_id(interface_id);
  if (!cur || !ws_info(cur) || regulation >= ARRAY_SIZE(ws_regulations)) {
    return -1;
  }
  cur->ws_info->regulation_ctxt.regulation = regulation;
  mac_helper_set_regional_regulation(cur, regulation);
  return ws_regulations[cur->ws_info->regulation_ctxt.regulation].init(cur);
}

int ws_regulation_update_channel_mask(const struct protocol_interface_info_entry *cur, uint32_t *channel_mask)
{
  return ws_regulations[cur->ws_info->regulation_ctxt.regulation].update_channel_mask(cur, channel_mask);
}
