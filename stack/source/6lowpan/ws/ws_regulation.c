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

#include "app_wsbrd/rcp_api.h"

#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/ws/ws_common.h"
#include "nwk_interface/protocol.h"

#include "6lowpan/ws/ws_regulation.h"

int ws_regulation_set(int8_t interface_id, uint32_t regulation)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);

    if (!cur)
        return -1;
    cur->ws_info.regulation = regulation;
    rcp_set_regional_regulation(regulation);
    return 0;
}
