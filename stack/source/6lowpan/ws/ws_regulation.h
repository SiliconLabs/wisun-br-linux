/***************************************************************************//**
 * @file ws_regulation.h
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

#ifndef WS_REGULATION_H
#define WS_REGULATION_H

#include <stdint.h>
#include <stdbool.h>

/**************************************************************************//**
 * @brief Set the regional regulation.
 * @param[in] interface_id Wi-SUN interface ID
 * @param[in] regulation New regional regulation
 * @return 0 if successful, an error code otherwise
 *****************************************************************************/
int ws_regulation_set(int8_t interface_id, uint32_t regulation);

#endif  // WS_REGULATION_H
