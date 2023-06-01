/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SL_RF_DRIVER_H
#define SL_RF_DRIVER_H

#include <stdint.h>

struct wsmac_ctxt;
typedef enum phy_link_type phy_link_type_e;

void rf_rx(struct wsmac_ctxt *ctxt);
int8_t virtual_rf_device_register(phy_link_type_e link_type, uint16_t mtu_size);

#endif
