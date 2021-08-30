/*
 * License: GPLv2
 * Created: 2021-05-19 10:27:04
 * Copyright 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef SL_RF_DRIVER_H
#define SL_RF_DRIVER_H

#include <stdint.h>

struct wsmac_ctxt;
typedef enum phy_link_type_e phy_link_type_e;

void rf_rx(struct wsmac_ctxt *ctxt);
int8_t virtual_rf_device_register(phy_link_type_e link_type, uint16_t mtu_size);

#endif
