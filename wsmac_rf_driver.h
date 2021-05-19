/*
 * License: GPLv2
 * Created: 2021-05-19 10:27:04
 * Copyright 2021, Silicon Labs
 * Main authors:
 *    - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSMAC_RF_DRIVER_H
#define WSMAC_RF_DRIVER_H

#include <stdint.h>

typedef enum phy_link_type_e phy_link_type_e;

int8_t virtual_rf_device_register(phy_link_type_e link_type, uint16_t mtu_size);

#endif
