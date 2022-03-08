/*
 * Copyright (c) 2016-2019, Pelion and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include "ns_trace.h"
#include "nanostack/mac/platform/arm_hal_phy.h"
#include "net_interface.h"
#include "mac/rf_driver_storage.h"
#include "virtual_rf_defines.h"


#define TRACE_GROUP "vrfc"

static phy_device_driver_s device_driver;
static int8_t rf_driver_id = (-1);
static const phy_rf_channel_configuration_s phy_2_4ghz = {.channel_0_center_frequency = 2405000000, .channel_spacing = 5000000, .datarate = 250000, .number_of_channels = 16, .modulation = M_OQPSK};
static const phy_device_channel_page_s phy_channel_pages = { CHANNEL_PAGE_0, &phy_2_4ghz};

static int8_t phy_rf_rx(const uint8_t *data_ptr, uint16_t data_len, uint8_t link_quality, int8_t dbm, int8_t driver_id)
{
    return -1;
}

static uint8_t mac_mlme_status_2_phy_status(uint8_t status)
{
    switch (status) {
        case MLME_TX_NO_ACK:
            return PHY_LINK_TX_FAIL;
        case MLME_BUSY_CHAN:
            return PHY_LINK_CCA_FAIL;
        case MLME_SUCCESS:
            return PHY_LINK_TX_DONE;
        default:
            return PHY_LINK_TX_SUCCESS;
    }
}

static int8_t phy_rf_tx_done(int8_t driver_id, uint8_t tx_handle, phy_link_tx_status_e status, uint8_t cca_retry, uint8_t tx_retry)
{
    return -1;
}

static int8_t phy_rf_virtual_config_send(int8_t driver_id, const uint8_t *data, uint16_t length)
{
    return -1;
}

int8_t virtual_rf_client_register(void)
{
    if (rf_driver_id < 0) {
        memset(&device_driver, 0, sizeof(phy_device_driver_s));
        device_driver.phy_rx_cb = &phy_rf_rx;
        device_driver.phy_tx_done_cb = &phy_rf_tx_done;
        device_driver.virtual_config_tx_cb = phy_rf_virtual_config_send;
        device_driver.driver_description = "VSND_Client";
        device_driver.link_type = PHY_LINK_15_4_2_4GHZ_TYPE;
        device_driver.phy_channel_pages = &phy_channel_pages;
        rf_driver_id = arm_net_phy_register(&device_driver);

    }
    return rf_driver_id;
}


