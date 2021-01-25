/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "hal_interrupt.h"
#include "net_interface.h"
#include "sw_mac.h"
#include "mac_api.h"
#include "ns_virtual_rf_api.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP  "main"

static mac_description_storage_size_t storage_sizes = {
    .device_decription_table_size = 32, // FIXME: we have plenty of memory. Increase this value
    .key_description_table_size = 4,
    .key_lookup_size = 1,
    .key_usage_size = 3,
};

static uint8_t rcp_mac[8] = { 10, 11, 12, 13, 14, 15, 16, 17 };

int main(int argc, char *argv[])
{
    mac_api_t *rcp_mac_api;
    int rcp_driver_id, rcp_if_id;

    platform_critical_init();
    mbed_trace_init();

    if (net_init_core())
        tr_err("%s: net_init_core", __func__);

    rcp_driver_id = virtual_rf_device_register(PHY_LINK_15_4_SUBGHZ_TYPE, 2043);
    if (rcp_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, rcp_driver_id);
    arm_net_phy_mac64_set(rcp_mac, rcp_driver_id);
    rcp_mac_api = ns_sw_mac_create(rcp_driver_id, &storage_sizes);
    if (!rcp_mac_api)
        tr_err("%s: ns_sw_mac_create", __func__);
    rcp_if_id = arm_nwk_interface_lowpan_init(rcp_mac_api, "ws0");
    if (rcp_if_id < 0)
        tr_err("%s: arm_nwk_interface_lowpan_init: %d", __func__, rcp_if_id);

    return 0;
}

