/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#include "hal_interrupt.h"
#include "net_interface.h"
#include "sw_mac.h"
#include "mac_api.h"
#include "ethernet_mac_api.h"
#include "ns_virtual_rf_api.h"
#include "ws_bbr_api.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP  "main"

static mac_description_storage_size_t storage_sizes = {
    .device_decription_table_size = 32, // FIXME: we have plenty of memory. Increase this value
    .key_description_table_size = 4,
    .key_lookup_size = 1,
    .key_usage_size = 3,
};

static uint8_t rcp_mac[8] = { 10, 11, 12, 13, 14, 15, 16, 17 };
static uint8_t tun_mac[8] = { 20, 21, 22, 23, 24, 25, 26, 27 };

static int8_t tun_tx(uint8_t *buf, uint16_t len, uint8_t tx_handle, data_protocol_e protocol)
{
    tr_info("%s: FIXME\n", __func__);
    return 0;
}

static struct phy_device_driver_s tun_phy_driver = {
    /* link_type must match with ifr.ifr_flags:
     *   IFF_TAP | IFF_NO_PI -> PHY_LINK_ETHERNET_TYPE
     *   IFF_TUN | IFF_NO_PI -> PHY_LINK_SLIP
     *   IFF_TUN -> PHY_LINK_TUN
     */
    .link_type = PHY_LINK_TUN,
    .PHY_MAC = tun_mac,
    .data_request_layer = IPV6_DATAGRAMS_DATA_FLOW,
    .driver_description = (char *)"TUN BH",
    .tx = tun_tx,
};

int main(int argc, char *argv[])
{
    mac_api_t *rcp_mac_api;
    eth_mac_api_t *tun_mac_api;
    int rcp_driver_id, rcp_if_id;
    int tun_driver_id, tun_if_id;

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

    tun_driver_id = arm_net_phy_register(&tun_phy_driver);
    if (tun_driver_id < 0)
        tr_err("%s: arm_net_phy_register: %d", __func__, tun_driver_id);
    tun_mac_api = ethernet_mac_create(tun_driver_id);
    if (!tun_mac_api)
        tr_err("%s: ethernet_mac_create", __func__);
    tun_if_id = arm_nwk_interface_ethernet_init(tun_mac_api, "bh0");
    if (tun_if_id < 0)
        tr_err("%s: arm_nwk_interface_ethernet_init: %d", __func__, tun_if_id);

    if (ws_bbr_start(rcp_if_id, tun_if_id))
        tr_err("%s: ws_bbr_start", __func__);

    return 0;
}

