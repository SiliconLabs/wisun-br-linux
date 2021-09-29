/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSBR_H
#define WSBR_H

#include <stdbool.h>
#include <stdint.h>
#include <linux/if.h>

#include "nanostack/mac_api.h"
#include "nanostack/fhss_config.h"
#include "nanostack/net_interface.h"
#include "nanostack/source/MAC/rf_driver_storage.h"

struct phy_device_driver_s;
struct eth_mac_api_s;
struct fhss_api;

struct wsbr_ctxt {
    struct os_ctxt *os_ctxt;

    struct phy_device_driver_s *tun_driver;
    struct eth_mac_api_s *tun_mac_api;
    int  tun_driver_id;
    int  tun_if_id;
    int  tun_fd;
    char tun_dev[IFNAMSIZ];

    bool reset_done;
    bool hw_addr_done;
    uint8_t hw_mac[8];
    uint8_t dynamic_mac[8];
    struct fhss_api *fhss_api;
    struct mac_api_s mac_api;
    struct mac_description_storage_size_s storage_sizes;

    bool fhss_conf_valid;
    struct fhss_ws_configuration fhss_conf;

    int  (*rcp_tx)(struct os_ctxt *ctxt, const void *buf, unsigned int len);
    int  (*rcp_rx)(struct os_ctxt *ctxt, void *buf, unsigned int len);
    int  rcp_driver_id;
    int  rcp_if_id;
    int  rcp_time_diff;

    int spinel_tid;
    int spinel_iid;

    int  ws_domain;
    int  ws_mode;
    int  ws_class;
    int  ws_size;
    char ws_name[33]; // null-terminated string of 32 chars
    uint8_t ws_gtk[4][16];
    bool ws_gtk_force[4];
    uint8_t ipv6_prefix[16];
    uint32_t ws_allowed_channels[8];
    arm_certificate_entry_s tls_own;
    arm_certificate_entry_s tls_ca;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsbr_ctxt g_ctxt;

#endif
