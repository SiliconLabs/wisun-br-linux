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

    uint8_t dynamic_mac[8];
    struct fhss_api *fhss_api;
    struct mac_api_s mac_api;

    int  (*rcp_tx)(struct os_ctxt *ctxt, const void *buf, unsigned int len);
    int  (*rcp_rx)(struct os_ctxt *ctxt, void *buf, unsigned int len);
    int  rcp_driver_id;
    int  rcp_if_id;

    int  ws_domain;
    int  ws_mode;
    int  ws_class;
    char ws_name[33]; // null-terminated string of 32 chars
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsbr_ctxt g_ctxt;

#endif
