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

struct phy_device_driver_s;
struct eth_mac_api_s;
struct mac_api_s;
struct wsbr_ctxt;

struct wsbr_ctxt {
    struct os_ctxt *os_ctxt;

    struct phy_device_driver_s *tun_driver;
    struct eth_mac_api_s *tun_mac_api;
    int  tun_driver_id;
    int  tun_if_id;
    int  tun_fd;
    char tun_dev[IFNAMSIZ];

    struct mac_api_s *rcp_mac_api;
    int  (*rcp_tx)(struct wsbr_ctxt *ctxt, const void *buf, unsigned int len);
    int  (*rcp_rx)(struct wsbr_ctxt *ctxt, void *buf, unsigned int len);
    int  rcp_driver_id;
    int  rcp_if_id;
    int  rcp_trig_fd;
    int  rcp_fd;

    int  rcp_spi_recv_window;
    uint8_t rcp_uart_rx_buf[2048];
    int  rcp_uart_rx_buf_len;
    bool rcp_uart_next_frame_ready;

    int  event_fd[2];

    int  ws_domain;
    int  ws_mode;
    int  ws_class;
    char ws_name[33]; // null-terminated string of 32 chars
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsbr_ctxt g_ctxt;

#endif
