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
#include <linux/limits.h>
#ifdef HAVE_LIBSYSTEMD
#  include <systemd/sd-bus.h>
#else
typedef struct sd_bus sd_bus;
#endif

#include "host-common/utils.h"
#include "nanostack/mac_api.h"
#include "nanostack/fhss_config.h"
#include "nanostack/net_interface.h"
#include "nanostack/source/MAC/rf_driver_storage.h"

struct phy_device_driver_s;
struct eth_mac_api_s;
struct fhss_api;

struct wsbr_ctxt {
    struct os_ctxt *os_ctxt;
    sd_bus *dbus;

    char uart_dev[PATH_MAX];
    int  uart_baudrate;
    bool uart_rtscts;

    struct phy_device_driver_s *tun_driver;
    struct eth_mac_api_s *tun_mac_api;
    int  tun_driver_id;
    int  tun_if_id;
    int  tun_fd;
    char tun_dev[IFNAMSIZ];
    bool tun_autoconf;

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

    uint32_t rcp_version_api;
    uint32_t rcp_version_fw;

    int  ws_domain;
    int  ws_mode;
    int  ws_class;
    int  ws_size;
    char ws_name[33]; // null-terminated string of 32 chars
    int  ws_pan_id;
    int  tx_power;
    uint8_t ws_gtk[4][16];
    bool ws_gtk_force[4];
    uint8_t ipv6_prefix[16];
    uint32_t ws_allowed_channels[8];
    int ws_pmk_lifetime;
    int ws_ptk_lifetime;
    int ws_gtk_expire_offset;
    int ws_gtk_new_activation_time;
    int ws_gtk_new_install_required;
    int ws_revocation_lifetime_reduction;
    int ws_gtk_max_mismatch;
    arm_certificate_entry_s tls_own;
    arm_certificate_entry_s tls_ca;
    int uc_dwell_interval;
    int bc_interval;
    int bc_dwell_interval;
    uint8_t ws_allowed_mac_addresses[10][8];
    uint8_t ws_allowed_mac_address_count;
    uint8_t ws_denied_mac_addresses[10][8];
    uint8_t ws_denied_mac_address_count;

    // For DebugPing dbus interface
    int ping_socket_fd;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsbr_ctxt g_ctxt;

/**
 * Indicates RCP firmware API is older than specified version.
 * (major.minor.patch).
 */
static inline bool fw_api_older_than(const struct wsbr_ctxt *ctxt,
                                     uint8_t major,
                                     uint16_t minor,
                                     uint8_t patch)
{
    uint8_t fw_api_major = FIELD_GET(0xFF000000, ctxt->rcp_version_api);
    uint16_t fw_api_minor = FIELD_GET(0x00FFFF00, ctxt->rcp_version_api);
    uint8_t fw_api_patch = FIELD_GET(0x000000FF, ctxt->rcp_version_api);

    if (fw_api_major < major)
        return true;
    if (fw_api_major == major && fw_api_minor < minor)
        return true;
    if (fw_api_major == major && fw_api_minor == minor && fw_api_patch < patch)
        return true;
    return false;
}

void wsbr_handle_reset(struct wsbr_ctxt *ctxt, const char *version_fw_str);

#endif
