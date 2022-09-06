/*
 * Copyright (c) 2021-2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef WSBR_H
#define WSBR_H

#include <stdbool.h>
#include <stdint.h>
#ifdef HAVE_LIBSYSTEMD
#  include <systemd/sd-bus.h>
#else
typedef struct sd_bus sd_bus;
#endif

#include "common/bits.h"
#include "common/utils.h"
#include "common/version.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/fhss_config.h"
#include "stack/net_interface.h"
#include "stack/source/mac/rf_driver_storage.h"

#include "commandline.h"

struct spinel_buffer;
struct phy_device_driver;
struct eth_mac_api;
struct fhss_api;

struct wsbr_ctxt {
    struct os_ctxt *os_ctxt;
    struct wsbrd_conf config;
    sd_bus *dbus;

    int timerfd;

    int  tun_if_id;
    int  tun_fd;
    int  sock_mcast;

    uint32_t rcp_init_state;
    uint8_t hw_mac[8];
    uint8_t dynamic_mac[8];
    struct fhss_api *fhss_api;
    struct mac_api mac_api;
    struct mac_description_storage_size storage_sizes;

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

    uint8_t phy_operating_modes[16]; // 15 possible phy_mode_id + 1 sentinel value

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
    return version_older_than(ctxt->rcp_version_api, major, minor, patch);
}

void wsbr_handle_reset(struct wsbr_ctxt *ctxt, const char *version_fw_str);

void wsbr_spinel_replay_interface(struct spinel_buffer *buf);

#endif
