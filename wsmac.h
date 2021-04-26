/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSMAC_H
#define WSMAC_H

#include "nanostack/fhss_ws_extension.h"

struct os_ctxt;
struct mac_api_s;

struct neighbor_timings {
    uint8_t eui64[8];
    struct fhss_ws_neighbor_timing_info val;
};

struct wsmac_ctxt {
    struct os_ctxt *os_ctxt;

    int  rcp_driver_id;
    struct mac_api_s *rcp_mac_api;
    struct arm_device_driver_list *rf_driver;
    struct fhss_api *fhss_api;

    struct neighbor_timings neighbor_timings[17];

    int spinel_tid;
    int spinel_iid;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsmac_ctxt g_ctxt;

#endif
