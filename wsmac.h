/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef WSMAC_H
#define WSMAC_H

struct os_ctxt;
struct mac_api_s;
struct fhss_api;

struct wsmac_ctxt {
    struct os_ctxt *os_ctxt;

    int  rcp_driver_id;
    struct mac_api_s *rcp_mac_api;
    struct arm_device_driver_list *rf_driver;
    struct fhss_api *fhss_api;

    int spinel_tid;
    int spinel_iid;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsmac_ctxt g_ctxt;

#endif
