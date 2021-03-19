/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* Provide FHSS related functions to MAC 802.15.4 interface (located in
 * nanostack/source/MAC/IEEE802_15_4). This bloc is now relocated to the
 * device.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "nanostack/mac_api.h"

#include "wsbr.h"
#include "wsbr_fhss_mac.h"
#include "utils.h"
#include "log.h"

int ns_sw_mac_fhss_register(struct mac_api_s *mac_api, struct fhss_api *fhss_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    BUG_ON(!mac_api);
    BUG_ON(!fhss_api);

    // The original function initialize of the callback. But it useless now.
    ctxt->fhss_api = fhss_api;

    WARN("not implemented");
    return 0;
}

struct fhss_api *ns_sw_mac_get_fhss_api(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    BUG_ON(!mac_api);

    WARN("not implemented");
    return ctxt->fhss_api;
}

int ns_sw_mac_fhss_unregister(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    BUG_ON(!mac_api);

    ctxt->fhss_api = NULL;
    WARN("not implemented");
    return 0;
}

uint32_t ns_sw_mac_read_current_timestamp(struct mac_api_s *mac_api)
{
    BUG_ON(!mac_api);
    WARN("not implemented");

    return 0;
}

int8_t ns_sw_mac_enable_frame_counter_per_key(struct mac_api_s *mac_api,
                                              bool enable_feature)
{
    BUG_ON(!mac_api);
    WARN("not implemented");

    return 0;
}

