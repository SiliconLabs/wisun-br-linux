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

/* Provide FHSS related functions to MAC 802.15.4 interface (located in
 * stack/source/mac/ieee802154). This bloc is now relocated to the
 * device.
 */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "common/iobuf.h"
#include "common/utils.h"
#include "common/spinel_defs.h"
#include "common/spinel_buffer.h"
#include "common/log.h"
#include "stack/mac/mac_api.h"

#include "wsbr.h"
#include "wsbr_mac.h"
#include "wsbr_fhss_net.h"

#include "wsbr_fhss_mac.h"

int ns_sw_mac_fhss_register(struct mac_api *mac_api, struct fhss_api *fhss_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct iobuf_write buf = { };

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);
    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_REGISTER);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
    // The original function initialize of the callback. But it useless now.
    ctxt->fhss_api = fhss_api;
    return 0;
}

struct fhss_api *ns_sw_mac_get_fhss_api(struct mac_api *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    return ctxt->fhss_api;
}

int ns_sw_mac_fhss_unregister(struct mac_api *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct iobuf_write buf = { };

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);
    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_FHSS_UNREGISTER);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);
    ctxt->fhss_api = NULL;
    return 0;
}

uint32_t ns_sw_mac_read_current_timestamp(struct mac_api *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct timespec tp;

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);

    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (tp.tv_sec * 1000000 + tp.tv_nsec / 1000) - ctxt->rcp_time_diff;
}

int8_t ns_sw_mac_enable_frame_counter_per_key(struct mac_api *mac_api,
                                              bool enable_feature)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct iobuf_write buf = { };

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);
    spinel_push_hdr_set_prop(ctxt, &buf, SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY);
    spinel_push_bool(&buf, enable_feature);
    rcp_tx(ctxt, &buf);
    iobuf_free(&buf);

    return 0;
}

