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
#include "wsbr_mac.h"
#include "wsbr_fhss_mac.h"
#include "wsbr_fhss_net.h"
#include "host-common/utils.h"
#include "host-common/spinel.h"
#include "host-common/spinel_buffer.h"
#include "host-common/log.h"

int ns_sw_mac_fhss_register(struct mac_api_s *mac_api, struct fhss_api *fhss_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);
    BUG_ON(fhss_api != FHSS_API_PLACEHOLDER);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_REGISTER);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    // The original function initialize of the callback. But it useless now.
    ctxt->fhss_api = fhss_api;
    return 0;
}

struct fhss_api *ns_sw_mac_get_fhss_api(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    return ctxt->fhss_api;
}

int ns_sw_mac_fhss_unregister(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3);

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_FHSS_UNREGISTER);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);
    ctxt->fhss_api = NULL;
    return 0;
}

uint32_t ns_sw_mac_read_current_timestamp(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct timespec tp;

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);

    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (tp.tv_sec * 1000000 + tp.tv_nsec / 1000) - ctxt->rcp_time_diff;
}

int8_t ns_sw_mac_enable_frame_counter_per_key(struct mac_api_s *mac_api,
                                              bool enable_feature)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    struct spinel_buffer *buf = ALLOC_STACK_SPINEL_BUF(1 + 3 + 3 + 1);

    BUG_ON(!mac_api);
    BUG_ON(ctxt != &g_ctxt);
    spinel_push_hdr_set_prop(ctxt, buf, SPINEL_PROP_WS_ENABLE_FRAME_COUNTER_PER_KEY);
    spinel_push_bool(buf, enable_feature);
    ctxt->rcp_tx(ctxt->os_ctxt, buf->frame, buf->cnt);

    return 0;
}

