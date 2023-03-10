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

