/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
/* Frequency hoping related stuff */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "nanostack/nanostack/fhss_api.h"

#include "mac_api.h"
#include "wsbr.h"
#include "wsbr_fhss.h"
#include "utils.h"
#include "log.h"

uint16_t mac_read_tx_queue_sizes(const fhss_api_t *fhss_api, bool broadcast_queue)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_read_64bit_mac_address(const fhss_api_t *fhss_api, uint8_t *mac_address)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    // Call wsbr_mac_addr_get()
    ctxt->mac_api.mac64_get(&ctxt->mac_api, MAC_EXTENDED_DYNAMIC, mac_address);
    return 0;
}

uint32_t mac_read_phy_datarate(const fhss_api_t *fhss_api)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

uint32_t mac_read_phy_timestamp(const fhss_api_t *fhss_api)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_set_channel(const fhss_api_t *fhss_api, uint8_t channel_number)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_fhss_frame_tx(const fhss_api_t *fhss_api, int frame_type)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_synch_lost(const fhss_api_t *fhss_api)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_poll_tx_queue(const fhss_api_t *fhss_api)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_broadcast_notification(const fhss_api_t *fhss_api, uint32_t broadcast_time)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int mac_get_coordinator_mac_address(const fhss_api_t *fhss_api, uint8_t *mac_address)
{
    struct wsbr_ctxt *ctxt = &g_ctxt;

    BUG_ON(ctxt->fhss_api != fhss_api);
    return 0;
}

int ns_sw_mac_fhss_register(struct mac_api_s *mac_api, struct fhss_api *fhss_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);
    fhss_callback_t callbacks;

    BUG_ON(!mac_api);
    BUG_ON(!fhss_api);

    ctxt->fhss_api = fhss_api;
    callbacks.read_tx_queue_size = &mac_read_tx_queue_sizes;
    callbacks.read_datarate = &mac_read_phy_datarate;
    callbacks.read_timestamp = &mac_read_phy_timestamp;
    callbacks.read_mac_address = &mac_read_64bit_mac_address;
    callbacks.change_channel = &mac_set_channel;
    callbacks.send_fhss_frame = &mac_fhss_frame_tx;
    callbacks.synch_lost_notification = &mac_synch_lost;
    callbacks.tx_poll = &mac_poll_tx_queue;
    callbacks.broadcast_notify = &mac_broadcast_notification;
    callbacks.read_coord_mac_address = &mac_get_coordinator_mac_address;
    fhss_api->init_callbacks(fhss_api, &callbacks);

    return 0;
}

struct fhss_api *ns_sw_mac_get_fhss_api(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    BUG_ON(!mac_api);

    return ctxt->fhss_api;
}

int ns_sw_mac_fhss_unregister(struct mac_api_s *mac_api)
{
    struct wsbr_ctxt *ctxt = container_of(mac_api, struct wsbr_ctxt, mac_api);

    BUG_ON(!mac_api);

    ctxt->fhss_api = NULL;
    return 0;
}

uint32_t ns_sw_mac_read_current_timestamp(struct mac_api_s *mac_api)
{
    BUG_ON(!mac_api);

    return 0;
}

int8_t ns_sw_mac_enable_frame_counter_per_key(struct mac_api_s *mac_api,
                                              bool enable_feature)
{
    BUG_ON(!mac_api);

    return 0;
}

