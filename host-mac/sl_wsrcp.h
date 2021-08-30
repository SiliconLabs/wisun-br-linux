/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
#ifndef SL_WSRCP_H
#define SL_WSRCP_H

#include <stdbool.h>
#include <stdint.h>
#ifdef HAVE_LIBPCAP
#  include <pcap/pcap.h>
#endif

#include "host-common/slist.h"
#include "nanostack/fhss_ws_extension.h"
#include "nanostack/source/MAC/rf_driver_storage.h"

struct os_ctxt;
struct mac_api_s;

struct neighbor_timings {
    uint8_t eui64[8];
    struct fhss_ws_neighbor_timing_info val;
};

// When MAC receive an MSDU to send, it may be queued if the RF driver is busy.
// In this case, lifetime of MSDU is longer and therefore, can't be stored on
// the stack.
//
// So, we use heap to store them. The struct below aims to track these data and
// freeing them when the MAC send confirmation.
//
// FIXME: more or less redundant with mac_pre_build_frame_t
struct msdu_malloc_info {
    int msduHandle;
    void *msdu;
    struct ns_ie_iovec *header;
    struct ns_ie_iovec *payload;
    struct slist list;
};

struct wsmac_ctxt {
    struct os_ctxt *os_ctxt;

    bool rf_frame_cca_progress;
    int rf_fd;

    uint8_t eui64[8];
    int  rcp_driver_id;
    struct mac_api_s *rcp_mac_api;
    struct arm_device_driver_list *rf_driver;
    struct fhss_api *fhss_api;
    struct slist *msdu_malloc_list;

    struct neighbor_timings neighbor_timings[32];

    int spinel_tid;
    int spinel_iid;

#ifdef HAVE_LIBPCAP
    pcap_t *pcap_ctxt;
    pcap_dumper_t *pcap_dumper;
#endif
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsmac_ctxt g_ctxt;
extern mac_description_storage_size_t g_storage_sizes;

#endif
