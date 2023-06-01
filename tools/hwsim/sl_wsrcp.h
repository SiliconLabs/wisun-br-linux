/*
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef SL_WSRCP_H
#define SL_WSRCP_H

#include <stdbool.h>
#include <stdint.h>
#ifdef HAVE_LIBPCAP
#  include <pcap/pcap.h>
#endif
#include "common/slist.h"
#include "common/events_scheduler.h"

#include "stack/mac/fhss_ws_extension.h"
#include "mac/rf_driver_storage.h"

struct os_ctxt;
struct mac_api;

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
    struct iovec *header;
    struct iovec *payload;
    struct slist list;
};

struct wsmac_ctxt {
    struct os_ctxt *os_ctxt;
    struct events_scheduler scheduler;

    bool rf_frame_cca_progress;
    int rf_fd;

    uint8_t eui64[8];
    int  rcp_driver_id;
    struct mac_api *rcp_mac_api;
    struct arm_device_driver_list *rf_driver;
    struct fhss_api *fhss_api;
    struct slist *msdu_malloc_list;

    struct neighbor_timings neighbor_timings[255];

    int spinel_tid;
    int spinel_iid;

    struct slist *timers;
    struct slist *fhss_timers;

#ifdef HAVE_LIBPCAP
    pcap_t *pcap_ctxt;
    pcap_dumper_t *pcap_dumper;
#endif
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsmac_ctxt g_ctxt;
extern mac_description_storage_size_t g_storage_sizes;

struct mac_api *init_mac_api(int rcp_driver_id);

#endif
