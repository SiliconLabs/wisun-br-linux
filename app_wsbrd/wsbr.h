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
#ifndef WSBR_H
#define WSBR_H

#include <stdbool.h>
#include <stdint.h>
#ifdef HAVE_LIBSYSTEMD
#  include <systemd/sd-bus.h>
#else
typedef struct sd_bus sd_bus;
#endif

#include "common/dhcp_server.h"
#include "common/events_scheduler.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/fhss_config.h"
#include "rcp_api.h"

#include "commandline.h"

struct iobuf_read;

struct wsbr_ctxt {
    struct os_ctxt *os_ctxt;
    struct events_scheduler scheduler;
    struct wsbrd_conf config;
    struct dhcp_server dhcp_server;
    sd_bus *dbus;

    int timerfd;

    int  tun_fd;
    int  sock_mcast;

    struct rcp rcp;
    int  rcp_if_id;

    int spinel_tid;
    int spinel_iid;

    int pcapng_fd;
    mode_t pcapng_type;

    struct {
        uint8_t eui64[8];
        uint8_t ipv6[16];
    } *dhcp_leases;
    int dhcp_leases_len;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsbr_ctxt g_ctxt;

void wsbr_dhcp_lease_update(struct wsbr_ctxt *ctxt, const uint8_t eui64[8], const uint8_t ipv6[16]);

#endif
