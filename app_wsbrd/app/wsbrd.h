/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <poll.h>
#ifdef HAVE_LIBSYSTEMD
#  include <systemd/sd-bus.h>
#else
typedef struct sd_bus sd_bus;
#endif

#include "common/authenticator/authenticator.h"
#include "common/dhcp_relay.h"
#include "common/dhcp_server.h"
#include "common/events_scheduler.h"
#include "common/rcp_api.h"
#include "common/timer.h"
#include "common/tun.h"
#include "net/protocol.h"

#include "commandline.h"

struct iobuf_read;

enum {
    POLLFD_TUN,
    POLLFD_RCP,
    POLLFD_DBUS,
    POLLFD_EVENT,
    POLLFD_TIMER,
    POLLFD_DHCP,
    POLLFD_RPL,
    POLLFD_BR_EAPOL_RELAY, // HAVE_AUTH_LEGACY only
    POLLFD_EAPOL_RELAY,
    POLLFD_PAE_AUTH,       // HAVE_AUTH_LEGACY only
    POLLFD_RADIUS,
    POLLFD_PCAP,
    POLLFD_COUNT,
};

struct wsbr_ctxt {
    struct pollfd fds[POLLFD_COUNT];
    struct events_scheduler scheduler;
    struct timer_entry timer_legacy;
    struct wsbrd_conf config;
    struct dhcp_relay dhcp_relay;
    struct dhcp_server dhcp_server;
    struct auth_ctx auth;
    struct net_if net_if;
    sd_bus *dbus;

    struct tun_ctx tun;
    struct rcp rcp;

    int spinel_tid;
    int spinel_iid;

    int pcapng_fd;
    mode_t pcapng_type;
    uint64_t pcapng_t0_us;
};

// This global variable is necessary for various API of nanostack. Beside this
// case, please never use it.
extern struct wsbr_ctxt g_ctxt;

#endif
