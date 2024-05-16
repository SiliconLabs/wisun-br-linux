/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2022 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef FUZZ_INTERFACES_H
#define FUZZ_INTERFACES_H
#include <netinet/in.h>
#include <stdint.h>

#define IF_SOCKET_COUNT 6

struct wsbr_ctxt;
struct fuzz_ctxt;
struct iobuf_read;
struct rcp;

enum {
    IF_TUN,
    IF_DHCP_SERVER,
    IF_EAPOL_RELAY,
    IF_BR_EAPOL_RELAY,
    IF_PAE_AUTH,
    IF_RADIUS,
    IF_RPL,
};

struct fuzz_iface {
    int pipefd[2];
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint16_t src_port;
};

void fuzz_ind_replay_socket(struct rcp *rcp, struct iobuf_read *buf);

#endif
