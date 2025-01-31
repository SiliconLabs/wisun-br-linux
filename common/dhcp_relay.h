/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2025 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef DHCP_RELAY_H
#define DHCP_RELAY_H
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

struct dhcp_relay {
    int fd;
    uint8_t hop_limit;
    struct in6_addr link_addr;
    struct in6_addr server_addr;
};

void dhcp_relay_start(struct dhcp_relay *relay);
void dhcp_relay_stop(struct dhcp_relay *relay);
void dhcp_relay_recv(struct dhcp_relay *relay);

#endif
