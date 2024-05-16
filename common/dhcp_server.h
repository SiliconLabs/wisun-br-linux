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
#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H
#include <stddef.h>
#include <stdint.h>

/*
 * dhcp_start() will start listening on port 547. The struct dhcp_server will be
 * filled with the necessary values. By default, valid_lifetime and
 * preferred_lifetime are set to infinite. However, if these fields are set
 * before the call to dhcp_start() the defined values are used.
 *
 * Once started, the caller has to poll (with poll() or equivalent)
 * dhcp_server->fd for any incoming frames. dhcp_recv() has to be called
 * dhcp_server->fd is ready.
 */

struct dhcp_server {
    int fd;
    int tun_if_id;
    uint32_t preferred_lifetime;
    uint32_t valid_lifetime;
    uint8_t hwaddr[8];
    uint8_t prefix[8];
};

void dhcp_start(struct dhcp_server *dhcp, const char *tun_dev, uint8_t *hwaddr, uint8_t *prefix);
void dhcp_recv(struct dhcp_server *dhcp);

#endif
