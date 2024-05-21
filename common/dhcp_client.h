/*
 * Copyright (c) 2021-2024 Silicon Laboratories Inc. (www.silabs.com)

 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections of
 * the MSLA applicable to Object Code, Source Code and Modified Open Source Code.
 * By using this software, you agree to the terms of the MSLA.

 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */

#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H

#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

#include "common/int24.h"
#include "common/timer.h"

struct tun_ctx;

// Identity Association Address Option
struct dhcp_iaaddr {
    struct in6_addr ipv6;
    uint32_t valid_lifetime_s;
    struct timer_entry valid_lifetime_timer;
};

struct dhcp_client {
    int fd;
    int tun_if_id;
    uint8_t eui64[8];
    bool running;

    uint32_t md_s;  // Initial Transmission Max Delay
    uint32_t irt_s; // Initial Retransmission Timeout
    uint32_t mrt_s; // Max Retransmission Timeout
    uint32_t rt_s;  // Retransmission Timeout

    uint24_t tid; // Transaction ID
    int solicit_count;
    struct dhcp_iaaddr iaaddr;

    /*
     * This timer serves two purposes:
     *  - Solicit initial transmission and retries
     *  - Address renegociation before expiration via solicit
     */
    struct timer_entry solicit_timer;
    struct timer_group timer_group;
    struct timespec start_time; // For Elapsed Time option

    struct in6_addr (*get_dst)(struct dhcp_client *client);
    void (*on_addr_add)(struct dhcp_client *client, const struct in6_addr *addr, uint32_t valid_lifetime_s, uint32_t preferred_lifetime_s);
    void (*on_addr_del)(struct dhcp_client *client, const struct in6_addr *addr);
};

void dhcp_client_init(struct dhcp_client *client, const struct tun_ctx *tun, const uint8_t eui64[8]);
void dhcp_client_start(struct dhcp_client *client);
void dhcp_client_recv(struct dhcp_client *client);

#endif
