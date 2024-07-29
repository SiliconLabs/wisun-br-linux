/*
 * Copyright (c) 2024 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef RFC8415_TXALG_H
#define RFC8415_TXALG_H

#include "common/timer.h"

/*
 * RFC 8415 Section 15 describes a parameterized algorithm for sending packets
 * while avoiding overlap with other nodes using timing randomization, and
 * retrying on failure. The algorithm was originally described for the DHCPv6
 * protocol, but it can be used in other contexts.
 */

struct rfc8415_txalg {
    int max_delay_s;
    int irt_s;  // Initial Retransmission Delay (seconds)
    int mrc;    // Maximum Retransmission Count
    int mrt_s;  // Maximum Retransmission Time (seconds)
    int mrd_s;  // Maximum Retransmission Delay (seconds)

    float rand_min;
    float rand_max;

    float rt_s; // Retry Timeout (seconds)
    int c;      // Transmission Count

    struct timer_entry timer_delay;
    struct timer_entry timer_rt;
    struct timer_entry timer_mrd;

    void (*tx)(struct rfc8415_txalg *txalg);
    void (*fail)(struct rfc8415_txalg *txalg);
};

void rfc8415_txalg_init(struct rfc8415_txalg *txalg);

void rfc8415_txalg_start(struct rfc8415_txalg *txalg);
void rfc8415_txalg_stop(struct rfc8415_txalg *txalg);
bool rfc8415_txalg_stopped(struct rfc8415_txalg *txalg);

#endif
