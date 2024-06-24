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
#ifndef TRICKLE_H
#define TRICKLE_H

#include <stdint.h>

#include "common/timer.h"

/*
 * The trickle algorithm is specified by RFC 6202 and describes a strategy to
 * send packets with random exponential delays for collision avoidance, and a
 * notion of packet redundancy for distributed information delivery.
 */

// Imax is defined as a number of Imin doublings: Imax = Imin * 2^doublings
#define TRICKLE_DOUBLINGS(val, doublings) ((val) << (doublings))

struct trickle_cfg {
    unsigned int Imin_ms; // Minimum Interval Size
    unsigned int Imax_ms; // Maximum Interval Size
    unsigned int k;       // Redundancy Constant
};

struct trickle {
    const struct trickle_cfg *cfg;

    unsigned int I_ms; // Current Interval Size
    unsigned int c;    // Consistent Counter

    struct timer_entry timer_interval;
    struct timer_entry timer_transmit;

    char debug_name[4];
    void (*on_transmit)(struct trickle *tkl);
    void (*on_interval_done)(struct trickle *tkl);
};

void trickle_init(struct trickle *tkl);

void trickle_start(struct trickle *tkl);
void trickle_stop(struct trickle *tkl);

void trickle_consistent(struct trickle *tkl);
void trickle_inconsistent(struct trickle *tkl);

#endif
