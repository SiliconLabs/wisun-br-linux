/*
 * SPDX-License-Identifier: LicenseRef-MSLA
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
#include <stddef.h>

#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/rand.h"

#include "trickle.h"

static void trickle_interval_begin(struct trickle *tkl)
{
    unsigned int t_ms;

    /*
     * When an interval begins, Trickle resets c to 0 and sets t to a
     * random point in the interval, taken from the range [I/2, I), that
     * is, values greater than or equal to I/2 and less than I. The
     * interval ends at I.
     */
    tkl->c = 0;
    t_ms = randf_range(tkl->I_ms / 2, tkl->I_ms);
    timer_start_rel(NULL, &tkl->timer_transmit, t_ms);
    timer_start_rel(NULL, &tkl->timer_interval, tkl->I_ms);
    TRACE(TR_TRICKLE, "tkl %-4s begin: t=%us I[%u,%u]=%us", tkl->debug_name,
          t_ms / 1000, tkl->cfg->Imin_ms / 1000, tkl->cfg->Imax_ms / 1000, tkl->I_ms / 1000);
}

static void trickle_interval_done(struct timer_group *group, struct timer_entry *timer)
{
    struct trickle *tkl = container_of(timer, struct trickle, timer_interval);

    /*
     * When the interval I expires, Trickle doubles the interval length. If
     * this new interval length would be longer than the time specified by
     * Imax, Trickle sets the interval length I to be the time specified by
     * Imax.
     */
    tkl->I_ms = MIN(tkl->I_ms * 2, tkl->cfg->Imax_ms);
    trickle_interval_begin(tkl);

    if (tkl->on_interval_done)
        tkl->on_interval_done(tkl);
}

static void trickle_transmit(struct timer_group *group, struct timer_entry *timer)
{
    struct trickle *tkl = container_of(timer, struct trickle, timer_transmit);
    bool tx;

    /*
     * At time t, Trickle transmits if and only if the counter c is less than
     * the redundancy constant k.
     */
    tx = !tkl->cfg->k || tkl->c < tkl->cfg->k;
    TRACE(TR_TRICKLE, "tkl %-4s %-5s: c=%u k=%d", tkl->debug_name,
          tx ? "tx" : "skip", tkl->c, tkl->cfg->k);

    if (tx && tkl->on_transmit)
        tkl->on_transmit(tkl);
}

void trickle_init(struct trickle *tkl)
{
    BUG_ON(!tkl);
    BUG_ON(!tkl->cfg);
    BUG_ON(tkl->cfg->Imin_ms > tkl->cfg->Imax_ms);
    tkl->timer_interval.callback = trickle_interval_done;
    tkl->timer_transmit.callback = trickle_transmit;
}

void trickle_start(struct trickle *tkl)
{
    /*
     * When the algorithm starts execution, it sets I to a value in the
     * range of [Imin, Imax] -- that is, greater than or equal to Imin
     * and less than or equal to Imax. The algorithm then begins the
     * first interval.
     */
    tkl->I_ms = randf_range(tkl->cfg->Imin_ms, tkl->cfg->Imax_ms);
    trickle_interval_begin(tkl);
}

void trickle_stop(struct trickle *tkl)
{
    timer_stop(NULL, &tkl->timer_interval);
    timer_stop(NULL, &tkl->timer_transmit);
    TRACE(TR_TRICKLE, "tkl %-4s stop", tkl->debug_name);
}

void trickle_consistent(struct trickle *tkl)
{
    /*
     * Whenever Trickle hears a transmission that is "consistent", it
     * increments the counter c.
     */
    tkl->c++;
    TRACE(TR_TRICKLE, "tkl %-4s consistent: c=%u", tkl->debug_name, tkl->c);
}

void trickle_inconsistent(struct trickle *tkl)
{
    /*
     * If Trickle hears a transmission that is "inconsistent" and I is greater
     * than Imin, it resets the Trickle timer. To reset the timer, Trickle sets
     * I to Imin and starts a new interval as in step 2. If I is equal to Imin
     * when Trickle hears an "inconsistent" transmission, Trickle does nothing.
     * Trickle can also reset its timer in response to external "events".
     */
    if (tkl->I_ms <= tkl->cfg->Imin_ms)
        return;
    TRACE(TR_TRICKLE, "tkl %-4s inconsistent", tkl->debug_name);
    tkl->I_ms = tkl->cfg->Imin_ms;
    trickle_interval_begin(tkl);
}
