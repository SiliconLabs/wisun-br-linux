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
#include "common/memutils.h"
#include "common/rand.h"

#include "rfc8415_txalg.h"

/*
 * Each of the computations of a new RT includes a randomization factor
 * (RAND), which is a random number chosen with a uniform distribution
 * between -0.1 and +0.1.
 *
 * NOTE: This implementation allows a different range to be used.
 */
static inline float rfc8415_txalg_rand(struct rfc8415_txalg *txalg)
{
    return randf_range(txalg->rand_min, txalg->rand_max);
}

static void rfc8415_txalg_fail(struct rfc8415_txalg *txalg)
{
    rfc8415_txalg_stop(txalg);
    if (txalg->fail)
        txalg->fail(txalg);
}

static void rfc8415_txalg_timeout_delay(struct timer_group *group, struct timer_entry *timer)
{
    struct rfc8415_txalg *txalg = container_of(timer, struct rfc8415_txalg, timer_delay);
    float rand = rfc8415_txalg_rand(txalg);

    /*
     * RT for the first message transmission is based on IRT:
     *   RT = IRT + RAND*IRT
     */
    txalg->rt_s = txalg->irt_s + rand * txalg->irt_s;
    timer_start_rel(group, &txalg->timer_rt, 1000 * txalg->rt_s);

    if (txalg->mrd_s)
        timer_start_rel(group, &txalg->timer_mrd, 1000 * txalg->mrd_s);

    txalg->tx(txalg);
    txalg->c++;
}

static void rfc8415_txalg_timeout_rt(struct timer_group *group, struct timer_entry *timer)
{
    struct rfc8415_txalg *txalg = container_of(timer, struct rfc8415_txalg, timer_rt);
    float rand = rfc8415_txalg_rand(txalg);

    /*
     * MRC specifies an upper bound on the number of times a client may
     * retransmit a message. Unless MRC is zero, the message exchange fails
     * once the client has transmitted the message MRC times.
     */
    if (txalg->mrc && txalg->c >= txalg->mrc) {
        rfc8415_txalg_fail(txalg);
        return;
    }

    /*
     * RT for each subsequent message transmission is based on the previous
     * value of RT:
     *   RT = 2*RTprev + RAND*RTprev
     */
    txalg->rt_s = 2 * txalg->rt_s + rand * txalg->rt_s;

    /*
     * MRT specifies an upper bound on the value of RT (disregarding the
     * randomization added by the use of RAND). If MRT has a value of 0,
     * there is no upper limit on the value of RT. Otherwise:
     *   if (RT > MRT)
     *       RT = MRT + RAND*MRT
     */
    if (txalg->mrt_s && txalg->rt_s > txalg->mrt_s)
        txalg->rt_s = txalg->mrt_s + rand * txalg->mrt_s;

    timer_start_rel(group, &txalg->timer_rt, 1000 * txalg->rt_s);

    txalg->tx(txalg);
    txalg->c++;
}

static void rfc8415_txalg_timeout_mrd(struct timer_group *group, struct timer_entry *timer)
{
    struct rfc8415_txalg *txalg = container_of(timer, struct rfc8415_txalg, timer_mrd);

    /*
     * MRD specifies an upper bound on the length of time a client may
     * retransmit a message. Unless MRD is zero, the message exchange fails
     * once MRD seconds have elapsed since the client first transmitted the
     * message.
     */
    rfc8415_txalg_fail(txalg);
}

void rfc8415_txalg_init(struct rfc8415_txalg *txalg)
{
    BUG_ON(!txalg->tx);
    BUG_ON(txalg->rand_min >= txalg->rand_max);

    txalg->timer_delay.callback = rfc8415_txalg_timeout_delay;
    txalg->timer_rt.callback    = rfc8415_txalg_timeout_rt;
    txalg->timer_mrd.callback   = rfc8415_txalg_timeout_mrd;
}

void rfc8415_txalg_start(struct rfc8415_txalg *txalg)
{
    txalg->c = 0;

    /*
     * The first Solicit message from the client on the interface SHOULD be
     * delayed by a random amount of time between 0 and SOL_MAX_DELAY.
     *
     * NOTE: This module allows an initial delay for any packet type.
     */
    timer_start_rel(NULL, &txalg->timer_delay,
                    1000 * randf_range(0, txalg->max_delay_s));
}

void rfc8415_txalg_stop(struct rfc8415_txalg *txalg)
{
    txalg->c = 0;
    timer_stop(NULL, &txalg->timer_delay);
    timer_stop(NULL, &txalg->timer_rt);
    timer_stop(NULL, &txalg->timer_mrd);
}

bool rfc8415_txalg_stopped(struct rfc8415_txalg *txalg)
{
    return timer_stopped(&txalg->timer_delay) && timer_stopped(&txalg->timer_rt) &&
           timer_stopped(&txalg->timer_mrd);
}
