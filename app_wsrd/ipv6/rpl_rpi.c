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
#include <netinet/ip6.h>
#include <errno.h>

#include "app_wsrd/ipv6/ipv6.h"
#include "app_wsrd/ipv6/rpl.h"
#include "common/specs/rpl.h"
#include "common/log.h"

#include "rpl_rpi.h"

// RFC 6553 4. RPL Router Behavior
int rpl_rpi_process(struct ipv6_ctx *ipv6, struct ip6_opt *opt)
{
    const struct ipv6_neigh *parent;
    struct rpl_rpi *rpi;
    uint16_t dag_rank;

    if (opt->ip6o_len < sizeof(struct rpl_rpi)) {
        TRACE(TR_DROP, "drop %-9s: malformed packet", "rpl-rpi");
        return -EINVAL;
    }
    rpi = (struct rpl_rpi *)(opt + 1);

    /*
     *     RFC 6550 11.2.2.1. Instance Forwarding
     * If any node cannot forward a packet along the DODAG associated with the
     * RPLInstanceID, then the node SHOULD discard the packet and send an ICMP
     * error message.
     */
    parent = rpl_neigh_pref_parent(ipv6);
    if (!parent || parent->rpl->dio.instance_id != rpi->instance_id) {
        TRACE(TR_DROP, "drop %-9s: InstanceID mismatch", "rpl-rpi");
        // TODO: ICMP error
        return -EINVAL;
    }

    /*     RFC 6550 11.2.2.2. DAG Inconsistency Loop Detection
     * A receiver detects an inconsistency if it receives a packet with either:
     *     the 'O' bit set (to Down) from a node of a higher Rank.
     *     the 'O' bit cleared (for Up) from a node of a lower Rank.
     * [...]
     * When an inconsistency is detected on a packet, if the Rank-Error bit was
     * not set, then the Rank-Error bit is set. If it was set the packet MUST
     * be discarded and the Trickle timer MUST be reset.
     */
    dag_rank = rpl_mrhof_rank(ipv6) / ntohs(parent->rpl->config.min_hop_rank_inc);
    if (( (rpi->flags & RPL_MASK_RPI_O) && ntohs(rpi->sender_rank) > dag_rank) ||
        (!(rpi->flags & RPL_MASK_RPI_O) && ntohs(rpi->sender_rank) < dag_rank)) {
        if (rpi->flags & RPL_MASK_RPI_R) {
            TRACE(TR_DROP, "drop %-9s: rank error", "rpl-rpi");
            trickle_inconsistent(&ipv6->rpl.dio_trickle);
            return -EINVAL;
        } else {
            rpi->flags |= RPL_MASK_RPI_R;
        }
    }
    rpi->sender_rank = htons(dag_rank);

    /*
     *     RFC 6550 11.2.2.3. DAO Inconsistency Detection and Recovery
     * In Non-Storing mode, the packets are source routed to the destination,
     * and DAO inconsistencies are not corrected locally.
     */
    return 0;
}
