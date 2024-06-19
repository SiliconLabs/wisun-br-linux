/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
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
#ifndef RPL_H
#define RPL_H

#include <sys/queue.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

#include "common/timer.h"
#include "common/trickle_legacy.h"

/*
 * Implementation of a RPL non-storing root for a Linux host.
 *
 * rpl_start() will open an ICMPv6 socket and listen for RPL control packets.
 * Various RPL parameters must be filled beforehand in the struct rpl_root,
 * but they should not be modified externally after starting the RPL service.
 * 2 callbacks route_add and route_del need to be provided to allow for route
 * provisionning. When a RPL downard route is triggered, functions from
 * rpl_srh.h need to be called in order to build the source routing header.
 * There is currently no generic mechanism provided to insert the SRH but
 * rpl_glue.h provides the necessary functions for the nanostack API.
 *
 * Once started, the caller has to poll (with poll() or equivalent)
 * rpl_root->sockfd for any incoming packets, and call rpl_recv() when ready.
 * Additionally rpl_timer() must be setup as a timer callback with the timer ID
 * WS_TIMER_RPL in order to run the trickle algorithm for DIO packets.
 *
 * Some information are stored to disk using rpl_storage.h. They can be restored on
 * reboot by calling rpl_storage_load() before rpl_start().
 *
 * Known limitations:
 * - The RPL Packet Information (RPI) option is never inserted in IPv6 packets.
 * - Packets with a RPI error are always dropped instead of allowing one fault.
 * - Target prefixes can only be full addresses.
 * - Target groups are not supported (multiple targets followed by multiple
 *   transits in a DAO).
 * - Target descriptors are not supported.
 *
 * RPL is specified in:
 * - RFC 6550: RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
 * - RFC 6553: The Routing Protocol for Low-Power and Lossy Networks (RPL)
 *   Option for Carrying RPL Information in Data-Plane Datagrams
 * - RFC 6554: An IPv6 Routing Header for Source Routes with the Routing
 *   Protocol for Low-Power and Lossy Networks (RPL)
 * - RFC 9008: Using RPI Option Type, Routing Header for Source Routes, and
 *   IPv6-in-IPv6 Encapsulation in the RPL Data Plane
 * - IANA: https://www.iana.org/assignments/rpl/rpl.xhtml
 */

/*
 * Different structures are used between parsing and storing because some data
 * contained in the transit information option (TIO) make more sense when
 * considered unique to a RPL target option, namely the path sequence and the E
 * bit. The handling of path control bits is also made easier that way.
 */

struct rpl_transit {
    uint32_t path_lifetime_s;
    uint8_t  parent[16];
};

struct rpl_target {
    uint8_t prefix[16]; // Only full address are supported

    bool external;
    uint8_t path_seq;
    //   RFC 6550 - 6.7.8. Transit Information
    // Path Lifetime: [...] The period starts when a new Path Sequence is seen.
    time_t path_seq_tstamp_s;
    // One entry per bit in the path control field, from MSB to LSB (index 0
    // corresponds to the most preferred parent). An unassigned path control
    // bit maps to a 0-initialized transit.
    struct rpl_transit transits[8];

    struct timer_entry timer;
    SLIST_ENTRY(rpl_target) link;
};

// Declare struct rpl_target_list
SLIST_HEAD(rpl_target_list, rpl_target);

struct rpl_root {
    int sockfd;

    struct trickle_legacy dio_trickle;
    uint8_t dio_i_doublings;
    uint8_t dio_i_min;
    uint8_t dio_redundancy;

    uint8_t instance_id;
    uint8_t dodag_id[16];
    uint8_t dodag_version_number;
    uint8_t dodag_pref;
    uint16_t min_rank_hop_inc;
    uint32_t lifetime_s;
    uint16_t lifetime_unit_s;
    uint8_t dtsn; // DAO Trigger Sequence Number
    uint8_t pcs;  // Path Control Size
    bool    rpi_ignorable;

    void (*on_target_add)(struct rpl_root *root, struct rpl_target *target);
    void (*on_target_del)(struct rpl_root *root, struct rpl_target *target);
    void (*on_target_update)(struct rpl_root *root, struct rpl_target *target, bool updated_transit);

    // When enabled, some parts of the specification are ignored in order to
    // hopefully improve interoperability with faulty devices.
    // In particular:
    // - Path Sequence is ignored, information found in DAO is always
    //   considered up to date and added to previously learned information.
    // - Source Routing Header compression always uses CmprI = CmprE.
    bool compat;

    struct timer_group timer_group;
    struct rpl_target_list targets;
};

void rpl_start(struct rpl_root *root,
               const char ifname[IF_NAMESIZE]);
void rpl_recv(struct rpl_root *root);
void rpl_timer(int ticks);

void rpl_dodag_version_inc(struct rpl_root *root);
void rpl_dtsn_inc(struct rpl_root *root);

struct rpl_target *rpl_target_get(struct rpl_root *root, const uint8_t prefix[16]);
struct rpl_target *rpl_target_new(struct rpl_root *root, const uint8_t prefix[16]);
void rpl_target_del(struct rpl_root *root, struct rpl_target *target);
uint16_t rpl_target_count(struct rpl_root *root);
struct rpl_transit *rpl_transit_preferred(struct rpl_root *root, struct rpl_target *target);

static inline uint16_t rpl_dag_rank(const struct rpl_root *root, uint16_t rank)
{
    //   RFC 6550 - 3.5.1.  Rank Comparison (DAGRank())
    // The integer portion of the Rank is computed by the DAGRank() macro as
    // follows, where floor(x) is the function that evaluates to the greatest
    // integer less than or equal to x:
    //   DAGRank(rank) = floor(rank/MinHopRankIncrease)
    return rank / root->min_rank_hop_inc;
}

static inline uint16_t rpl_root_rank(struct rpl_root *root)
{
    //   RFC 6550 - 8.2.2.2. DODAG Roots
    // A DODAG root MUST advertise a Rank of ROOT_RANK.
    //   RFC 6550 - 17. RPL Constants and Variables
    // [...] ROOT_RANK has a value of MinHopRankIncrease [...].
    return root->min_rank_hop_inc;
}

#endif
