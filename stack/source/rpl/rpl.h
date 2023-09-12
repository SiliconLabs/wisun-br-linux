#ifndef RPL_H
#define RPL_H

#include <sys/queue.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>

#include "common/trickle.h"

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

// RFC 6550 - 7.2. Sequence Counter Operation
#define RPL_SEQUENCE_WINDOW 16
#define RPL_LOLLIPOP_INIT (-RPL_SEQUENCE_WINDOW)

// RFC 6550 - 17. RPL Constants and Variables
#define RPL_DEFAULT_INSTANCE                  0
#define RPL_DEFAULT_PATH_CONTROL_SIZE         0
#define RPL_DEFAULT_DIO_INTERVAL_MIN          3 // min interval 8ms
#define RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS   20 // max interval 2.3h with default Imin
#define RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT  10
#define RPL_DEFAULT_MIN_HOP_RANK_INCREASE   256

// Wi-SUN FAN 1.1v06 - 6.2.1.1 Configuration Parameters
#define WS_DEFAULT_DCO_LIFETIME_UNIT       1200 // 20min
#define WS_DEFAULT_DCO_LIFETIME               6 // 2h with default unit
#define WS_DEFAULT_DIO_INTERVAL_MIN          19 // min interval 9min
#define WS_DEFAULT_DIO_INTERVAL_DOUBLINGS     1 // max interval 18min with default Imin
#define WS_DEFAULT_DIO_REDUNDANCY_CONSTANT    0
#define WS_DEFAULT_MIN_HOP_RANK_INCREASE    128

// Wi-SUN FAN 1.1v06 - 6.2.3.1.6.3 Upward Route Formation
#define WS_PATH_CONTROL_SIZE 7

/*
 * Different structures are used between parsing and storing because some data
 * contained in the transit information option (TIO) make more sense when
 * considered unique to a RPL target option, namely the path sequence and the E
 * bit. The handling of path control bits is also made easier that way.
 */

struct rpl_transit {
    uint8_t path_lifetime;
    uint8_t parent[16];
};

struct rpl_target {
    uint8_t prefix[16]; // Only full address are supported

    bool external;
    int8_t path_seq;
    //   RFC 6550 - 6.7.8. Transit Information
    // Path Lifetime: [...] The period starts when a new Path Sequence is seen.
    time_t path_seq_tstamp_s;
    // One entry per bit in the path control field, from MSB to LSB (index 0
    // corresponds to the most preferred parent). An unassigned path control
    // bit maps to a 0-initialized transit.
    struct rpl_transit transits[8];

    SLIST_ENTRY(rpl_target) link;
};

// Declare struct rpl_target_list
SLIST_HEAD(rpl_target_list, rpl_target);

struct rpl_root {
    int sockfd;

    struct trickle dio_trickle;
    uint8_t dio_i_doublings;
    uint8_t dio_i_min;
    uint8_t dio_redundancy;

    uint8_t instance_id;
    uint8_t dodag_id[16];
    uint8_t dodag_version_number;
    uint8_t dodag_pref;
    uint8_t min_rank_hop_inc;
    uint8_t  lifetime_default;
    uint16_t lifetime_unit_s;
    uint8_t dtsn; // DAO Trigger Sequence Number
    uint8_t pcs;  // Path Control Size

    void (*route_add)(struct rpl_root *root, const uint8_t prefix[16], size_t prefix_len);
    void (*route_del)(struct rpl_root *root, const uint8_t prefix[16], size_t prefix_len);

    struct rpl_target_list targets;
};

extern const uint8_t rpl_all_nodes[16]; // ff02::1a

void rpl_start(struct rpl_root *root, const char ifname[IF_NAMESIZE]);
void rpl_recv(struct rpl_root *root);
void rpl_timer(int ticks);

void rpl_dodag_version_inc(struct rpl_root *root);
void rpl_dtsn_inc(struct rpl_root *root);

struct rpl_target *rpl_target_get(struct rpl_root *root, const uint8_t prefix[16]);
void rpl_target_del(struct rpl_root *root, struct rpl_target *target);
struct rpl_transit *rpl_transit_preferred(struct rpl_root *root, struct rpl_target *target);

#endif
