/*
 * Copyright (c) 2015-2021, Pelion and affiliates.
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "common/endian.h"
#include "common/trickle_legacy.h"
#include "common/rand.h"
#include "common/bits.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/seqno.h"
#include "common/specs/ipv6.h"
#include "common/memutils.h"

#include "net/timers.h"
#include "net/ns_buffer.h"
#include "net/protocol.h"
#include "ipv6/ipv6.h"
#include "6lowpan/mac/mac_helper.h"
#include "ws/ws_common.h"

#include "mpl/mpl.h"

#define TRACE_GROUP "mpl"

#define MPL_OPT_S_MASK      0xC0
#define MPL_OPT_S_SHIFT     6
#define MPL_OPT_M           0x20
#define MPL_OPT_V           0x10

#define MAX_BUFFERED_MESSAGES_SIZE 8192
#define MAX_BUFFERED_MESSAGE_LIFETIME 600 // 1/10 s ticks

static uint16_t mpl_total_buffered;

/* Note that we don't use a buffer_t, to save a little RAM. We don't need
 * any of the metadata it stores...
 */
typedef struct mpl_data_message {
    bool running;
    bool colour;
    uint32_t timestamp;
    trickle_legacy_t trickle;
    ns_list_link_t link;
    uint16_t mpl_opt_data_offset;   /* offset to option data of MPL option */
    uint8_t message[];
} mpl_buffered_message_t;

typedef struct mpl_seed {
    ns_list_link_t link;
    bool colour;
    uint16_t lifetime;
    uint8_t min_sequence;
    uint8_t id_len;
    NS_LIST_HEAD(mpl_buffered_message_t, link) messages; /* sequence number order */
    uint8_t id[];
} mpl_seed_t;

/* For simplicity, we assume each MPL domain is on exactly 1 interface */
struct mpl_domain {
    struct net_if *interface;
    uint8_t address[16];
    uint8_t sequence;
    bool colour;
    uint16_t seed_set_entry_lifetime;
    NS_LIST_HEAD(mpl_seed_t, link) seeds;
    trickle_legacy_params_t data_trickle_params;
    ns_list_link_t link;
    uint8_t seed_id_mode;
};

static NS_LIST_DEFINE(mpl_domains, mpl_domain_t, link);

static void mpl_buffer_delete(mpl_seed_t *seed, mpl_buffered_message_t *message);
static buffer_t *mpl_exthdr_provider(buffer_t *buf, ipv6_exthdr_stage_e stage, int16_t *result);
static void mpl_seed_delete(mpl_domain_t *domain, mpl_seed_t *seed);

static bool mpl_initted;

static void mpl_init(void)
{
    if (mpl_initted) {
        return;
    }
    mpl_initted = true;

    ipv6_set_exthdr_provider(ROUTE_MPL, mpl_exthdr_provider);
}

static uint8_t mpl_buffer_sequence(const mpl_buffered_message_t *message)
{
    return message->message[message->mpl_opt_data_offset + 1];
}

static uint16_t mpl_buffer_size(const mpl_buffered_message_t *message)
{
    return IPV6_HDRLEN + read_be16(message->message + IPV6_HDROFF_PAYLOAD_LENGTH);
}

mpl_domain_t *mpl_domain_lookup(struct net_if *cur, const uint8_t address[16])
{
    ns_list_foreach(mpl_domain_t, domain, &mpl_domains) {
        if (domain->interface == cur && addr_ipv6_equal(domain->address, address)) {
            return domain;
        }
    }
    return NULL;
}

mpl_domain_t *mpl_domain_lookup_with_realm_check(struct net_if *cur, const uint8_t address[16])
{
    if (!addr_is_ipv6_multicast(address)) {
        return NULL;
    }

    return mpl_domain_lookup(cur, address);
}

/* Look up domain by address, ignoring the scop field, so ff22::1 matches ff23::1 */
/* We assume all addresses are multicast, so don't bother checking the first byte */
static mpl_domain_t *mpl_domain_lookup_ignoring_scop(struct net_if *cur, const uint8_t address[16])
{
    ns_list_foreach(mpl_domain_t, domain, &mpl_domains) {
        if (domain->interface == cur &&
                memcmp(address + 2, domain->address + 2, 14) == 0 &&
                (address[1] & 0xf0) == (domain->address[1] & 0xf0)) {
            return domain;
        }
    }
    return NULL;
}

static int mpl_domain_count_on_interface(struct net_if *cur)
{
    int count = 0;
    ns_list_foreach(mpl_domain_t, domain, &mpl_domains) {
        if (domain->interface == cur) {
            count++;
        }
    }
    return count;
}

mpl_domain_t *mpl_domain_create(struct net_if *cur, const uint8_t address[16],
                                uint16_t seed_set_entry_lifetime, uint8_t seed_id_mode,
                                const trickle_legacy_params_t *data_trickle_params)
{
    mpl_domain_t *domain;

    if (!addr_is_ipv6_multicast(address) || addr_ipv6_multicast_scope(address) < IPV6_SCOPE_REALM_LOCAL ||
        !data_trickle_params) {
        return NULL;
    }

    mpl_init();

    /* We lock out attempts to join two domains differing only by scop - this
     * is because we couldn't distinguish control messages, which are sent
     * to the link-local version of the same address. Seems to be a
     * specification limitation?
     */
    if (mpl_domain_lookup_ignoring_scop(cur, address)) {
        return NULL;
    }

    domain = zalloc(sizeof(struct mpl_domain));
    memcpy(domain->address, address, 16);
    domain->interface = cur;
    domain->sequence = rand_get_8bit();
    domain->colour = false;
    ns_list_init(&domain->seeds);
    domain->seed_set_entry_lifetime = seed_set_entry_lifetime;
    domain->data_trickle_params = *data_trickle_params;
    ns_list_add_to_end(&mpl_domains, domain);
    BUG_ON(seed_id_mode != MPL_SEED_IPV6_SRC && seed_id_mode != MPL_SEED_128_BIT);
    domain->seed_id_mode = seed_id_mode;

    //ipv6_route_add_with_info(address, 128, cur->id, NULL, ROUTE_MPL, domain, 0, 0xffffffff, 0);
    addr_add_group(cur, address);
    return domain;
}

bool mpl_domain_delete(struct net_if *cur, const uint8_t address[16])
{
    mpl_domain_t *domain = mpl_domain_lookup(cur, address);
    if (!domain) {
        return false;
    }
    int count = mpl_domain_count_on_interface(cur);

    /* Don't let them delete all-mpl-forwarders unless it's the last */
    if (addr_ipv6_equal(address, ADDR_ALL_MPL_FORWARDERS)) {
        if (count != 1) {
            return true;
        }
    }

    ns_list_foreach_safe(mpl_seed_t, seed, &domain->seeds) {
        mpl_seed_delete(domain, seed);
    }

    //ipv6_route_delete(address, 128, cur->id, NULL, ROUTE_MPL);
    addr_remove_group(cur, address);
    ns_list_remove(&mpl_domains, domain);
    free(domain);
    return true;
}

static mpl_seed_t *mpl_seed_lookup(const mpl_domain_t *domain, uint8_t id_len, const uint8_t *seed_id)
{
    ns_list_foreach(mpl_seed_t, seed, &domain->seeds) {
        if (seed->id_len == id_len && memcmp(seed->id, seed_id, id_len) == 0) {
            return seed;
        }
    }

    return NULL;
}

static mpl_seed_t *mpl_seed_create(mpl_domain_t *domain, uint8_t id_len, const uint8_t *seed_id, uint8_t sequence)
{
    mpl_seed_t *seed = malloc(sizeof(mpl_seed_t) + id_len);
    if (!seed) {
        return NULL;
    }

    seed->min_sequence = sequence;
    seed->lifetime = domain->seed_set_entry_lifetime;
    seed->id_len = id_len;
    seed->colour = domain->colour;
    ns_list_init(&seed->messages);
    memcpy(seed->id, seed_id, id_len);
    ns_list_add_to_end(&domain->seeds, seed);
    return seed;
}

static void mpl_seed_delete(mpl_domain_t *domain, mpl_seed_t *seed)
{
    ns_list_foreach_safe(mpl_buffered_message_t, message, &seed->messages) {
        mpl_buffer_delete(seed, message);
    }
    ns_list_remove(&domain->seeds, seed);
    free(seed);
}

static void mpl_seed_advance_min_sequence(mpl_seed_t *seed, uint8_t min_sequence)
{
    seed->min_sequence = min_sequence;
    ns_list_foreach_safe(mpl_buffered_message_t, message, &seed->messages) {
        if (seqno_cmp8(min_sequence, mpl_buffer_sequence(message)) > 0) {
            mpl_buffer_delete(seed, message);
        }
    }
}

static mpl_buffered_message_t *mpl_buffer_lookup(mpl_seed_t *seed, uint8_t sequence)
{
    ns_list_foreach(mpl_buffered_message_t, message, &seed->messages) {
        if (mpl_buffer_sequence(message) == sequence) {
            return message;
        }
    }
    return NULL;
}

static void mpl_free_space(void)
{
    mpl_seed_t *oldest_seed = NULL;
    mpl_buffered_message_t *oldest_message = NULL;

    /* We'll free one message - earliest sequence number from one seed */
    /* Choose which seed by looking at the timestamp - oldest one first */
    ns_list_foreach(mpl_domain_t, domain, &mpl_domains) {
        ns_list_foreach(mpl_seed_t, seed, &domain->seeds) {
            mpl_buffered_message_t *message = ns_list_get_first(&seed->messages);
            if (!message) {
                continue;
            }
            if (!oldest_message ||
                    g_monotonic_time_100ms - message->timestamp > g_monotonic_time_100ms - oldest_message->timestamp) {
                oldest_message = message;
                oldest_seed = seed;
            }
        }
    }

    if (!oldest_message) {
        return;
    }

    oldest_seed->min_sequence = mpl_buffer_sequence(oldest_message) + 1;
    mpl_buffer_delete(oldest_seed, oldest_message);
}


static mpl_buffered_message_t *mpl_buffer_create(buffer_t *buf, mpl_domain_t *domain, mpl_seed_t *seed, uint8_t sequence, uint8_t hop_limit)
{
    /* IP layer ensures buffer length == IP length */
    uint16_t ip_len = buffer_data_length(buf);

    while (mpl_total_buffered + ip_len > MAX_BUFFERED_MESSAGES_SIZE) {
        tr_debug("MPL MAX buffered message size limit...free space");
        mpl_free_space();
    }

    /* As we came in, message sequence was >= min_sequence, but mpl_free_space
     * could end up pushing min_sequence forward. We must take care and
     * re-check min_sequence.
     *
     * For example, let's say min_sequence=1, we're holding 1,3,5, and we receive 2.
     * a) If mpl_free_space doesn't touch this seed, we're fine.
     * b) If it frees 1, it will advance min_sequence to 2, and we're fine.
     * c) If it frees 1 and 3, it will advance min_sequence to 4, and we cannot
     *    accept this message. (If we forced min_sequence to 2, we'd end up processing
     *    message 3 again).
     */
    if (seqno_cmp8(seed->min_sequence, sequence) > 0) {
        tr_debug("Can no longer accept %"PRIu8" < %"PRIu8, sequence, seed->min_sequence);
        return NULL;
    }

    mpl_buffered_message_t *message = malloc(sizeof(mpl_buffered_message_t) + ip_len);
    if (!message) {
        tr_debug("No heap for new MPL message");
        return NULL;
    }
    memcpy(message->message, buffer_data_pointer(buf), ip_len);
    message->message[IPV6_HDROFF_HOP_LIMIT] = hop_limit;
    message->mpl_opt_data_offset = buf->mpl_option_data_offset;
    message->colour = seed->colour;
    message->timestamp = g_monotonic_time_100ms;
    /* Make sure trickle structure is initialised */
    trickle_legacy_start(&message->trickle, "MPL MSG", &domain->data_trickle_params);

    /* Messages held ordered - eg for benefit of mpl_seed_bm_len() */
    bool inserted = false;
    ns_list_foreach_reverse(mpl_buffered_message_t, m, &seed->messages) {
        if (seqno_cmp8(sequence, mpl_buffer_sequence(m)) > 0) {
            ns_list_add_after(&seed->messages, m, message);
            inserted = true;
            break;
        }
    }
    if (!inserted) {
        ns_list_add_to_start(&seed->messages, message);
    }
    mpl_total_buffered += ip_len;

    return message;
}

static void mpl_buffer_delete(mpl_seed_t *seed, mpl_buffered_message_t *message)
{
    mpl_total_buffered -= mpl_buffer_size(message);
    ns_list_remove(&seed->messages, message);
    free(message);
}

static void mpl_buffer_transmit(mpl_domain_t *domain, mpl_buffered_message_t *message, bool newest)
{
    uint16_t ip_len = mpl_buffer_size(message);
    buffer_t *buf = buffer_get(ip_len);
    if (!buf) {
        tr_debug("No heap for MPL transmit");
        return;
    }

    buffer_data_add(buf, message->message, ip_len);

    /* Modify the M flag [Thread says it must be clear] */
    uint8_t *flag = buffer_data_pointer(buf) + message->mpl_opt_data_offset;
    if (newest) {
        *flag |= MPL_OPT_M;
    } else {
        *flag &= ~MPL_OPT_M;
    }

    // Make sure ip_routed_up is set, even on locally-seeded packets, to
    // distinguishes the "forwarded" copies from the original seed.
    // Used to suppress extra copies to sleepy children.
    buf->ip_routed_up = true;
    buf->dst_sa.addr_type = ADDR_IPV6;
    buf->src_sa.addr_type = ADDR_IPV6;
    memcpy(buf->dst_sa.address, message->message + IPV6_HDROFF_DST_ADDR, 16);
    memcpy(buf->src_sa.address, message->message + IPV6_HDROFF_SRC_ADDR, 16);

    ipv6_transmit_multicast_on_interface(buf, domain->interface);
    tr_info("MPL transmit %u", mpl_buffer_sequence(message));
}

static void mpl_buffer_inconsistent(const mpl_domain_t *domain, mpl_buffered_message_t *message)
{
    trickle_legacy_inconsistent(&message->trickle, &domain->data_trickle_params);
}

static uint8_t mpl_seed_id_len(uint8_t seed_id_type)
{
    static const uint8_t len[] = {
        [MPL_SEED_IPV6_SRC] = 0,
        [MPL_SEED_16_BIT] = 2,
        [MPL_SEED_64_BIT] = 8,
        [MPL_SEED_128_BIT] = 16
    };
    return len[seed_id_type];
}

static uint8_t mpl_seed_id_type(uint8_t seed_id_len)
{
    switch (seed_id_len) {
        default:
            return MPL_SEED_IPV6_SRC;
        case 2:
            return MPL_SEED_16_BIT;
        case 8:
            return MPL_SEED_64_BIT;
        case 16:
            return MPL_SEED_128_BIT;
    }
}

bool mpl_hbh_len_check(const uint8_t *opt_data, uint8_t opt_data_len)
{
    if (opt_data_len < 2) {
        return false;
    }
    if (opt_data[0] & MPL_OPT_V) {
        return true; /* No length complaint - we let "process" drop */
    }

    uint8_t seed_id_type = (opt_data[0] & MPL_OPT_S_MASK) >> MPL_OPT_S_SHIFT;
    /* Note that option is allowed to be longer - spec allows for extension
     * beyond seed-id.
     */
    if (opt_data_len < 2 + mpl_seed_id_len(seed_id_type)) {
        return false;
    }
    return true;
}

/*      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                                     |  Option Type  |  Opt Data Len |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     | S |M|V|  rsv  |   sequence    |      seed-id (optional)       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

bool mpl_process_hbh(buffer_t *buf, struct net_if *cur, uint8_t *opt_data)
{
    if ((buf->options.ip_extflags & IPEXT_HBH_MPL) || buf->options.ll_security_bypass_rx) {
        tr_warn("Bad MPL");
        return false;
    }

    /* mpl_hbh_len_check has already returned true, so know length is okay */

    /* V flag indicates incompatible new version - packets MUST be dropped */
    if (opt_data[0] & MPL_OPT_V) {
        tr_warn("MPL V!");
        return false;
    }

    mpl_domain_t *domain = mpl_domain_lookup_with_realm_check(cur, buf->dst_sa.address);
    if (!domain) {
        tr_debug("No MPL domain");
        return false;
    }

    buf->options.ip_extflags |= IPEXT_HBH_MPL;
    buf->mpl_option_data_offset = opt_data - buffer_data_pointer(buf);

    return true;
    // return mpl_forwarder_process_message(buf, domain, opt_data);
}

/* seeding is true if this is processing an outgoing message */
bool mpl_forwarder_process_message(buffer_t *buf, mpl_domain_t *domain, bool seeding)
{
    const uint8_t *opt_data = buffer_data_pointer(buf) + buf->mpl_option_data_offset;
    uint8_t sequence = opt_data[1];
    uint8_t seed_id_type = (opt_data[0] & MPL_OPT_S_MASK) >> MPL_OPT_S_SHIFT;
    const uint8_t *seed_id = opt_data + 2;
    uint8_t seed_id_len = mpl_seed_id_len(seed_id_type);

    tr_debug("MPL %s %"PRIu8, seeding ? "transmit" : "received", sequence);

    if (!domain) {
        domain = mpl_domain_lookup_with_realm_check(buf->interface, buf->dst_sa.address);
        if (!domain) {
            tr_debug("No domain %s  %s", tr_ipv6(domain->address), trace_array(seed_id, seed_id_len));
            return false;
        }
    }

    if (seed_id_type == MPL_SEED_IPV6_SRC) {
        seed_id = buf->src_sa.address;
        seed_id_len = 16;
    }

    tr_debug("seed %s seq %"PRIu8, trace_array(seed_id, seed_id_len), sequence);
    mpl_seed_t *seed = mpl_seed_lookup(domain, seed_id_len, seed_id);
    if (!seed) {
        seed = mpl_seed_create(domain, seed_id_len, seed_id, sequence);
        if (!seed) {
            tr_debug("No seed %s  %s", tr_ipv6(domain->address), trace_array(seed_id, seed_id_len));
            return false;
        }
    }

    /* If the M flag is set, we report an inconsistency against any messages with higher sequences */
    if ((opt_data[0] & MPL_OPT_M)) {
        ns_list_foreach(mpl_buffered_message_t, message, &seed->messages) {
            if (seqno_cmp8(mpl_buffer_sequence(message), sequence) > 0) {
                mpl_buffer_inconsistent(domain, message);
            }
        }
    }

    /* Drop old messages (sequence < MinSequence) */
    if (seqno_cmp8(seed->min_sequence, sequence) > 0) {
        tr_debug("Old MPL message %"PRIu8" < %"PRIu8, sequence, seed->min_sequence);
        return false;
    }

    mpl_buffered_message_t *message = mpl_buffer_lookup(seed, sequence);
    if (message) {
        tr_debug("Repeated MPL message %"PRIu8, sequence);
        trickle_legacy_consistent(&message->trickle);
        return false;
    }

    seed->lifetime = domain->seed_set_entry_lifetime;

    uint8_t hop_limit = buffer_data_pointer(buf)[IPV6_HDROFF_HOP_LIMIT];
    if (!seeding && hop_limit != 0) {
        hop_limit--;
    }

    if (domain->data_trickle_params.TimerExpirations == 0 || hop_limit == 0) {
        /* As a non-forwarder, just accept the packet and advance the
         * min_sequence - means we will drop anything arriving out-of-order, but
         * old implementation always did this in all cases anyway (even if
         * being a forwarder).
         *
         * We also do this if hop limit is 0, so we are not going to forward.
         * This avoids the edge case discussed in the comment above mpl_control_handler.
         *
         * And finally, also treat Thread non-routers like this, to avoid
         * need to dynamically changing TimerExpirations.
         */
        mpl_seed_advance_min_sequence(seed, sequence + 1);
        return true;
    }

    message = mpl_buffer_create(buf, domain, seed, sequence, hop_limit);
    if (!message) {
        tr_debug("MPL Buffer Craete fail");
    }

    return true;
}

void mpl_timer(int seconds)
{
    ns_list_foreach(mpl_domain_t, domain, &mpl_domains) {
        uint32_t message_age_limit = (domain->seed_set_entry_lifetime * UINT32_C(10)) / 4;
        if (message_age_limit > MAX_BUFFERED_MESSAGE_LIFETIME) {
            message_age_limit = MAX_BUFFERED_MESSAGE_LIFETIME;
        }
        ns_list_foreach_safe(mpl_seed_t, seed, &domain->seeds) {
            /* Count down seed lifetime, and expire immediately when hit */
            if (seed->lifetime > seconds) {
                seed->lifetime -= seconds;
            } else {
                mpl_seed_delete(domain, seed);
                continue;
            }
            /* Once data trickle timer has stopped, we MAY delete a message by
             * advancing MinSequence. We use timestamp to control this, so we
             * can hold beyond just the initial data transmission, permitting
             * it to be restarted by control messages.
             */
            ns_list_foreach_safe(mpl_buffered_message_t, message, &seed->messages) {
                if (!trickle_legacy_running(&message->trickle, &domain->data_trickle_params) &&
                        g_monotonic_time_100ms - message->timestamp >= message_age_limit) {
                    seed->min_sequence = mpl_buffer_sequence(message) + 1;
                    mpl_buffer_delete(seed, message);
                    continue;
                }
                if (trickle_legacy_tick(&message->trickle, &domain->data_trickle_params, seconds))
                    mpl_buffer_transmit(domain, message, ns_list_get_next(&seed->messages, message) == NULL);
            }
        }
    }
}

static buffer_t *mpl_exthdr_provider(buffer_t *buf, ipv6_exthdr_stage_e stage, int16_t *result)
{
    mpl_domain_t *domain = mpl_domain_lookup_with_realm_check(buf->interface, buf->dst_sa.address);
    const uint8_t *seed_id;
    uint8_t seed_id_len;

    /* Deal with simpler modify-already-created-header case first. Note that no error returns. */
    if (stage == IPV6_EXTHDR_MODIFY) {
        if (!domain || buf->options.mpl_fwd_workaround) {
            buf->options.mpl_fwd_workaround = false;
            *result = IPV6_EXTHDR_MODIFY_TUNNEL;
            memcpy(buf->dst_sa.address, ADDR_ALL_MPL_FORWARDERS, 16);
            buf->src_sa.addr_type = ADDR_NONE; // force auto-selection
            return buf;
        }

        if (buf->options.ip_extflags & IPEXT_HBH_MPL_UNFILLED) {
            /* We assume we created this, therefore our option is in place
             * in the expected place. Sequence is set now, AFTER
             * fragmentation.
             */
            uint8_t *iphdr = buffer_data_pointer(buf);
            uint8_t *ext = iphdr + IPV6_HDRLEN;
            if (iphdr[IPV6_HDROFF_NH] != IPV6_NH_HOP_BY_HOP || ext[2] != IPV6_OPTION_MPL) {
                tr_error("modify");
                return buffer_free(buf);
            }
            /* We don't bother setting the M flag on these initial packets. Setting to 0 is always acceptable. */
            ext[5] = domain->sequence++;
            buf->options.ip_extflags &= ~ IPEXT_HBH_MPL_UNFILLED;
            buf->mpl_option_data_offset = IPV6_HDRLEN + 4;
            mpl_forwarder_process_message(buf, domain, true);
        }
        *result = 0;
        return buf;
    }

    /* Rest of code deals with header insertion */
    if (!domain) {
        // We will need to tunnel - do nothing on the inner packet
        *result = 0;
        buf->options.ipv6_use_min_mtu = 1;
        return buf;
    }

    seed_id = addr_select_source(buf->interface, domain->address, 0);
    if (domain->seed_id_mode == MPL_SEED_IPV6_SRC)
        seed_id_len = 0;
    else if (domain->seed_id_mode == MPL_SEED_128_BIT)
        seed_id_len = 16;
    else
        BUG();

    if (!seed_id) {
        tr_error("No MPL Seed ID");
        return buffer_free(buf);
    }

    switch (stage) {
        case IPV6_EXTHDR_SIZE:
            *result = 4 + seed_id_len;
            return buf;
        case IPV6_EXTHDR_INSERT: {
            /* Only have 4 possible lengths/padding patterns to consider:
              * HbH 2 + Option header 4 + Seed 0 + Padding 2 = 8
              * HbH 2 + Option header 4 + Seed 2 + Padding 0 = 8
              * HbH 2 + Option header 4 + Seed 8 + Padding 2 = 16
              * HbH 2 + Option header 4 + Seed 16 + Padding 2 = 24
              */
            uint8_t extlen = (6 + seed_id_len + 7) & ~ 7;
            buf = buffer_headroom(buf, extlen);
            if (!buf) {
                return NULL;
            }
            uint8_t *ext = buffer_data_reserve_header(buf, extlen);
            ext[0] = buf->options.type;
            buf->options.type = IPV6_NH_HOP_BY_HOP;
            ext[1] = (extlen / 8) - 1;
            ext[2] = IPV6_OPTION_MPL;
            ext[3] = 2 + seed_id_len;
            ext[4] = (mpl_seed_id_type(seed_id_len) << MPL_OPT_S_SHIFT);
            ext[5] = 0; // sequence placeholder
            memcpy(ext + 6, seed_id, seed_id_len);
            if (seed_id_len != 2) {
                ext[extlen - 2] = IPV6_OPTION_PADN;
                ext[extlen - 1] = 0;
            }

            *result = 0;
            buf->options.ip_extflags |= IPEXT_HBH_MPL | IPEXT_HBH_MPL_UNFILLED;
            return buf;
        }
        default:
            return buffer_free(buf);
    }
}
