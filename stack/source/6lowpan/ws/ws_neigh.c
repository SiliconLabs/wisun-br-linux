/*
 * Copyright (c) 2018-2020, Pelion and affiliates.
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

#include "common/time_extra.h"
#include "common/ws_regdb.h"
#include "common/version.h"
#include "common/endian.h"
#include "common/mathutils.h"
#include "common/rand.h"
#include "common/log.h"
#include "common/bits.h"
#include "common/specs/ws.h"

#include "6lowpan/ws/ws_bootstrap.h"
#include "nwk_interface/protocol.h"
#include "app_wsbrd/wsbr.h"

#include "ws_neigh.h"

#define LFN_SCHEDULE_GUARD_TIME_MS 300

bool ws_neigh_alloc(ws_neigh_table_t *table, uint8_t list_size, neighbor_entry_remove_notify *remove_cb)
{
    ws_neigh_t *list_ptr;

    table->neigh_info_list = malloc(sizeof(ws_neigh_t) * list_size);

    if (!table->neigh_info_list)
        return false;

    table->list_size = list_size;
    table->remove_cb = remove_cb;
    list_ptr = table->neigh_info_list;

    for (uint8_t i = 0; i < list_size; i++) {
        memset(list_ptr, 0, sizeof(ws_neigh_t));
        list_ptr->rsl_in = RSL_UNITITIALIZED;
        list_ptr->rsl_out = RSL_UNITITIALIZED;
        list_ptr->index = i;
        list_ptr++;
    }
    return true;
}


void ws_neigh_dealloc(ws_neigh_table_t *table)
{
    free(table->neigh_info_list);
    table->neigh_info_list = NULL;
    table->list_size = 0;
}

ws_neigh_t *ws_neigh_add(ws_neigh_table_t *table,
                         const uint8_t mac64[8],
                         uint8_t role,
                         unsigned int key_index_mask)
{
    ws_neigh_t *neigh_table = table->neigh_info_list;
    ws_neigh_t *neigh_entry = NULL;

    for (uint8_t i = 0; i < table->list_size; i++) {
        if (!neigh_table[i].in_use) {
            neigh_entry = &neigh_table[i];
            break;
        }
    }

    if (!neigh_entry)
        return NULL;

    neigh_entry->node_role = role;
    for (uint8_t key_index = 1; key_index <= 7; key_index++)
        if (!(key_index_mask & (1u << key_index)))
            neigh_entry->frame_counter_min[key_index - 1] = UINT32_MAX;
    neigh_entry->in_use = true;
    memcpy(neigh_entry->mac64, mac64, 8);
    neigh_entry->lifetime_s = WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME;
    neigh_entry->expiration_s = time_current(CLOCK_MONOTONIC) + WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor add %s / %ds", tr_eui64(neigh_entry->mac64), neigh_entry->lifetime_s);
    return neigh_entry;
}

ws_neigh_t *ws_neigh_get(ws_neigh_table_t *table, const uint8_t *mac64)
{
    ws_neigh_t *neigh_table = table->neigh_info_list;

    for (uint8_t i = 0; i < table->list_size; i++) {
        if (!neigh_table[i].in_use)
            continue;
        if (!memcmp(neigh_table[i].mac64, mac64, 8))
            return &neigh_table[i];
    }

    return NULL;
}

void ws_neigh_del(ws_neigh_table_t *table, const uint8_t *mac64)
{
    ws_neigh_t *entry = ws_neigh_get(table, mac64);
    uint8_t index;

    if (entry) {
        TRACE(TR_NEIGH_15_4, "15.4 neighbor del %s / %ds", tr_eui64(entry->mac64), entry->lifetime_s);
        index = entry->index;
        memset(entry, 0, sizeof(ws_neigh_t));
        entry->rsl_in = RSL_UNITITIALIZED;
        entry->rsl_out = RSL_UNITITIALIZED;
        entry->index = index;
    }
}

void ws_neigh_table_expire(struct ws_neigh_table *table, int time_update)
{
    ws_neigh_t *neigh_table = table->neigh_info_list;

    for (uint8_t i = 0; i < table->list_size; i++) {
        if (!neigh_table[i].in_use)
            continue;

        if (time_current(CLOCK_MONOTONIC) >= neigh_table[i].expiration_s)
            table->remove_cb(neigh_table[i].mac64);
    }
}

uint8_t ws_neigh_get_neigh_count(ws_neigh_table_t *table)
{
    ws_neigh_t *neigh_table = table->neigh_info_list;
    uint8_t count = 0;

    for (uint8_t i = 0; i < table->list_size; i++)
        if (neigh_table[i].in_use)
            count++;

    return count;
}

static void ws_neigh_calculate_ufsi_drift(ws_neigh_t *ws_neighbor, uint24_t ufsi,
                                          uint64_t timestamp, const uint8_t address[8])
{
    if (ws_neighbor->fhss_data.ffn.utt_rx_tstamp_us && ws_neighbor->fhss_data.ffn.ufsi) {
        // No UFSI on fixed channel
        if (ws_neighbor->fhss_data.uc_chan_func == WS_FIXED_CHANNEL) {
            return;
        }
        double seq_length = 0x10000;
        if (ws_neighbor->fhss_data.uc_chan_func == WS_TR51CF) {
            seq_length = ws_neighbor->fhss_data.uc_chan_count;
        }
        double ufsi_prev_tmp = ws_neighbor->fhss_data.ffn.ufsi;
        double ufsi_cur_tmp = ufsi;
        if (ws_neighbor->fhss_data.uc_chan_func == WS_DH1CF) {
            if (ufsi_cur_tmp < ufsi_prev_tmp) {
                ufsi_cur_tmp += 0xffffff;
            }
        }
        // Convert 24-bit UFSI to real time before drift calculation
        double time_since_seq_start_prev_ms = (ufsi_prev_tmp * seq_length * ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms) / 0x1000000;
        double time_since_seq_start_cur_ms = (ufsi_cur_tmp * seq_length * ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms) / 0x1000000;
        uint64_t time_since_last_ufsi_us = timestamp - ws_neighbor->fhss_data.ffn.utt_rx_tstamp_us;

        if (ws_neighbor->fhss_data.uc_chan_func == WS_TR51CF) {
            uint32_t full_uc_schedule_ms = ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms * ws_neighbor->fhss_data.uc_chan_count;
            uint32_t temp_ms;

            if (!full_uc_schedule_ms)
                return;
            temp_ms = (time_since_last_ufsi_us / 1000) / full_uc_schedule_ms;
            if (time_since_seq_start_cur_ms >= time_since_seq_start_prev_ms) {
                temp_ms--;
            }
            time_since_seq_start_cur_ms += temp_ms * full_uc_schedule_ms + (full_uc_schedule_ms - time_since_seq_start_prev_ms) + time_since_seq_start_prev_ms;
        }

        double ufsi_diff_ms = time_since_seq_start_cur_ms - time_since_seq_start_prev_ms;
        if (time_since_seq_start_cur_ms < time_since_seq_start_prev_ms)
            // add ufsi sequence length
            ufsi_diff_ms += seq_length * ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms;

        double ufsi_drift_ms = time_since_last_ufsi_us / 1000.f - ufsi_diff_ms;
        // Since resolution of the RCP timer is 1µs, a window 10 million times
        // larger (=10s) allows to get 0.1ppm of precision in the calculus below
        // FIXME: improve precision by storing ufsi over time and calculate drift
        // over a bigger window
        if (time_since_last_ufsi_us >= 10000000)
            TRACE(TR_NEIGH_15_4, "15.4 neighbor sync %s / %.01lfppm drift (%.0lfus in %lds)", tr_eui64(address),
                  1000000000.f * ufsi_drift_ms / time_since_last_ufsi_us, ufsi_drift_ms * 1000, time_since_last_ufsi_us / 1000000);
        else
            TRACE(TR_NEIGH_15_4, "15.4 neighbor sync %s / drift measure not available", tr_eui64(address));
    }
}

void ws_neigh_ut_update(ws_neigh_t *neighbor, uint24_t ufsi,
                        uint64_t tstamp_us, const uint8_t eui64[8])
{
    ws_neigh_calculate_ufsi_drift(neighbor, ufsi, tstamp_us, eui64);

    if (neighbor->fhss_data.ffn.utt_rx_tstamp_us == tstamp_us &&
        neighbor->fhss_data.ffn.ufsi             == ufsi)
        return; // Save an update

    neighbor->fhss_data.ffn.utt_rx_tstamp_us = tstamp_us;
    neighbor->fhss_data.ffn.ufsi             = ufsi;
    neighbor->host_rx_timestamp = time_current(CLOCK_MONOTONIC);
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_legacy_set_fhss_neighbor(eui64, &neighbor->fhss_data);
}

void ws_neigh_lut_update(ws_neigh_t *neighbor,
                         uint16_t slot_number, uint24_t interval_offset,
                         uint64_t tstamp_us, const uint8_t eui64[8])
{
    neighbor->fhss_data.lfn.lutt_rx_tstamp_us     = tstamp_us;
    neighbor->fhss_data.lfn.uc_slot_number        = slot_number;
    neighbor->fhss_data.lfn.uc_interval_offset_ms = interval_offset;
}

void ws_neigh_lnd_update(ws_neigh_t *neighbor, const struct ws_lnd_ie *ie_lnd, uint64_t tstamp_us)
{
    neighbor->fhss_data.lfn.lpa_response_delay_ms = ie_lnd->response_delay;
    neighbor->fhss_data.lfn.lpa_slot_duration_ms  = ie_lnd->discovery_slot_time;
    neighbor->fhss_data.lfn.lpa_slot_count        = ie_lnd->discovery_slots;
    neighbor->fhss_data.lfn.lpa_slot_first        = ie_lnd->discovery_first_slot;
    neighbor->fhss_data.lfn.lnd_rx_tstamp_us      = tstamp_us;
}

void ws_neigh_nr_update(ws_neigh_t *neighbor, ws_nr_ie_t *nr_ie)
{
    neighbor->fhss_data.lfn.uc_interval_min_ms = nr_ie->listen_interval_min;
    neighbor->fhss_data.lfn.uc_interval_max_ms = nr_ie->listen_interval_max;
}

static void ws_neigh_excluded_mask_by_range(struct ws_channel_mask *channel_info,
                                            const ws_excluded_channel_range_t *range_info, uint16_t number_of_channels)
{
    uint16_t range_start, range_stop;
    const uint8_t *range_ptr = range_info->range_start;

    for (int i = 0; i < range_info->number_of_range; i++) {
        range_start = read_le16(range_ptr);
        range_ptr += 2;
        range_stop = MIN(read_le16(range_ptr), number_of_channels);
        range_ptr += 2;
        for (int channel = range_start; channel <= range_stop; channel++) {
            if (bittest(channel_info->channel_mask, channel)) {
                bitclr(channel_info->channel_mask, channel);
                channel_info->channel_count--;
            }
        }
    }
}

static void ws_neigh_excluded_mask_by_mask(struct ws_channel_mask *channel_info,
                                           const ws_excluded_channel_mask_t *mask_info, uint16_t number_of_channels)
{
    int nchan = MIN(number_of_channels, mask_info->mask_len_inline * 8);

    for (int i = 0; i < nchan; i++) {
        if (bittest(channel_info->channel_mask, i) && bittest(mask_info->channel_mask, i)) {
            bitclr(channel_info->channel_mask, i);
            channel_info->channel_count--;
        }
    }
}

static void ws_neigh_set_chan_list(const struct net_if *net_if,
                                   struct ws_channel_mask *chan_list,
                                   const struct ws_generic_channel_info *_chan_info,
                                   uint16_t *chan_cnt)
{
    struct ws_generic_channel_info chan_info = *_chan_info;
    uint8_t reg_domain = REG_DOMAIN_UNDEF;
    uint8_t chan_plan_id = 0;
    uint8_t op_class = 0;

    switch (chan_info.channel_plan) {
    case 0:
        reg_domain = chan_info.plan.zero.regulatory_domain;
        op_class   = chan_info.plan.zero.operating_class;
        *chan_cnt = ws_common_channel_number_calc(reg_domain, op_class, 0);
        break;
    case 1:
        *chan_cnt = chan_info.plan.one.number_of_channel;
        break;
    case 2:
        reg_domain   = chan_info.plan.two.regulatory_domain;
        chan_plan_id = chan_info.plan.two.channel_plan_id;
        *chan_cnt = ws_common_channel_number_calc(reg_domain, 0, chan_plan_id);
        break;
    default:
        BUG("unsupported channel plan: %d", chan_info.channel_plan);
    }

    switch (chan_info.excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_RANGE:
        ws_common_generate_channel_list(net_if, chan_list->channel_mask, *chan_cnt,
                                        reg_domain, op_class, chan_plan_id);
        chan_list->channel_count = bitcnt(chan_list->channel_mask, *chan_cnt);
        ws_neigh_excluded_mask_by_range(chan_list, &chan_info.excluded_channels.range, *chan_cnt);
        break;
    case WS_EXC_CHAN_CTRL_BITMASK:
        ws_common_generate_channel_list(net_if, chan_list->channel_mask, *chan_cnt,
                                        reg_domain, op_class, chan_plan_id);
        chan_list->channel_count = bitcnt(chan_list->channel_mask, *chan_cnt);
        ws_neigh_excluded_mask_by_mask(chan_list, &chan_info.excluded_channels.mask, *chan_cnt);
        break;
    case WS_EXC_CHAN_CTRL_NONE:
        if (*chan_cnt != chan_list->channel_count) {
            ws_common_generate_channel_list(net_if, chan_list->channel_mask, *chan_cnt,
                                            reg_domain, op_class, chan_plan_id);
            chan_list->channel_count = bitcnt(chan_list->channel_mask, *chan_cnt);
        }
        break;
    default:
        BUG("unsupported excluded channel control: %d", chan_info.excluded_channel_ctrl);
    }
}

void ws_neigh_us_update(const struct net_if *net_if, ws_neigh_t *ws_neighbor,
                        const struct ws_generic_channel_info *chan_info,
                        uint8_t dwell_interval, const uint8_t eui64[8])
{
    ws_neighbor->fhss_data.uc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_FIXED_CHANNEL) {
        ws_neighbor->fhss_data.uc_chan_fixed = chan_info->function.zero.fixed_channel;
        ws_neighbor->fhss_data.uc_chan_count = 1;
    } else {
        ws_neigh_set_chan_list(net_if, &ws_neighbor->fhss_data.uc_channel_list, chan_info,
                                  &ws_neighbor->fhss_data.uc_chan_count);
    }
    ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms = dwell_interval;
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_legacy_set_fhss_neighbor(eui64, &ws_neighbor->fhss_data);
}

// Compute the divisors of val closest to q_ref, possibly including 1 and val
static void ws_neigh_calc_closest_divisors(uint24_t val, uint24_t q_ref,
                                           uint24_t *below, uint24_t *above)
{
    uint24_t q;
    uint24_t _q;

    *below = 0;
    *above = 0;
    // Iterate through divisors from 1 to sqrt(val)
    for (q = 1; q * q <= val; q++) {
        if (val % q == 0) {
            if (q <= q_ref) {
                *below = q;
            } else {
                *above = q;
                return;
            }
        }
    }
    // Iterate through the remaining divisors
    q--;
    for (; q > 0; q--) {
        _q = val / q;
        if (val % _q == 0) {
            if (_q <= q_ref) {
                *below = _q;
            } else {
                *above = _q;
                return;
            }
        }
    }
}

// Compute the Adjusted Listening Interval to be included in the LTO-IE
// See Wi-SUN FAN 1.1v06 6.3.4.6.4.2.1.2 FFN Processing of LFN PAN Advertisement Solicit
uint24_t ws_neigh_calc_lfn_adjusted_interval(uint24_t bc_interval, uint24_t uc_interval,
                                             uint24_t uc_interval_min, uint24_t uc_interval_max)
{
    uint24_t r;
    uint24_t q_above;
    uint24_t q_below;

    if (!bc_interval || !uc_interval || !uc_interval_min || !uc_interval_max)
        return 0;
    if (uc_interval < uc_interval_min || uc_interval > uc_interval_max) {
        TRACE(TR_IGNORE, "ignore: lto-ie incoherent with nr-ie");
        return 0;
    }

    if (uc_interval > bc_interval) {
        // Current state:
        //   uc = q * bc + r
        // Desired state:
        //   uc' = q' * bc
        // This can be solved arithmetically:
        //   for a bigger interval:  uc' = uc + bc - r = (q + 1) * bc
        //   for a smaller interval: uc' = uc - r = q * bc
        r = uc_interval % bc_interval;
        if (r == 0)
            return uc_interval; // No need to adjust
        if (uc_interval + bc_interval - r <= uc_interval_max)
            return uc_interval + bc_interval - r; // Extend interval
        if (uc_interval - r >= uc_interval_min)
            return uc_interval - r; // Reduce interval
        return uc_interval; // No multiple available in range
    } else {
        // Current state:
        //   bc = q * uc + r
        // Desired state:
        //   bc = q' * uc'
        // This case is much more difficult. The solution proposed here is
        // iterate through divisors of bc to find those closest to q:
        //   q_below <= q < q_above
        //   for a bigger interval:  uc' = bc / q_below
        //   for a smaller interval: uc' = bc / q_above
        if (bc_interval % uc_interval == 0)
            return uc_interval; // No need to adjust

        ws_neigh_calc_closest_divisors(bc_interval, bc_interval / uc_interval,
                                                &q_below, &q_above);

        if (q_above && bc_interval / q_above >= uc_interval_min)
            return bc_interval / q_above; // Reduce interval
        if (q_below && bc_interval / q_below <= uc_interval_max)
            return bc_interval / q_below; // Extend interval
        return uc_interval; // No sub-multiple available in range
    }
}

uint24_t ws_neigh_calc_lfn_offset(uint24_t adjusted_listening_interval, uint32_t bc_interval)
{
    /* This minimalist algorithm ensures that LFN BC will not overlap with any
     * LFN UC.
     * It returns an offset inside the LFN BC Interval that will be used by the
     * MAC to computed the actual offset to be applied by the targeted LFN.
     * Any LFN UC is placed randomly after the LFN BC, in an interval of
     *   offset = [GUARD_INTERVAL, LFN_BC_INTERVAL - GUARD_INTERVAL] or
     *   offset = [GUARD_INTERVAL, LFN_UC_INTERVAL - GUARD_INTERVAL]
     * For any multiple LFN UC interval, the listening slot will happen at
     * "offset + n*LFN_BC_INTERVAL" which guarantees that it will not come near
     * the LFN BC slot.
     * For any divisor LFN UC interval, the listening slot will happen an
     * entire number of times between two LFN BC slot, which is fine.
     * The two closest LFN UC slots are at:
     *   "offset + n*LFN_BC_INTERVAL - LFN_UC INTERVAL" and
     *   "offset + n*LFN_BC_INTERVAL"
     * These are safe as long as "LFN_UC_INTERVAL >= 2 * GUARD_INTERVAL"
     * Because of the randomness and the offset range depending on the
     * LFN UC Interval, there is no protection between LFN Unicast schedules.
     * However, they are spread as much as possible.
     * TODO: algorithm that allocates or reallocates offsets to each LFN in
     * order to minimize overlap.
     */
    uint16_t max_offset_ms;

    // Cannot protect LFN BC with such a short interval, do nothing
    if (adjusted_listening_interval < 2 * LFN_SCHEDULE_GUARD_TIME_MS)
        return 0;

    if (adjusted_listening_interval >= bc_interval)
        max_offset_ms = bc_interval - LFN_SCHEDULE_GUARD_TIME_MS;
    else
        max_offset_ms = adjusted_listening_interval - LFN_SCHEDULE_GUARD_TIME_MS;
    return LFN_SCHEDULE_GUARD_TIME_MS * rand_get_random_in_range(1, max_offset_ms / LFN_SCHEDULE_GUARD_TIME_MS);
}

void ws_neigh_lus_update(const struct net_if *net_if,
                         ws_neigh_t *ws_neighbor,
                         const struct ws_generic_channel_info *chan_info,
                         uint24_t listen_interval_ms)
{
    uint24_t adjusted_listening_interval;

    if (ws_neighbor->fhss_data.lfn.uc_listen_interval_ms != listen_interval_ms) {
        adjusted_listening_interval = ws_neigh_calc_lfn_adjusted_interval(net_if->ws_info.fhss_conf.lfn_bc_interval,
                                                                                        ws_neighbor->fhss_data.lfn.uc_listen_interval_ms,
                                                                                        ws_neighbor->fhss_data.lfn.uc_interval_min_ms,
                                                                                        ws_neighbor->fhss_data.lfn.uc_interval_max_ms);
        if (adjusted_listening_interval && adjusted_listening_interval != listen_interval_ms)
            ws_neighbor->offset_adjusted = false;
    }

    ws_neighbor->fhss_data.lfn.uc_listen_interval_ms = listen_interval_ms;
    if (!chan_info)
        return; // Support chan plan tag 255 (reuse previous schedule)
    ws_neighbor->fhss_data.uc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_FIXED_CHANNEL) {
        ws_neighbor->fhss_data.uc_chan_fixed = chan_info->function.zero.fixed_channel;
        ws_neighbor->fhss_data.uc_chan_count = 1;
    } else {
        ws_neigh_set_chan_list(net_if, &ws_neighbor->fhss_data.uc_channel_list, chan_info,
                                  &ws_neighbor->fhss_data.uc_chan_count);
    }
}

uint8_t ws_neigh_rsl_from_dbm_calculate(int8_t dbm_heard)
{
    /* RSL MUST be calculated as the received signal level relative to standard
     * thermal noise (290oK) at 1 Hz bandwidth or 174 dBm.
     * This provides a range of -174 (0) to +80 (254) dBm.
     */

    return dbm_heard + 174;
}

static void ws_neigh_parent_set_analyze(ws_neigh_t *ws_neighbor)
{
    if (ws_neighbor->rsl_in == RSL_UNITITIALIZED ||
            ws_neighbor->rsl_out == RSL_UNITITIALIZED) {
        ws_neighbor->candidate_parent = false;
        return;
    }

    if (ws_neigh_rsl_in_get(ws_neighbor) < (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD - CAND_PARENT_HYSTERISIS) &&
            ws_neigh_rsl_out_get(ws_neighbor) < (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD - CAND_PARENT_HYSTERISIS)) {
        ws_neighbor->candidate_parent = false;
    }

    if (ws_neigh_rsl_in_get(ws_neighbor) > (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERISIS) &&
            ws_neigh_rsl_out_get(ws_neighbor) > (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERISIS)) {
        ws_neighbor->candidate_parent = true;
    }
}

void ws_neigh_rsl_in_calculate(ws_neigh_t *ws_neighbor, int8_t dbm_heard)
{
    uint8_t rsl = ws_neigh_rsl_from_dbm_calculate(dbm_heard);
    if (ws_neighbor->rsl_in == RSL_UNITITIALIZED) {
        ws_neighbor->rsl_in = rsl << WS_RSL_SCALING;
    }
    ws_neighbor->rsl_in = ws_neighbor->rsl_in + rsl - (ws_neighbor->rsl_in >> WS_RSL_SCALING);
    ws_neighbor->rssi = dbm_heard;
    ws_neigh_parent_set_analyze(ws_neighbor);
    return;
}

void ws_neigh_rsl_out_calculate(ws_neigh_t *ws_neighbor, uint8_t rsl_reported)
{
    if (ws_neighbor->rsl_out == RSL_UNITITIALIZED) {
        ws_neighbor->rsl_out = rsl_reported << WS_RSL_SCALING;
    }
    ws_neighbor->rsl_out = ws_neighbor->rsl_out + rsl_reported - (ws_neighbor->rsl_out >> WS_RSL_SCALING);
    ws_neigh_parent_set_analyze(ws_neighbor);
    return;
}


bool ws_neigh_neighbor_duplicate_packet_check(ws_neigh_t *ws_neighbor,
                                              uint8_t mac_dsn, uint64_t rx_timestamp)
{
    if (ws_neighbor->last_DSN != mac_dsn) {
        // New packet always accepted
        ws_neighbor->last_DSN = mac_dsn;
        return true;
    }

    if (!ws_neighbor->unicast_data_rx) {
        // No unicast info stored always accepted
        return true;
    }

    rx_timestamp -= ws_neighbor->fhss_data.ffn.utt_rx_tstamp_us;
    rx_timestamp /= 1000000; //Convert to s

    //Compare only when last rx timestamp is less than 5 seconds
    if (rx_timestamp < 5) {
        //Packet is sent too fast filter it out
        return false;
    }

    return true;
}

int ws_neigh_lfn_count(ws_neigh_table_t *table)
{
    ws_neigh_t *neigh_table = table->neigh_info_list;
    int cnt = 0;

    for (uint8_t i = 0; i < table->list_size; i++)
        if (neigh_table[i].node_role == WS_NR_ROLE_LFN)
            cnt++;

    return cnt;
}

void ws_neigh_trusted_neighbor(struct ws_neigh *neigh)
{
    if (neigh->trusted_device)
        return;

    neigh->expiration_s = time_current(CLOCK_MONOTONIC) + neigh->lifetime_s;
    neigh->trusted_device = true;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor trusted %s / %ds", tr_eui64(neigh->mac64), neigh->lifetime_s);
}

void ws_neigh_refresh_neighbor(struct ws_neigh *neigh, uint32_t lifetime_s)
{
    neigh->lifetime_s = lifetime_s;
    neigh->expiration_s = time_current(CLOCK_MONOTONIC) + lifetime_s;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor refresh %s / %ds", tr_eui64(neigh->mac64), neigh->lifetime_s);
}
