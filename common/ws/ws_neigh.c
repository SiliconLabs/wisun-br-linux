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
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <inttypes.h>
#include <limits.h>
#include "common/ws/ws_regdb.h"
#include "common/ws/ws_types.h"
#include "common/sys_queue_extra.h"
#include "common/string_extra.h"
#include "common/time_extra.h"
#include "common/version.h"
#include "common/endian.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/rand.h"
#include "common/log.h"
#include "common/bits.h"
#include "common/specs/ws.h"

#include "ws_neigh.h"

#define LFN_SCHEDULE_GUARD_TIME_MS 300

static void ws_neigh_timer_cb(struct timer_group *group, struct timer_entry *timer)
{
    struct ws_neigh_table *table = container_of(group, struct ws_neigh_table, timer_group);
    struct ws_neigh *neigh = container_of(timer, struct ws_neigh, timer);

    ws_neigh_del(table, &neigh->eui64);
}

// Wi-SUN FAN 1v33 6.2.3.1.6.1 Link Metrics
static void ws_neigh_etx_compute(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    float etx;

    /*
     * The ETX calculation epoch is triggered when both the following
     * conditions are satisfied:
     *   1. At least 4 transmissions have occurred since the last ETX
     *      calculation.
     *   2. At least 1 minute has expired since the last ETX calculation.
     *
     * [...]
     *
     * At node start up, 1 transmission attempts will trigger the ETX
     * calculation epoch (to speed boot time).
     */
    if (!((neigh->etx_tx_cnt >= 4 && timer_stopped(&neigh->etx_timer_compute)) ||
          isnan(neigh->etx))) {
        // Probe right now until we reach the 4 necessary measurements
        if (timer_stopped(&neigh->etx_timer_outdated) && table->on_etx_outdated)
            table->on_etx_outdated(table, neigh);
        return;
    }

    /*
     * ETX MUST be calculated as
     *   (frame transmission attempts)/(received frame acknowledgements) * 128
     * with a maximum value of 1024, where 0 received frame acknowledgments
     * sets ETX to the maximum value.
     */
    if (neigh->etx_ack_cnt)
        etx = MIN((float)neigh->etx_tx_cnt / neigh->etx_ack_cnt * 128, WS_ETX_MAX);
    else
        etx = WS_ETX_MAX;

    /*
     * Arbitrary: we give less weight to the first few ETX calculations.
     * This allows to converge to a more accurate ETX value faster.
     */
    if (neigh->etx_compute_cnt < 8)
        neigh->etx_compute_cnt++;

    /*
     * The ETX calculation is performed at a defined epoch, with the ETX result
     * fed into an EWMA using smoothing factor of 1/8.
     */
    etx = ws_neigh_ewma_next(neigh->etx, etx, 1.f / (float)neigh->etx_compute_cnt);

    TRACE(TR_NEIGH_15_4, "15.4 neighbor %s etx update tx=%u / ack=%u => old=%.2f new=%.2f",
          tr_eui64(neigh->eui64.u8), neigh->etx_tx_cnt, neigh->etx_ack_cnt, neigh->etx, etx);

    neigh->etx = etx;
    neigh->etx_tx_cnt  = 0;
    neigh->etx_ack_cnt = 0;
    timer_start_rel(&table->timer_group, &neigh->etx_timer_compute, 60 * 1000);

    /*
     * A Router SHOULD refresh its neighbor link metrics at least every 30
     * minutes.
     */
    timer_start_rel(&table->timer_group, &neigh->etx_timer_outdated, 30 * 60 * 1000);

    if (table->on_etx_update)
        table->on_etx_update(table, neigh);
}

static void ws_neigh_etx_timeout_outdated(struct timer_group *group, struct timer_entry *timer)
{
    struct ws_neigh_table *table = container_of(group, struct ws_neigh_table, timer_group);
    struct ws_neigh *neigh = container_of(timer, struct ws_neigh, etx_timer_outdated);

    if (table->on_etx_outdated)
        table->on_etx_outdated(table, neigh);
}

static void ws_neigh_etx_timeout_compute(struct timer_group *group, struct timer_entry *timer)
{
    struct ws_neigh_table *table = container_of(group, struct ws_neigh_table, timer_group);
    struct ws_neigh *neigh = container_of(timer, struct ws_neigh, etx_timer_compute);

    ws_neigh_etx_compute(table, neigh);
}

void ws_neigh_etx_update(struct ws_neigh_table *table,
                         struct ws_neigh *neigh,
                         int tx_count, bool ack)
{
    neigh->etx_tx_cnt  += tx_count;
    neigh->etx_ack_cnt += ack;
    /*
     * FIXME: ETX computation is scheduled to ensure the confirmed frame is
     * properly processed by higher layers.
     */
    timer_start_rel(&table->timer_group, &neigh->etx_timer_compute, 0);
}

struct ws_neigh *ws_neigh_add(struct ws_neigh_table *table,
                              const struct eui64 *eui64,
                              uint8_t role, int8_t tx_power_dbm,
                              unsigned int key_index_mask)
{
    struct ws_neigh *neigh = zalloc(sizeof(struct ws_neigh));

    neigh->node_role = role;
    for (uint8_t key_index = 1; key_index <= HIF_KEY_COUNT; key_index++)
        if (!(key_index_mask & BIT(key_index)))
            neigh->frame_counter_min[key_index - 1] = UINT32_MAX;

    /*
     *  Wi-SUN FAN 1.1v09 6.2.3.1.6.1 Link Metrics
     * A Router SHOULD refresh its neighbor link metrics at least every 30
     * minutes.
     *
     * Note:
     * - this neighbor link metrics refresh only applies to wsrd
     * - 2200s gives a 7min margin for probe retries.
     */
    neigh->lifetime_s = WS_NEIGHBOR_LINK_TIMEOUT;
    neigh->eui64 = *eui64;
    neigh->timer.callback = ws_neigh_timer_cb;
    timer_start_rel(&table->timer_group, &neigh->timer, neigh->lifetime_s * 1000);
    neigh->rsl_in_dbm = NAN;
    neigh->rsl_in_dbm_unsecured = NAN;
    neigh->rsl_out_dbm = NAN;
    neigh->rx_power_dbm = INT_MAX;
    neigh->rx_power_dbm_unsecured = INT_MAX;
    neigh->lqi = INT_MAX;
    neigh->lqi_unsecured = INT_MAX;
    neigh->apc_txpow_dbm = tx_power_dbm;
    neigh->apc_txpow_dbm_ofdm = tx_power_dbm;
    neigh->etx = NAN;
    neigh->etx_timer_compute.callback  = ws_neigh_etx_timeout_compute;
    neigh->etx_timer_outdated.callback = ws_neigh_etx_timeout_outdated;
    SLIST_INSERT_HEAD(&table->neigh_list, neigh, link);
    if (table->on_add)
        table->on_add(table, neigh);
    TRACE(TR_NEIGH_15_4, "15.4 neighbor add %s / %ds", tr_eui64(neigh->eui64.u8), neigh->lifetime_s);
    return neigh;
}

struct ws_neigh *ws_neigh_get(const struct ws_neigh_table *table, const struct eui64 *eui64)
{
    struct ws_neigh *neigh;

    return SLIST_FIND(neigh, &table->neigh_list, link,
                      eui64_eq(&neigh->eui64, eui64));
}

void ws_neigh_del(struct ws_neigh_table *table, const struct eui64 *eui64)
{
    struct ws_neigh *neigh = ws_neigh_get(table, eui64);

    if (neigh) {
        timer_stop(&table->timer_group, &neigh->timer);
        timer_stop(&table->timer_group, &neigh->etx_timer_compute);
        timer_stop(&table->timer_group, &neigh->etx_timer_outdated);
        SLIST_REMOVE(&table->neigh_list, neigh, ws_neigh, link);
        TRACE(TR_NEIGH_15_4, "15.4 neighbor del %s / %ds", tr_eui64(neigh->eui64.u8), neigh->lifetime_s);
        if (table->on_del)
            table->on_del(table, neigh);
        free(neigh);
    }
}

void ws_neigh_clean(struct ws_neigh_table *table)
{
    struct ws_neigh *neigh;
    struct ws_neigh *tmp;

    SLIST_FOREACH_SAFE(neigh, &table->neigh_list, link, tmp)
        ws_neigh_del(table, &neigh->eui64);
}

void ws_neigh_etx_reset(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    neigh->etx = NAN;
    neigh->etx_tx_cnt = 0;
    neigh->etx_ack_cnt = 0;
    neigh->etx_compute_cnt = 0;
    timer_stop(&table->timer_group, &neigh->etx_timer_compute);
    timer_stop(&table->timer_group, &neigh->etx_timer_outdated);
}

size_t ws_neigh_get_neigh_count(struct ws_neigh_table *table)
{
    return SLIST_SIZE(&table->neigh_list, link);
}

static void ws_neigh_calculate_ufsi_drift(struct ws_neigh_fhss *fhss_data, uint24_t ufsi,
                                          uint64_t timestamp, const struct eui64 *eui64)
{
    if (fhss_data->ffn.utt_rx_tstamp_us && fhss_data->ffn.ufsi) {
        // No UFSI on fixed channel
        if (fhss_data->uc_chan_func == WS_CHAN_FUNC_FIXED) {
            return;
        }
        double seq_length = 0x10000;
        double ufsi_prev_tmp = fhss_data->ffn.ufsi;
        double ufsi_cur_tmp = ufsi;
        if (fhss_data->uc_chan_func == WS_CHAN_FUNC_DH1CF) {
            if (ufsi_cur_tmp < ufsi_prev_tmp) {
                ufsi_cur_tmp += 0xffffff;
            }
        }
        // Convert 24-bit UFSI to real time before drift calculation
        double time_since_seq_start_prev_ms = (ufsi_prev_tmp * seq_length * fhss_data->ffn.uc_dwell_interval_ms) / 0x1000000;
        double time_since_seq_start_cur_ms = (ufsi_cur_tmp * seq_length * fhss_data->ffn.uc_dwell_interval_ms) / 0x1000000;
        uint64_t time_since_last_ufsi_us = timestamp - fhss_data->ffn.utt_rx_tstamp_us;

        double ufsi_diff_ms = time_since_seq_start_cur_ms - time_since_seq_start_prev_ms;
        if (time_since_seq_start_cur_ms < time_since_seq_start_prev_ms)
            // add ufsi sequence length
            ufsi_diff_ms += seq_length * fhss_data->ffn.uc_dwell_interval_ms;

        double ufsi_drift_ms = time_since_last_ufsi_us / 1000.f - ufsi_diff_ms;
        // Since resolution of the RCP timer is 1µs, a window 10 million times
        // larger (=10s) allows to get 0.1ppm of precision in the calculus below
        // FIXME: improve precision by storing ufsi over time and calculate drift
        // over a bigger window
        if (time_since_last_ufsi_us >= 10000000)
            TRACE(TR_NEIGH_15_4, "15.4 neighbor sync %s / %.01lfppm drift (%.0lfus in %"PRId64"s)", tr_eui64(eui64->u8),
                  1000000000.f * ufsi_drift_ms / time_since_last_ufsi_us, ufsi_drift_ms * 1000, time_since_last_ufsi_us / 1000000);
        else
            TRACE(TR_NEIGH_15_4, "15.4 neighbor sync %s / drift measure not available", tr_eui64(eui64->u8));
    }
}

void ws_neigh_ut_update(struct ws_neigh_fhss *fhss_data, uint24_t ufsi,
                        uint64_t tstamp_us, const struct eui64 *eui64)
{
    ws_neigh_calculate_ufsi_drift(fhss_data, ufsi, tstamp_us, eui64);

    if (fhss_data->ffn.utt_rx_tstamp_us == tstamp_us &&
        fhss_data->ffn.ufsi             == ufsi)
        return; // Save an update

    fhss_data->ffn.utt_rx_tstamp_us = tstamp_us;
    fhss_data->ffn.ufsi             = ufsi;
}

// Wi-SUN FAN 1.1v08 - 6.3.4.6.4.2.6 Maintaining FFN / LFN Synchronization
//   When the FFN receives a LUTT-IE from a LFN it does not adjust any time
//   difference relative to the expected LFN’s unicast listening reference point.
// In fact, the LUTT information must only be updated when combined with an
// LUS-IE which indicates a change in timing offset and/or interval.
void ws_neigh_lut_update(struct ws_neigh_fhss *fhss_data,
                         uint16_t slot_number, uint24_t interval_offset,
                         uint64_t tstamp_us)
{
    fhss_data->lfn.lutt_rx_tstamp_us     = tstamp_us;
    fhss_data->lfn.uc_slot_number        = slot_number;
    fhss_data->lfn.uc_interval_offset_ms = interval_offset;
}

void ws_neigh_lnd_update(struct ws_neigh_fhss *fhss_data, const struct ws_lnd_ie *ie_lnd, uint64_t tstamp_us)
{
    fhss_data->lfn.lpa_response_delay_ms = ie_lnd->response_delay;
    fhss_data->lfn.lpa_slot_duration_ms  = ie_lnd->discovery_slot_time;
    fhss_data->lfn.lpa_slot_count        = ie_lnd->discovery_slots;
    fhss_data->lfn.lpa_slot_first        = ie_lnd->discovery_first_slot;
    fhss_data->lfn.lnd_rx_tstamp_us      = tstamp_us;
}

void ws_neigh_nr_update(struct ws_neigh *neigh, struct ws_nr_ie *nr_ie)
{
    neigh->lto_info.uc_interval_min_ms = nr_ie->listen_interval_min;
    neigh->lto_info.uc_interval_max_ms = nr_ie->listen_interval_max;
}

static void ws_neigh_excluded_mask_by_range(uint8_t channel_mask[WS_CHAN_MASK_LEN],
                                            const struct ws_excluded_channel_range *range_info,
                                            uint16_t number_of_channels)
{
    uint16_t range_start, range_stop;
    const uint8_t *range_ptr = range_info->range_start;

    for (int i = 0; i < range_info->number_of_range; i++) {
        range_start = read_le16(range_ptr);
        range_ptr += 2;
        range_stop = MIN(read_le16(range_ptr), number_of_channels);
        range_ptr += 2;
        bitfill(channel_mask, false, range_start, range_stop);
    }
}

static void ws_neigh_excluded_mask_by_mask(uint8_t channel_mask[WS_CHAN_MASK_LEN],
                                           const struct ws_excluded_channel_mask *mask_info,
                                           uint16_t number_of_channels)
{
    int nchan = MIN(number_of_channels, mask_info->mask_len_inline * 8);

    for (int i = 0; i < nchan; i++)
        if (bittest(mask_info->channel_mask, i))
            bitclr(channel_mask, i);
}

static void ws_neigh_set_chan_list(const struct ws_fhss_config *fhss_config,
                                   uint8_t chan_mask[WS_CHAN_MASK_LEN],
                                   const struct ws_generic_channel_info *chan_info)
{
    struct chan_params params_custom = {
        .reg_domain   = REG_DOMAIN_UNDEF,
        .chan0_freq   = chan_info->plan.one.ch0 * 1000,
        .chan_count   = chan_info->plan.one.number_of_channel,
    };
    const struct chan_params *params = NULL;

    switch (chan_info->channel_plan) {
    case 0:
        params = ws_regdb_chan_params(chan_info->plan.zero.regulatory_domain, 0, chan_info->plan.zero.operating_class);
        BUG_ON(!params);
        break;
    case 1:
        params_custom.chan_spacing = ws_regdb_chan_spacing_from_id(chan_info->plan.one.channel_spacing),
        params = &params_custom;
        break;
    case 2:
        params = ws_regdb_chan_params(chan_info->plan.two.regulatory_domain, chan_info->plan.two.channel_plan_id, 0);
        BUG_ON(!params);
        break;
    default:
        BUG("unsupported channel plan: %d", chan_info->channel_plan);
    }

    ws_chan_mask_calc_reg(chan_mask, params, fhss_config->regional_regulation);
    if (chan_info->excluded_channel_ctrl == WS_EXC_CHAN_CTRL_RANGE)
        ws_neigh_excluded_mask_by_range(chan_mask, &chan_info->excluded_channels.range, params->chan_count);
    if (chan_info->excluded_channel_ctrl == WS_EXC_CHAN_CTRL_BITMASK)
        ws_neigh_excluded_mask_by_mask(chan_mask, &chan_info->excluded_channels.mask, params->chan_count);
}

void ws_neigh_us_update(const struct ws_fhss_config *fhss_config, struct ws_neigh_fhss *fhss_data,
                        const struct ws_generic_channel_info *chan_info,
                        uint8_t dwell_interval)
{
    fhss_data->uc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_CHAN_FUNC_FIXED) {
        memset(fhss_data->uc_channel_list, 0, sizeof(fhss_data->uc_channel_list));
        bitset(fhss_data->uc_channel_list, chan_info->function.zero.fixed_channel);
    } else {
        ws_neigh_set_chan_list(fhss_config, fhss_data->uc_channel_list, chan_info);
    }
    fhss_data->ffn.uc_dwell_interval_ms = dwell_interval;
}

bool ws_neigh_has_us(const struct ws_neigh_fhss *fhss_data)
{
    return memzcmp(fhss_data->uc_channel_list, WS_CHAN_MASK_LEN);
}

void ws_neigh_bt_update(struct ws_neigh_fhss *fhss_data, uint16_t slot_number, uint24_t interval_offset,
                        uint64_t tstamp_us)
{
    fhss_data->ffn.bt_rx_tstamp_us        = tstamp_us;
    fhss_data->ffn.bc_slot_number         = slot_number;
    fhss_data->ffn.bc_interval_offset_ms  = interval_offset;
}

void ws_neigh_bs_update(const struct ws_fhss_config *fhss_config, struct ws_neigh_fhss *fhss_data,
                        const struct ws_bs_ie *bs_ie)
{
    fhss_data->bc_chan_func = bs_ie->chan_plan.channel_function;
    if (bs_ie->chan_plan.channel_function == WS_CHAN_FUNC_FIXED) {
        memset(fhss_data->bc_channel_list, 0, sizeof(fhss_data->bc_channel_list));
        bitset(fhss_data->bc_channel_list, bs_ie->chan_plan.function.zero.fixed_channel);
    } else {
        ws_neigh_set_chan_list(fhss_config, fhss_data->bc_channel_list, &bs_ie->chan_plan);
    }
    fhss_data->ffn.bc_interval_ms = bs_ie->broadcast_interval;
    fhss_data->ffn.bc_dwell_interval_ms = bs_ie->dwell_interval;
    fhss_data->ffn.bsi = bs_ie->broadcast_schedule_identifier;
}

bool ws_neigh_has_bs(const struct ws_neigh_fhss *fhss_data)
{
    return memzcmp(fhss_data->bc_channel_list, WS_CHAN_MASK_LEN);
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

bool ws_neigh_lus_update(const struct ws_fhss_config *fhss_config,
                         struct ws_neigh_fhss *fhss_data,
                         const struct ws_generic_channel_info *chan_info,
                         uint24_t listen_interval_ms, const struct lto_info *lto_info)
{
    uint24_t adjusted_listening_interval;
    bool offset_adjusted = true;

    if (fhss_data->lfn.uc_listen_interval_ms != listen_interval_ms) {
        adjusted_listening_interval = ws_neigh_calc_lfn_adjusted_interval(fhss_config->lfn_bc_interval,
                                                                          fhss_data->lfn.uc_listen_interval_ms,
                                                                          lto_info->uc_interval_min_ms,
                                                                          lto_info->uc_interval_max_ms);
        if (adjusted_listening_interval && adjusted_listening_interval != listen_interval_ms)
            offset_adjusted = false;
    }

    fhss_data->lfn.uc_listen_interval_ms = listen_interval_ms;
    if (!chan_info)
        return offset_adjusted; // Support chan plan tag 255 (reuse previous schedule)
    fhss_data->uc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_CHAN_FUNC_FIXED) {
        memset(fhss_data->uc_channel_list, 0, sizeof(fhss_data->uc_channel_list));
        bitset(fhss_data->uc_channel_list, chan_info->function.zero.fixed_channel);
    } else {
        ws_neigh_set_chan_list(fhss_config, fhss_data->uc_channel_list, chan_info);
    }
    return offset_adjusted;
}

bool ws_neigh_duplicate_packet_check(struct ws_neigh *neigh, uint8_t mac_dsn, uint64_t rx_timestamp)
{
    if (neigh->last_dsn != mac_dsn) {
        // New packet always accepted
        neigh->last_dsn = mac_dsn;
        return true;
    }

    rx_timestamp -= neigh->fhss_data_unsecured.ffn.utt_rx_tstamp_us;
    rx_timestamp /= 1000000; //Convert to s

    //Compare only when last rx timestamp is less than 5 seconds
    if (rx_timestamp < 5) {
        //Packet is sent too fast filter it out
        return false;
    }

    return true;
}

int ws_neigh_lfn_count(struct ws_neigh_table *table)
{
    struct ws_neigh *neigh;
    int cnt = 0;

    SLIST_FOREACH(neigh, &table->neigh_list, link)
        if (neigh->node_role == WS_NR_ROLE_LFN)
            cnt++;
    return cnt;
}

void ws_neigh_trust(struct ws_neigh_table *table, struct ws_neigh *neigh)
{
    if (neigh->trusted_device)
        return;

    timer_start_rel(&table->timer_group, &neigh->timer, neigh->lifetime_s * 1000);
    neigh->trusted_device = true;
    TRACE(TR_NEIGH_15_4, "15.4 neighbor trusted %s / %ds", tr_eui64(neigh->eui64.u8), neigh->lifetime_s);
}

void ws_neigh_refresh(struct ws_neigh_table *table, struct ws_neigh *neigh, uint32_t lifetime_s)
{
    neigh->lifetime_s = lifetime_s;
    timer_start_rel(&table->timer_group, &neigh->timer, neigh->lifetime_s * 1000);
    TRACE(TR_NEIGH_15_4, "15.4 neighbor refresh %s / %ds", tr_eui64(neigh->eui64.u8), neigh->lifetime_s);
}

/*
 *   Wi-SUN FAN 1.1v08 3.1 Definitions
 * Exponentially Weighted Moving Average
 *
 *   Wi-SUN FAN 1.1v08 6.2.1 Constants
 * ETX_EWMA_SF    ETX EWMA Smoothing Factor   1/8
 * RSL_EWMA_SF    RSL EWMA Smoothing Factor   1/8
 */
float ws_neigh_ewma_next(float cur, float val, float smoothing_factor)
{
    // EWMA(0) = X(0)
    if (isnan(cur))
        return val;
    // EWMA(t) = S(X(t)) + (1-S)(EWMA(t-1))
    return smoothing_factor * (val - cur) + cur;
}

/*
 *   Wi-SUN FAN 1.1v08, 6.3.4.6.3.2.1 FFN Join State 1: Select PAN
 * PanCost = (PanRoutingCost / PRC_WEIGHT_FACTOR) + (PanSize / PS_WEIGHT_FACTOR)
 *
 * where,
 * PRC_WEIGHT_FACTOR = 256
 * PS_WEIGHT_FACTOR  = 64
 *
 * NOTE: PanCost precision is improved by avoiding truncation caused by
 * integer division.
 */
uint32_t ws_neigh_get_pan_cost(struct ws_neigh *neigh)
{
    return neigh->ie_pan.routing_cost + neigh->ie_pan.pan_size * 4;
}
