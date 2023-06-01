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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "common/bits.h"
#include "common/endian.h"
#include "common/utils.h"
#include "common/ws_regdb.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/version.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/fhss_config.h"
#include "stack/ws_management_api.h"
#include "stack/mac/mac_api.h"

#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/rcp_api.h"
#include "6lowpan/ws/ws_config.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_ie_lib.h"

#include "6lowpan/ws/ws_neighbor_class.h"

#define TRACE_GROUP "wsne"

bool ws_neighbor_class_alloc(ws_neighbor_class_t *class_data, uint8_t list_size)
{

    class_data->neigh_info_list = malloc(sizeof(ws_neighbor_class_entry_t) * list_size);
    if (!class_data->neigh_info_list) {
        return false;
    }

    class_data->list_size = list_size;
    ws_neighbor_class_entry_t *list_ptr = class_data->neigh_info_list;
    for (uint8_t i = 0; i < list_size; i++) {
        memset(list_ptr, 0, sizeof(ws_neighbor_class_entry_t));
        list_ptr->rsl_in = RSL_UNITITIALIZED;
        list_ptr->rsl_out = RSL_UNITITIALIZED;
        list_ptr++;
    }
    return true;
}


void ws_neighbor_class_dealloc(ws_neighbor_class_t *class_data)
{
    free(class_data->neigh_info_list);
    class_data->neigh_info_list = NULL;
    class_data->list_size = 0;
}

ws_neighbor_class_entry_t *ws_neighbor_class_entry_get(ws_neighbor_class_t *class_data, uint8_t attribute_index)
{
    if (!class_data->neigh_info_list || attribute_index >= class_data->list_size) {
        return NULL;
    }

    ws_neighbor_class_entry_t *entry = class_data->neigh_info_list + attribute_index;
    return entry;
}

uint8_t ws_neighbor_class_entry_index_get(ws_neighbor_class_t *class_data, ws_neighbor_class_entry_t *entry)
{
    if (!class_data->neigh_info_list) {
        return 0xff;
    }
    return entry - class_data->neigh_info_list;
}

void ws_neighbor_class_entry_remove(ws_neighbor_class_t *class_data, uint8_t attribute_index)
{
    ws_neighbor_class_entry_t *entry = ws_neighbor_class_entry_get(class_data, attribute_index);
    if (entry) {
        memset(entry, 0, sizeof(ws_neighbor_class_entry_t));
        entry->rsl_in = RSL_UNITITIALIZED;
        entry->rsl_out = RSL_UNITITIALIZED;
    }
}

static int own_ceil(float value)
{
    int ivalue = (int)value;
    if (value == (float)ivalue) {
        return ivalue;
    }
    return ivalue + 1;
}

static void ws_neighbor_calculate_ufsi_drift(ws_neighbor_class_entry_t *ws_neighbor, uint24_t ufsi, uint32_t timestamp, const uint8_t address[8])
{
    if (ws_neighbor->fhss_data.ffn.utt_rx_tstamp_us && ws_neighbor->fhss_data.ffn.ufsi) {
        // No UFSI on fixed channel
        if (ws_neighbor->fhss_data.uc_chan_func == WS_FIXED_CHANNEL) {
            return;
        }
        uint32_t seq_length = 0x10000;
        if (ws_neighbor->fhss_data.uc_chan_func == WS_TR51CF) {
            seq_length = ws_neighbor->fhss_data.uc_chan_count;
        }
        uint32_t ufsi_prev_tmp = ws_neighbor->fhss_data.ffn.ufsi;
        uint32_t ufsi_cur_tmp = ufsi;
        if (ws_neighbor->fhss_data.uc_chan_func == WS_DH1CF) {
            if (ufsi_cur_tmp < ufsi_prev_tmp) {
                ufsi_cur_tmp += 0xffffff;
            }
        }
        // Convert 24-bit UFSI to real time before drift calculation
        uint32_t time_since_seq_start_prev_ms = own_ceil((float)((uint64_t)ufsi_prev_tmp * seq_length * ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms) / 0x1000000);
        uint32_t time_since_seq_start_cur_ms = own_ceil((float)((uint64_t)ufsi_cur_tmp * seq_length * ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms) / 0x1000000);
        uint32_t time_since_last_ufsi_us = timestamp - ws_neighbor->fhss_data.ffn.utt_rx_tstamp_us;

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

        uint32_t ufsi_diff_ms = time_since_seq_start_cur_ms - time_since_seq_start_prev_ms;
        if (time_since_seq_start_cur_ms < time_since_seq_start_prev_ms)
            // add ufsi sequence length
            ufsi_diff_ms += seq_length * ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms;

        int32_t ufsi_drift_ms = (int32_t)(time_since_last_ufsi_us / 1000 - ufsi_diff_ms);
        // Only trace if there is significant error
        if (ufsi_drift_ms < -5 || ufsi_drift_ms > 5) {
            tr_debug("UFSI updated: %s, drift: %"PRIi32"ms in %"PRIu32" seconds", tr_eui64(address), ufsi_drift_ms, time_since_last_ufsi_us / 1000000);
        }
    }
}

void ws_neighbor_class_ut_update(ws_neighbor_class_entry_t *neighbor, uint24_t ufsi,
                                 uint32_t tstamp_us, const uint8_t eui64[8])
{
    ws_neighbor_calculate_ufsi_drift(neighbor, ufsi, tstamp_us, eui64);

    if (neighbor->fhss_data.ffn.utt_rx_tstamp_us == tstamp_us &&
        neighbor->fhss_data.ffn.ufsi             == ufsi)
        return; // Save an update

    neighbor->fhss_data.ffn.utt_rx_tstamp_us = tstamp_us;
    neighbor->fhss_data.ffn.ufsi             = ufsi;
    clock_gettime(CLOCK_MONOTONIC, &neighbor->host_rx_timestamp);
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_set_fhss_neighbor(eui64, &neighbor->fhss_data);
}

// Irrelevant for border router
void ws_neighbor_class_bt_update(ws_neighbor_class_entry_t *neighbor, uint16_t slot_number,
                                 uint24_t interval_offset,uint32_t timestamp)
{
    neighbor->broadcast_timing_info_stored = true;
    neighbor->fhss_data.ffn.bt_rx_tstamp_us       = timestamp;
    neighbor->fhss_data.ffn.bc_slot               = slot_number;
    neighbor->fhss_data.ffn.bc_interval_offset_ms = interval_offset;
}

void ws_neighbor_class_lut_update(ws_neighbor_class_entry_t *neighbor,
                                  uint16_t slot_number, uint24_t interval_offset,
                                  uint32_t tstamp_us, const uint8_t eui64[8])
{
    neighbor->fhss_data.lfn.lutt_rx_tstamp_us     = tstamp_us;
    neighbor->fhss_data.lfn.uc_slot_number        = slot_number;
    neighbor->fhss_data.lfn.uc_interval_offset_ms = interval_offset;
}

void ws_neighbor_class_lnd_update(ws_neighbor_class_entry_t *neighbor, const struct ws_lnd_ie *ie_lnd, uint32_t tstamp_us)
{
    neighbor->fhss_data.lfn.lpa_response_delay_ms = ie_lnd->response_delay;
    neighbor->fhss_data.lfn.lpa_slot_duration_ms  = ie_lnd->discovery_slot_time;
    neighbor->fhss_data.lfn.lpa_slot_count        = ie_lnd->discovery_slots;
    neighbor->fhss_data.lfn.lpa_slot_first        = ie_lnd->discovery_first_slot;
    neighbor->fhss_data.lfn.lnd_rx_tstamp_us      = tstamp_us;
}

static void ws_neighbour_excluded_mask_by_range(ws_channel_mask_t *channel_info, const ws_excluded_channel_range_t *range_info, uint16_t number_of_channels)
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

static void ws_neighbour_excluded_mask_by_mask(ws_channel_mask_t *channel_info, const ws_excluded_channel_mask_t *mask_info, uint16_t number_of_channels)
{
    int nchan = MIN(number_of_channels, mask_info->mask_len_inline * 8);

    for (int i = 0; i < nchan; i++) {
        if (bittest(channel_info->channel_mask, i) && bitrtest(mask_info->channel_mask, i)) {
            bitclr(channel_info->channel_mask, i);
            channel_info->channel_count--;
        }
    }
}

static void ws_neighbor_set_chan_list(const struct net_if *net_if,
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
        ws_neighbour_excluded_mask_by_range(chan_list, &chan_info.excluded_channels.range, *chan_cnt);
        break;
    case WS_EXC_CHAN_CTRL_BITMASK:
        ws_common_generate_channel_list(net_if, chan_list->channel_mask, *chan_cnt,
                                        reg_domain, op_class, chan_plan_id);
        chan_list->channel_count = bitcnt(chan_list->channel_mask, *chan_cnt);
        ws_neighbour_excluded_mask_by_mask(chan_list, &chan_info.excluded_channels.mask, *chan_cnt);
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

void ws_neighbor_class_us_update(const struct net_if *net_if, ws_neighbor_class_entry_t *ws_neighbor,
                           const struct ws_generic_channel_info *chan_info,
                           uint8_t dwell_interval, const uint8_t eui64[8])
{
    ws_neighbor->fhss_data.uc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_FIXED_CHANNEL) {
        ws_neighbor->fhss_data.uc_chan_fixed = chan_info->function.zero.fixed_channel;
        ws_neighbor->fhss_data.uc_chan_count = 1;
    } else {
        ws_neighbor_set_chan_list(net_if, &ws_neighbor->fhss_data.uc_channel_list, chan_info,
                                  &ws_neighbor->fhss_data.uc_chan_count);
    }
    ws_neighbor->fhss_data.ffn.uc_dwell_interval_ms = dwell_interval;
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_set_fhss_neighbor(eui64, &ws_neighbor->fhss_data);
}

// Irrelevant for border router
void ws_neighbor_class_bs_update(const struct net_if *net_if, ws_neighbor_class_entry_t *ws_neighbor,
                                 const struct ws_generic_channel_info *chan_info,
                                 uint8_t dwell_interval, uint32_t interval, uint16_t bsi)
{
    uint16_t chan_cnt;

    ws_neighbor->broadcast_schedule_info_stored = true;
    ws_neighbor->fhss_data.bc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_FIXED_CHANNEL)
        ws_neighbor->fhss_data.bc_chan_fixed = chan_info->function.zero.fixed_channel;
    else
        ws_neighbor_set_chan_list(net_if, &ws_neighbor->fhss_data.bc_channel_list, chan_info, &chan_cnt);
    ws_neighbor->fhss_data.ffn.bc_dwell_interval_ms = dwell_interval;
    ws_neighbor->fhss_data.ffn.bc_interval_ms       = interval;
    ws_neighbor->fhss_data.ffn.bsi                  = bsi;
}

void ws_neighbor_class_lus_update(const struct net_if *net_if,
                                  ws_neighbor_class_entry_t *ws_neighbor,
                                  const struct ws_generic_channel_info *chan_info,
                                  uint24_t listen_interval_ms)
{
    ws_neighbor->fhss_data.lfn.uc_listen_interval_ms = listen_interval_ms;
    if (!chan_info)
        return; // Support chan plan tag 255 (reuse previous schedule)
    ws_neighbor->fhss_data.uc_chan_func = chan_info->channel_function;
    if (chan_info->channel_function == WS_FIXED_CHANNEL) {
        ws_neighbor->fhss_data.uc_chan_fixed = chan_info->function.zero.fixed_channel;
        ws_neighbor->fhss_data.uc_chan_count = 1;
    } else {
        ws_neighbor_set_chan_list(net_if, &ws_neighbor->fhss_data.uc_channel_list, chan_info,
                                  &ws_neighbor->fhss_data.uc_chan_count);
    }
}

uint8_t ws_neighbor_class_rsl_from_dbm_calculate(int8_t dbm_heard)
{
    /* RSL MUST be calculated as the received signal level relative to standard
     * thermal noise (290oK) at 1 Hz bandwidth or 174 dBm.
     * This provides a range of -174 (0) to +80 (254) dBm.
     */

    return dbm_heard + 174;
}

static void ws_neighbor_class_parent_set_analyze(ws_neighbor_class_entry_t *ws_neighbor)
{
    if (ws_neighbor->rsl_in == RSL_UNITITIALIZED ||
            ws_neighbor->rsl_out == RSL_UNITITIALIZED) {
        ws_neighbor->candidate_parent = false;
        return;
    }

    if (ws_neighbor_class_rsl_in_get(ws_neighbor) < (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD - CAND_PARENT_HYSTERISIS) &&
            ws_neighbor_class_rsl_out_get(ws_neighbor) < (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD - CAND_PARENT_HYSTERISIS)) {
        ws_neighbor->candidate_parent = false;
    }

    if (ws_neighbor_class_rsl_in_get(ws_neighbor) > (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERISIS) &&
            ws_neighbor_class_rsl_out_get(ws_neighbor) > (DEVICE_MIN_SENS + CAND_PARENT_THRESHOLD + CAND_PARENT_HYSTERISIS)) {
        ws_neighbor->candidate_parent = true;
    }
}

void ws_neighbor_class_rsl_in_calculate(ws_neighbor_class_entry_t *ws_neighbor, int8_t dbm_heard)
{
    uint8_t rsl = ws_neighbor_class_rsl_from_dbm_calculate(dbm_heard);
    if (ws_neighbor->rsl_in == RSL_UNITITIALIZED) {
        ws_neighbor->rsl_in = rsl << WS_RSL_SCALING;
    }
    ws_neighbor->rsl_in = ws_neighbor->rsl_in + rsl - (ws_neighbor->rsl_in >> WS_RSL_SCALING);
    ws_neighbor->rssi = dbm_heard;
    ws_neighbor_class_parent_set_analyze(ws_neighbor);
    return;
}

void ws_neighbor_class_rsl_out_calculate(ws_neighbor_class_entry_t *ws_neighbor, uint8_t rsl_reported)
{
    if (ws_neighbor->rsl_out == RSL_UNITITIALIZED) {
        ws_neighbor->rsl_out = rsl_reported << WS_RSL_SCALING;
    }
    ws_neighbor->rsl_out = ws_neighbor->rsl_out + rsl_reported - (ws_neighbor->rsl_out >> WS_RSL_SCALING);
    ws_neighbor_class_parent_set_analyze(ws_neighbor);
    return;
}


bool ws_neighbor_class_neighbor_duplicate_packet_check(ws_neighbor_class_entry_t *ws_neighbor, uint8_t mac_dsn, uint32_t rx_timestamp)
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
