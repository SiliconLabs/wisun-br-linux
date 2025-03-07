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
#include "common/ws/ws_regdb.h"
#include "common/ws/ws_types.h"
#include "common/log.h"
#include "common/bits.h"
#include "common/endian.h"
#include "common/string_extra.h"
#include "common/ns_list.h"
#include "common/ieee802154_ie.h"
#include "common/memutils.h"
#include "common/iobuf.h"
#include "common/mathutils.h"
#include "common/sl_ws.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ws.h"

#include "ws_ie.h"

// Wi-SUN FAN 1.1v07 - 6.2.3.1.6.1 Link Metrics
#define WS_RSL_NORMALIZE_OFFSET 174

// Wi-SUN FAN 1.1v07 - 6.3.2.3.2.1.3 Field Definitions
#define WS_CLOCK_DRIFT_NOT_PROVIDED 255

static int ws_wh_header_base_write(struct iobuf_write *buf, uint8_t type)
{
    int offset;

    offset = ieee802154_ie_push_header(buf, IEEE802154_IE_ID_WH);
    iobuf_push_u8(buf, type);
    return offset;
}

static uint16_t ws_chan_plan_len(const struct ws_fhss_config *fhss_config)
{
    switch (fhss_config->chan_plan) {
    case 0:
        return 2; // reg domain, op class
    case 1:
        return 6; // ch0, chan spacing, chan count
    case 2:
        return 2; // reg domain, chan plan id
    default:
        BUG("Unsupported channel plan: %u", fhss_config->chan_plan);
    }
}

static uint16_t ws_chan_func_len(const struct ws_fhss_config *fhss_config, bool unicast)
{
    int fixed_channel = ws_chan_mask_get_fixed(unicast ? fhss_config->uc_chan_mask : fhss_config->bc_chan_mask);
    uint8_t chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;

    switch (chan_func) {
    case WS_CHAN_FUNC_FIXED:
        return 2;
    case WS_CHAN_FUNC_DH1CF:
    case WS_CHAN_FUNC_TR51CF:
        return 0;
    default:
        BUG("Unsupported channel function: %d", chan_func);
    }
}

static uint16_t ws_chan_excl_len(const struct ws_fhss_config *fhss_config, bool unicast)
{
    const uint8_t *chan_mask_custom = unicast ? fhss_config->uc_chan_mask : fhss_config->bc_chan_mask;
    uint8_t chan_mask_excl[WS_CHAN_MASK_LEN];
    uint8_t chan_mask_reg[WS_CHAN_MASK_LEN];

    BUG_ON(!fhss_config->chan_params);
    ws_chan_mask_calc_reg(chan_mask_reg, fhss_config->chan_params, fhss_config->regional_regulation);
    ws_chan_mask_calc_excl(chan_mask_excl, chan_mask_reg, chan_mask_custom);

    if (!memzcmp(chan_mask_excl, WS_CHAN_MASK_LEN))
        return 0;
    return MIN(ws_chan_mask_width(chan_mask_excl),
               1 + 4 * ws_chan_mask_ranges(chan_mask_excl));
}

uint16_t ws_wp_nested_hopping_schedule_length(const struct ws_fhss_config *fhss_config, bool unicast)
{
    uint16_t length = unicast ? 3 : 9;

    length++;
    length += ws_chan_plan_len(fhss_config);
    length += ws_chan_func_len(fhss_config, unicast);
    length += ws_chan_excl_len(fhss_config, unicast);
    return length;
}

void ws_wh_utt_write(struct iobuf_write *buf, uint8_t message_type)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_UTT);
    iobuf_push_u8(buf, message_type);
    iobuf_push_le24(buf, 0); // Unicast Fractional Sequence Interval (filled by MAC layer)
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_bt_write(struct iobuf_write *buf)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_BT);
    iobuf_push_le16(buf, 0); // Broadcast Slot Number (filled by MAC layer)
    iobuf_push_le24(buf, 0); // Broadcast Interval Offset (filled by MAC layer)
    ieee802154_ie_fill_len_header(buf, offset);
}


void ws_wh_fc_write(struct iobuf_write *buf, uint8_t tx, uint8_t rx)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_FC);
    iobuf_push_u8(buf, tx);
    iobuf_push_u8(buf, rx);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_rsl_write(struct iobuf_write *buf, uint8_t rsl)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_RSL);
    iobuf_push_u8(buf, rsl);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_ea_write(struct iobuf_write *buf, const struct eui64 *eui64)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_EA);
    iobuf_push_data(buf, eui64, 8);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lutt_write(struct iobuf_write *buf, uint8_t message_type)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LUTT);
    iobuf_push_u8(buf, message_type);
    iobuf_push_le16(buf, 0); // Unicast Slot Number (filled by MAC layer)
    iobuf_push_le24(buf, 0); // Unicast Interval Offset (filled by MAC layer)
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lus_write(struct iobuf_write *buf, struct ws_lus_ie *lus_ie)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LUS);
    iobuf_push_le24(buf, lus_ie->listen_interval);
    iobuf_push_u8(buf, lus_ie->channel_plan_tag);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_flus_write(struct iobuf_write *buf, uint24_t dwell_interval, uint8_t tag)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_FLUS);
    iobuf_push_u8(buf, dwell_interval);
    iobuf_push_u8(buf, tag);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lbt_write(struct iobuf_write *buf)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LBT);
    iobuf_push_le16(buf, 0); // LFN Broadcast Slot Number (filled by MAC layer)
    iobuf_push_le24(buf, 0); // LFN Broadcast Interval Offset (filled by MAC layer)
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lbs_write(struct iobuf_write *buf, uint24_t interval, uint16_t sched_id, uint8_t tag, uint8_t sync_period)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LBS);
    iobuf_push_le24(buf, interval);
    iobuf_push_le16(buf, sched_id);
    iobuf_push_u8(buf, tag);
    iobuf_push_u8(buf, sync_period);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lbc_write(struct iobuf_write *buf, uint24_t interval, uint8_t sync_period)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LBC);
    iobuf_push_le24(buf, interval);
    iobuf_push_u8(buf, sync_period);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_nr_write(struct iobuf_write *buf, uint8_t node_role,
                    uint8_t clock_drift, uint8_t timing_accuracy,
                    uint24_t listen_interval_min, uint24_t listen_interval_max)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_NR);
    iobuf_push_u8(buf, FIELD_PREP(WS_MASK_NR_ID, node_role));
    iobuf_push_u8(buf, clock_drift);
    iobuf_push_u8(buf, timing_accuracy);
    if (node_role == WS_NR_ROLE_LFN) {
        iobuf_push_le24(buf, listen_interval_min);
        iobuf_push_le24(buf, listen_interval_max);
    }
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lnd_write(struct iobuf_write *buf, struct ws_lnd_ie *lnd_ie)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LND);
    iobuf_push_u8(buf, lnd_ie->response_threshold);
    iobuf_push_le24(buf, 0); // Response Delay
    iobuf_push_u8(buf, lnd_ie->discovery_slot_time);
    iobuf_push_u8(buf, lnd_ie->discovery_slots);
    iobuf_push_le16(buf, 0); // Discovery First Slot
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_lto_write(struct iobuf_write *buf, uint24_t req_offset, uint24_t adjusted_listening_interval)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_LTO);
    iobuf_push_le24(buf, req_offset);
    iobuf_push_le24(buf, adjusted_listening_interval);
    ieee802154_ie_fill_len_header(buf, offset);
}

void ws_wh_panid_write(struct iobuf_write *buf, uint16_t panid)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_PANID);
    iobuf_push_le16(buf, panid);
    ieee802154_ie_fill_len_header(buf, offset);
}

static int ws_wh_vendor_write(struct iobuf_write *buf, uint8_t vendor_id)
{
    int offset;

    offset = ws_wh_header_base_write(buf, WS_WHIE_VH);
    // FIXME: handle vendor ID encoded on more than a byte
    iobuf_push_u8(buf, vendor_id);
    return offset;
}

void ws_wh_sl_utt_write(struct iobuf_write *buf, uint8_t sl_frame_type)
{
    int offset = ws_wh_vendor_write(buf, WS_VIN_SILICON_LABS);

    iobuf_push_u8(buf, SL_WHIE_UTT);
    iobuf_push_u8(buf, sl_frame_type);
    iobuf_push_le24(buf, 0); // Unicast Fractional Sequence Interval (filled by MAC layer)
    ieee802154_ie_fill_len_header(buf, offset);
}

static void ws_wp_schedule_base_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config, bool unicast)
{
    int fixed_channel = ws_chan_mask_get_fixed(unicast ? fhss_config->uc_chan_mask : fhss_config->bc_chan_mask);
    const uint8_t *chan_mask_custom = unicast ? fhss_config->uc_chan_mask : fhss_config->bc_chan_mask;
    uint8_t func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;
    uint8_t chan_mask_excl[WS_CHAN_MASK_LEN];
    uint8_t chan_mask_reg[WS_CHAN_MASK_LEN];
    uint8_t tmp8 = 0;

    BUG_ON(!fhss_config->chan_params);
    ws_chan_mask_calc_reg(chan_mask_reg, fhss_config->chan_params, fhss_config->regional_regulation);
    ws_chan_mask_calc_excl(chan_mask_excl, chan_mask_reg, chan_mask_custom);

    tmp8 |= FIELD_PREP(WS_MASK_SCHEDULE_CHAN_PLAN, fhss_config->chan_plan);
    tmp8 |= FIELD_PREP(WS_MASK_SCHEDULE_CHAN_FUNC, func);

    if (!memzcmp(chan_mask_excl, WS_CHAN_MASK_LEN))
        tmp8 |= FIELD_PREP(WS_MASK_SCHEDULE_CHAN_EXCL, WS_EXC_CHAN_CTRL_NONE);
    else if (ws_chan_mask_width(chan_mask_excl) < 1 + 4 * ws_chan_mask_ranges(chan_mask_excl))
        tmp8 |= FIELD_PREP(WS_MASK_SCHEDULE_CHAN_EXCL, WS_EXC_CHAN_CTRL_BITMASK);
    else
        tmp8 |= FIELD_PREP(WS_MASK_SCHEDULE_CHAN_EXCL, WS_EXC_CHAN_CTRL_RANGE);

    iobuf_push_u8(buf, tmp8);
}

static void ws_wp_chan_plan_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config)
{
    BUG_ON(!fhss_config->chan_params);
    switch (fhss_config->chan_plan) {
    case 0:
        iobuf_push_u8(buf, fhss_config->chan_params->reg_domain);
        iobuf_push_u8(buf, fhss_config->chan_params->op_class);
        break;
    case 1:
        iobuf_push_le24(buf, fhss_config->chan_params->chan0_freq / 1000);
        iobuf_push_u8(buf, ws_regdb_chan_spacing_id(fhss_config->chan_params->chan_spacing));
        iobuf_push_le16(buf, fhss_config->chan_params->chan_count);
        break;
    case 2:
        iobuf_push_u8(buf, fhss_config->chan_params->reg_domain);
        iobuf_push_u8(buf, fhss_config->chan_params->chan_plan_id);
        break;
    default:
        BUG("Unsupported channel plan: %u", fhss_config->chan_plan);
    }
}

static void ws_wp_chan_func_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config, bool unicast)
{
    int fixed_channel = ws_chan_mask_get_fixed(unicast ? fhss_config->uc_chan_mask : fhss_config->bc_chan_mask);
    uint8_t chan_func = (fixed_channel < 0) ? WS_CHAN_FUNC_DH1CF : WS_CHAN_FUNC_FIXED;

    switch (chan_func) {
    case WS_CHAN_FUNC_FIXED:
        BUG_ON(fixed_channel < 0);
        iobuf_push_le16(buf, fixed_channel);
        break;
    case WS_CHAN_FUNC_DH1CF:
    case WS_CHAN_FUNC_TR51CF:
        break;
    default:
        BUG("Unsupported channel function: %d", chan_func);
    }
}

static void ws_wp_chan_excl_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config, bool unicast)
{
    const uint8_t *chan_mask_custom = unicast ? fhss_config->uc_chan_mask : fhss_config->bc_chan_mask;
    uint8_t chan_mask_excl[WS_CHAN_MASK_LEN];
    uint8_t chan_mask_reg[WS_CHAN_MASK_LEN];
    int mask_len, range_cnt;
    int range_start;

    BUG_ON(!fhss_config->chan_params);
    ws_chan_mask_calc_reg(chan_mask_reg, fhss_config->chan_params, fhss_config->regional_regulation);
    ws_chan_mask_calc_excl(chan_mask_excl, chan_mask_reg, chan_mask_custom);

    if (!memzcmp(chan_mask_excl, WS_CHAN_MASK_LEN))
        return;

    mask_len = ws_chan_mask_width(chan_mask_excl);
    range_cnt = ws_chan_mask_ranges(chan_mask_excl);

    if (mask_len < 1 + 4 * range_cnt) {
        iobuf_push_data(buf, chan_mask_excl, mask_len);
    } else {
        iobuf_push_u8(buf, range_cnt);
        range_start = -1;
        for (int i = 0; i < 8 * WS_CHAN_MASK_LEN; i++) {
            if (range_start < 0) {
                if (bittest(chan_mask_excl, i))
                    range_start = i;
            } else {
                if (!bittest(chan_mask_excl, i)) {
                    iobuf_push_le16(buf, range_start);
                    iobuf_push_le16(buf, i - 1);
                    range_start = -1;
                }
            }
        }
        if (range_start >= 0) {
            iobuf_push_le16(buf, range_start);
            iobuf_push_le16(buf, WS_CHAN_MASK_LEN - 1);
        }
    }
}

static void ws_wp_schedule_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config, bool unicast)
{
    ws_wp_schedule_base_write(buf, fhss_config, unicast);
    ws_wp_chan_plan_write(buf, fhss_config);
    ws_wp_chan_func_write(buf, fhss_config, unicast);
    ws_wp_chan_excl_write(buf, fhss_config, unicast);
}

void ws_wp_nested_us_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_US, true);
    iobuf_push_u8(buf, fhss_config->uc_dwell_interval);
    iobuf_push_u8(buf, WS_CLOCK_DRIFT_NOT_PROVIDED);
    iobuf_push_u8(buf, 0); // TODO: timing accuracy
    ws_wp_schedule_write(buf, fhss_config, true);
    ieee802154_ie_fill_len_nested(buf, offset, true);
}

void ws_wp_nested_bs_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_BS, true);
    iobuf_push_le32(buf, fhss_config->bc_interval);
    iobuf_push_le16(buf, fhss_config->bsi);
    iobuf_push_u8(buf, fhss_config->bc_dwell_interval);
    iobuf_push_u8(buf, WS_CLOCK_DRIFT_NOT_PROVIDED);
    iobuf_push_u8(buf, 0); // TODO: timing accuracy
    ws_wp_schedule_write(buf, fhss_config, false);
    ieee802154_ie_fill_len_nested(buf, offset, true);
}

void ws_wp_nested_pan_write(struct iobuf_write *buf, uint16_t pan_size, uint16_t routing_cost,
                            uint8_t use_parent_bs_ie, uint8_t routing_method,
                            uint8_t lfn_window_style, uint8_t tps_version)
{
    uint8_t tmp8;
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_PAN, false);
    iobuf_push_le16(buf, pan_size);
    iobuf_push_le16(buf, routing_cost);
    tmp8 = 0;
    tmp8 |= FIELD_PREP(WS_MASK_PAN_PARENT_BS, use_parent_bs_ie);
    tmp8 |= FIELD_PREP(WS_MASK_PAN_ROUTING,   routing_method);
    tmp8 |= FIELD_PREP(WS_MASK_PAN_LFN_STYLE, lfn_window_style);
    tmp8 |= FIELD_PREP(WS_MASK_PAN_TPS, tps_version);
    iobuf_push_u8(buf, tmp8);
    ieee802154_ie_fill_len_nested(buf, offset, false);
}


void ws_wp_nested_netname_write(struct iobuf_write *buf,
                                const char *netname)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_NETNAME, false);
    iobuf_push_data(buf, netname, strlen(netname));
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

void ws_wp_nested_panver_write(struct iobuf_write *buf, uint16_t pan_version)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_PANVER, false);
    iobuf_push_le16(buf, pan_version);
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

void ws_wp_nested_gtkhash_write(struct iobuf_write *buf,
                                const uint8_t gtkhash[4][8])
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_GTKHASH, false);
    for (int i = 0; i < 4; i++)
        iobuf_push_data(buf, gtkhash[i], 8);
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

void ws_wp_nested_pom_write(struct iobuf_write *buf,
                            const uint8_t phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) + 1],
                            bool mdr_cmd_capable)
{
    int offset_bitfield;
    uint8_t bitfield;
    int offset;
    int i;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_POM, false);
    offset_bitfield = buf->len;
    iobuf_push_u8(buf, 0); // Filled after
    for (i = 0; phy_op_modes[i]; i++)
        iobuf_push_u8(buf, phy_op_modes[i]);
    bitfield = 0;
    bitfield |= FIELD_PREP(WS_MASK_POM_COUNT, i);
    bitfield |= FIELD_PREP(WS_MASK_POM_MDR, mdr_cmd_capable);
    buf->data[offset_bitfield] = bitfield;
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

void ws_wp_nested_lfnver_write(struct iobuf_write *buf, uint16_t version)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_LFNVER, false);
    iobuf_push_le16(buf, version);
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

void ws_wp_nested_lgtkhash_write(struct iobuf_write *buf,
                                 const uint8_t lgtkhash[3][8],
                                 uint8_t active_lgtk_index)
{
    uint8_t tmp8;
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_LGTKHASH, false);
    tmp8 = 0;
    tmp8 |= FIELD_PREP(WS_MASK_LGTKHASH_LGTK0, !!memzcmp(lgtkhash[0], 8));
    tmp8 |= FIELD_PREP(WS_MASK_LGTKHASH_LGTK1, !!memzcmp(lgtkhash[1], 8));
    tmp8 |= FIELD_PREP(WS_MASK_LGTKHASH_LGTK2, !!memzcmp(lgtkhash[2], 8));
    tmp8 |= FIELD_PREP(WS_MASK_LGTKHASH_INDEX, active_lgtk_index);
    iobuf_push_u8(buf, tmp8);
    for (int i = 0; i < 3; i++)
        if (memzcmp(lgtkhash[i], 8))
            iobuf_push_data(buf, lgtkhash[i], 8);
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

void ws_wp_nested_lcp_write(struct iobuf_write *buf, uint8_t tag,
                            const struct ws_fhss_config *fhss_config)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_LCP, true);
    iobuf_push_u8(buf, tag);
    ws_wp_schedule_write(buf, fhss_config, true); // Write unicast schedule
    ieee802154_ie_fill_len_nested(buf, offset, true);
}

void ws_wp_nested_lbats_write(struct iobuf_write *buf, struct ws_lbats_ie *lbats_ie)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_LBATS, false);
    iobuf_push_u8(buf, lbats_ie->additional_transmissions);
    iobuf_push_le16(buf, lbats_ie->next_transmit_delay);
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

/*
 *   Wi-SUN FAN 1.1v09 6.3.2.3.2.12 Join Metrics Information Element (JM-IE)
 * The Metric Length field MUST be set to indicate the length of the Metric
 * Data field, where:
 * 1. 0 indicates the Metric Data field is 0 octets in length.
 * 2. 1 indicates the Metric Data field is 1 octets in length.
 * 3. 2 indicates the Metric Data field is 2 octets in length.
 * 4. 3 indicates the Metric Data field is 4 octets in length.
 */
static uint8_t ws_wp_nested_jm_get_metric_len(uint8_t metric_len)
{
    static const int jm_len_conversion[] = { 0, 1, 2, 4 };

    BUG_ON(metric_len > ARRAY_SIZE(jm_len_conversion));
    return jm_len_conversion[metric_len];
}

void ws_wp_nested_jm_write(struct iobuf_write *buf, const struct ws_jm_ie *jm)
{
    int offset;

    offset = ieee802154_ie_push_nested(buf, WS_WPIE_JM, false);
    iobuf_push_u8(buf, jm->version);
    for (const struct ws_jm *metric = jm->metrics; metric->hdr; metric++) {
        iobuf_push_u8(buf, metric->hdr);
        iobuf_push_data(buf, metric->data, ws_wp_nested_jm_get_metric_len(FIELD_GET(WS_MASK_JM_LEN, metric->hdr)));
    }
    ieee802154_ie_fill_len_nested(buf, offset, false);
}

static void ws_wh_find_subid(const uint8_t *data, uint16_t length, uint8_t subid, struct iobuf_read *wh_content)
{
    const uint8_t *end = data + length;

    do {
        ieee802154_ie_find_header(data, length, IEEE802154_IE_ID_WH, wh_content);
        if (iobuf_pop_u8(wh_content) == subid)
            return;
        if (wh_content->err)
            return;
        length -= wh_content->data + wh_content->data_size - data;
        data = wh_content->data + wh_content->data_size;
    } while (data < end);
    wh_content->err = true;
}

static void ws_wh_find_sl_subid(const uint8_t *data, uint16_t length, uint8_t subid, struct iobuf_read *wh_content)
{
    const uint8_t *end = data + length;

    do {
        ieee802154_ie_find_header(data, length, IEEE802154_IE_ID_WH, wh_content);
        if (iobuf_pop_u8(wh_content) == WS_WHIE_VH && iobuf_pop_u8(wh_content) == WS_VIN_SILICON_LABS &&
            iobuf_pop_u8(wh_content) == subid)
            return;
        if (wh_content->err)
            return;
        length -= wh_content->data + wh_content->data_size - data;
        data = wh_content->data + wh_content->data_size;
    } while (data < end);
    wh_content->err = true;
}

bool ws_wh_utt_read(const uint8_t *data, uint16_t length, struct ws_utt_ie *utt_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_UTT, &ie_buf);
    utt_ie->message_type = iobuf_pop_u8(&ie_buf);
    utt_ie->ufsi         = iobuf_pop_le24(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_sl_utt_read(const uint8_t *data, uint16_t length, struct ws_utt_ie *utt_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_sl_subid(data, length, SL_WHIE_UTT, &ie_buf);
    utt_ie->message_type = iobuf_pop_u8(&ie_buf);
    utt_ie->ufsi         = iobuf_pop_le24(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_bt_read(const uint8_t *data, uint16_t length, struct ws_bt_ie *bt_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_BT, &ie_buf);
    bt_ie->broadcast_slot_number     = iobuf_pop_le16(&ie_buf);
    bt_ie->broadcast_interval_offset = iobuf_pop_le16(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_fc_read(const uint8_t *data, uint16_t length, struct ws_fc_ie *fc_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_FC, &ie_buf);
    fc_ie->tx_flow_ctrl = iobuf_pop_u8(&ie_buf);
    fc_ie->rx_flow_ctrl = iobuf_pop_u8(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_rsl_read(const uint8_t *data, uint16_t length, int *rsl)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_RSL, &ie_buf);
    // Wi-SUN FAN 1.1v07 - 6.3.2.3.1.4 Received Signal Level Information Element
    // The RSL field MUST be set to the 8 bit unsigned value (units of dB)
    // calculated as specified in section 6.2.3.1.6.1.
    *rsl = iobuf_pop_u8(&ie_buf) - WS_RSL_NORMALIZE_OFFSET;
    return !ie_buf.err;
}

bool ws_wh_ea_read(const uint8_t *data, uint16_t length, uint8_t eui64[8])
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_EA, &ie_buf);
    iobuf_pop_data(&ie_buf, eui64, 8);
    return !ie_buf.err;
}

bool ws_wh_lutt_read(const uint8_t *data, uint16_t length, struct ws_lutt_ie *lutt_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LUTT, &ie_buf);
    lutt_ie->message_type    = iobuf_pop_u8(&ie_buf);
    lutt_ie->slot_number     = iobuf_pop_le16(&ie_buf);
    lutt_ie->interval_offset = iobuf_pop_le24(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_lus_read(const uint8_t *data, uint16_t length, struct ws_lus_ie *lus_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LUS, &ie_buf);
    lus_ie->listen_interval  = iobuf_pop_le24(&ie_buf);
    lus_ie->channel_plan_tag = iobuf_pop_u8(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_flus_read(const uint8_t *data, uint16_t length, struct ws_flus_ie *flus_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_FLUS, &ie_buf);
    flus_ie->dwell_interval   = iobuf_pop_u8(&ie_buf);
    flus_ie->channel_plan_tag = iobuf_pop_u8(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_lbt_read(const uint8_t *data, uint16_t length, struct ws_lbt_ie *lbt_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LBT, &ie_buf);
    lbt_ie->slot_number     = iobuf_pop_le16(&ie_buf);
    lbt_ie->interval_offset = iobuf_pop_le24(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_lbs_read(const uint8_t *data, uint16_t length, struct ws_lbs_ie *lbs_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LBS, &ie_buf);
    lbs_ie->broadcast_interval     = iobuf_pop_le24(&ie_buf);
    lbs_ie->broadcast_scheduler_id = iobuf_pop_le16(&ie_buf);
    lbs_ie->channel_plan_tag       = iobuf_pop_u8(&ie_buf);
    lbs_ie->broadcast_sync_period  = iobuf_pop_u8(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_nr_read(const uint8_t *data, uint16_t length, struct ws_nr_ie *nr_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_NR, &ie_buf);
    nr_ie->node_role       = FIELD_GET(WS_MASK_NR_ID, iobuf_pop_u8(&ie_buf));
    nr_ie->clock_drift     = iobuf_pop_u8(&ie_buf);
    nr_ie->timing_accuracy = iobuf_pop_u8(&ie_buf);
    if (nr_ie->node_role == WS_NR_ROLE_LFN) {
        nr_ie->listen_interval_min = iobuf_pop_le24(&ie_buf);
        nr_ie->listen_interval_max = iobuf_pop_le24(&ie_buf);
    }
    return !ie_buf.err;
}

bool ws_wh_lnd_read(const uint8_t *data, uint16_t length, struct ws_lnd_ie *lnd_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LND, &ie_buf);
    lnd_ie->response_threshold   = iobuf_pop_u8(&ie_buf);
    lnd_ie->response_delay       = iobuf_pop_le24(&ie_buf);
    lnd_ie->discovery_slot_time  = iobuf_pop_u8(&ie_buf);
    lnd_ie->discovery_slots      = iobuf_pop_u8(&ie_buf);
    lnd_ie->discovery_first_slot = iobuf_pop_le16(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_lto_read(const uint8_t *data, uint16_t length, struct ws_lto_ie *lto_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LTO, &ie_buf);
    lto_ie->offset                      = iobuf_pop_le24(&ie_buf);
    lto_ie->adjusted_listening_interval = iobuf_pop_le24(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_panid_read(const uint8_t *data, uint16_t length, struct ws_panid_ie *panid_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_PANID, &ie_buf);
    panid_ie->panid = iobuf_pop_le16(&ie_buf);
    return !ie_buf.err;
}

bool ws_wh_lbc_read(const uint8_t *data, uint16_t length, struct ws_lbc_ie *lbc_ie)
{
    struct iobuf_read ie_buf;

    ws_wh_find_subid(data, length, WS_WHIE_LBC, &ie_buf);
    lbc_ie->lfn_broadcast_interval = iobuf_pop_le24(&ie_buf);
    lbc_ie->broadcast_sync_period  = iobuf_pop_u8(&ie_buf);
    return !ie_buf.err;
}

static void ws_channel_plan_read(struct iobuf_read *ie_buf, struct ws_generic_channel_info *chan_info)
{
    switch (chan_info->channel_plan) {
    case 0:
        chan_info->plan.zero.regulatory_domain = iobuf_pop_u8(ie_buf);
        chan_info->plan.zero.operating_class   = iobuf_pop_u8(ie_buf);
        break;
    case 1:
        chan_info->plan.one.ch0               = iobuf_pop_le24(ie_buf);
        chan_info->plan.one.channel_spacing   = iobuf_pop_u8(ie_buf);
        chan_info->plan.one.number_of_channel = iobuf_pop_le16(ie_buf);
        break;
    case 2:
        chan_info->plan.two.regulatory_domain = iobuf_pop_u8(ie_buf);
        chan_info->plan.two.channel_plan_id   = iobuf_pop_u8(ie_buf);
        break;
    default:
        ie_buf->err = true;
        break;
    }
}

static void ws_channel_function_read(struct iobuf_read *ie_buf, struct ws_generic_channel_info *chan_info)
{
    union ws_channel_function *func = &chan_info->function;

    switch (chan_info->channel_function) {
    case 0:
        func->zero.fixed_channel = iobuf_pop_le16(ie_buf);
        break;
    case 1:
    case 2:
        break;
    case 3:
        func->three.channel_hop_count = iobuf_pop_u8(ie_buf);
        func->three.channel_list = iobuf_pop_data_ptr(ie_buf, func->three.channel_hop_count);
        break;
    default:
        ie_buf->err = true;
        break;
    }
}

static void ws_channel_excluded_read(struct iobuf_read *ie_buf, struct ws_generic_channel_info *chan_info)
{
    union ws_excluded_channel *exc_chan = &chan_info->excluded_channels;

    switch (chan_info->excluded_channel_ctrl) {
    case WS_EXC_CHAN_CTRL_NONE:
        break;
    case WS_EXC_CHAN_CTRL_RANGE:
        exc_chan->range.number_of_range = iobuf_pop_u8(ie_buf);
        exc_chan->range.range_start = iobuf_pop_data_ptr(ie_buf, 4 * exc_chan->range.number_of_range);
        break;
    case WS_EXC_CHAN_CTRL_BITMASK:
        if (chan_info->channel_plan == 1)
            exc_chan->mask.mask_len_inline = roundup(chan_info->plan.one.number_of_channel, 8) / 8;
        else
            exc_chan->mask.mask_len_inline = iobuf_remaining_size(ie_buf);
        exc_chan->mask.channel_mask = iobuf_pop_data_ptr(ie_buf, exc_chan->mask.mask_len_inline);
        break;
    default:
        ie_buf->err = true;
        break;
    }
}

bool ws_wp_nested_us_read(const uint8_t *data, uint16_t length, struct ws_us_ie *us_ie)
{
    struct iobuf_read ie_buf;
    uint8_t tmp8;

    ieee802154_ie_find_nested(data, length, WS_WPIE_US, &ie_buf, true);
    us_ie->dwell_interval  = iobuf_pop_u8(&ie_buf);
    us_ie->clock_drift     = iobuf_pop_u8(&ie_buf);
    us_ie->timing_accuracy = iobuf_pop_u8(&ie_buf);
    tmp8 = iobuf_pop_u8(&ie_buf);
    us_ie->chan_plan.channel_plan          = FIELD_GET(WS_MASK_SCHEDULE_CHAN_PLAN,     tmp8);
    us_ie->chan_plan.channel_function      = FIELD_GET(WS_MASK_SCHEDULE_CHAN_FUNC,     tmp8);
    us_ie->chan_plan.excluded_channel_ctrl = FIELD_GET(WS_MASK_SCHEDULE_CHAN_EXCL, tmp8);
    ws_channel_plan_read(&ie_buf, &us_ie->chan_plan);
    ws_channel_function_read(&ie_buf, &us_ie->chan_plan);
    ws_channel_excluded_read(&ie_buf, &us_ie->chan_plan);
    return !ie_buf.err;
}

bool ws_wp_nested_bs_read(const uint8_t *data, uint16_t length, struct ws_bs_ie *bs_ie)
{
    struct iobuf_read ie_buf;
    uint8_t tmp8;

    ieee802154_ie_find_nested(data, length, WS_WPIE_BS, &ie_buf, true);
    bs_ie->broadcast_interval            = iobuf_pop_le32(&ie_buf);
    bs_ie->broadcast_schedule_identifier = iobuf_pop_le16(&ie_buf);
    bs_ie->dwell_interval                = iobuf_pop_u8(&ie_buf);
    bs_ie->clock_drift                   = iobuf_pop_u8(&ie_buf);
    bs_ie->timing_accuracy               = iobuf_pop_u8(&ie_buf);
    tmp8 = iobuf_pop_u8(&ie_buf);
    bs_ie->chan_plan.channel_plan          = FIELD_GET(WS_MASK_SCHEDULE_CHAN_PLAN, tmp8);
    bs_ie->chan_plan.channel_function      = FIELD_GET(WS_MASK_SCHEDULE_CHAN_FUNC, tmp8);
    bs_ie->chan_plan.excluded_channel_ctrl = FIELD_GET(WS_MASK_SCHEDULE_CHAN_EXCL, tmp8);
    ws_channel_plan_read(&ie_buf, &bs_ie->chan_plan);
    ws_channel_function_read(&ie_buf, &bs_ie->chan_plan);
    ws_channel_excluded_read(&ie_buf, &bs_ie->chan_plan);
    return !ie_buf.err;
}

bool ws_wp_nested_pan_read(const uint8_t *data, uint16_t length, struct ws_pan_ie *pan_ie)
{
    struct iobuf_read ie_buf;
    uint8_t tmp8;

    ieee802154_ie_find_nested(data, length, WS_WPIE_PAN, &ie_buf, false);
    pan_ie->pan_size = iobuf_pop_le16(&ie_buf);
    pan_ie->routing_cost = iobuf_pop_le16(&ie_buf);
    tmp8 = iobuf_pop_u8(&ie_buf);
    pan_ie->use_parent_bs_ie = FIELD_GET(WS_MASK_PAN_PARENT_BS, tmp8);
    pan_ie->routing_method   = FIELD_GET(WS_MASK_PAN_ROUTING,   tmp8);
    pan_ie->lfn_window_style = FIELD_GET(WS_MASK_PAN_LFN_STYLE, tmp8);
    pan_ie->fan_tps_version  = FIELD_GET(WS_MASK_PAN_TPS,       tmp8);
    return !ie_buf.err;
}

bool ws_wp_nested_panver_read(const uint8_t *data, uint16_t length, uint16_t *pan_version)
{
    struct iobuf_read ie_buf;

    ieee802154_ie_find_nested(data, length, WS_WPIE_PANVER, &ie_buf, false);
    *pan_version = iobuf_pop_le16(&ie_buf);
    return !ie_buf.err;
}

bool ws_wp_nested_gtkhash_read(const uint8_t *data, uint16_t length, uint8_t gtkhash[4][8])
{
    struct iobuf_read ie_buf;

    ieee802154_ie_find_nested(data, length, WS_WPIE_GTKHASH, &ie_buf, false);
    iobuf_pop_data(&ie_buf, (uint8_t *)gtkhash, 4 * 8);
    return !ie_buf.err;
}

bool ws_wp_nested_netname_read(const uint8_t *data, uint16_t length, struct ws_netname_ie *netname)
{
    struct iobuf_read ie_buf;

    ieee802154_ie_find_nested(data, length, WS_WPIE_NETNAME, &ie_buf, false);
    if (iobuf_remaining_size(&ie_buf) > WS_NETNAME_LEN)
        return false;
    memset(netname->netname, 0, sizeof(netname->netname));
    memcpy(netname->netname, iobuf_ptr(&ie_buf), iobuf_remaining_size(&ie_buf));
    return !ie_buf.err;
}

bool ws_wp_nested_pom_read(const uint8_t *data, uint16_t length, struct ws_pom_ie *pom_ie)
{
    struct iobuf_read ie_buf;
    uint8_t tmp8;

    ieee802154_ie_find_nested(data, length, WS_WPIE_POM, &ie_buf, false);
    tmp8 = iobuf_pop_u8(&ie_buf);
    pom_ie->phy_op_mode_number  = FIELD_GET(WS_MASK_POM_COUNT, tmp8);
    pom_ie->mdr_command_capable = FIELD_GET(WS_MASK_POM_MDR,   tmp8);
    iobuf_pop_data(&ie_buf, pom_ie->phy_op_mode_id, pom_ie->phy_op_mode_number);
    return !ie_buf.err;
}

bool ws_wp_nested_lfnver_read(const uint8_t *data, uint16_t length, struct ws_lfnver_ie *ws_lfnver)
{
    struct iobuf_read ie_buf;

    ieee802154_ie_find_nested(data, length, WS_WPIE_LFNVER, &ie_buf, false);
    ws_lfnver->lfn_version = iobuf_pop_le16(&ie_buf);
    return !ie_buf.err;
}

bool ws_wp_nested_lgtkhash_read(const uint8_t *data, uint16_t length, uint8_t lgtkhash[3][8], unsigned *active_lgtk_index)
{
    struct iobuf_read ie_buf;
    unsigned valid_hashs;

    ieee802154_ie_find_nested(data, length, WS_WPIE_LGTKHASH, &ie_buf, false);
    valid_hashs = FIELD_GET(WS_MASK_LGTKHASH_LGTK0 | WS_MASK_LGTKHASH_LGTK1 | WS_MASK_LGTKHASH_LGTK2, *data);
    *active_lgtk_index = FIELD_GET(WS_MASK_LGTKHASH_INDEX, *data);
    for (int i = 0; i < 3; i++) {
        if (valid_hashs & BIT(i))
            iobuf_pop_data(&ie_buf, lgtkhash[i], 8);
        else
            memset(lgtkhash[i], 0, 8);
    }
    return !ie_buf.err;
}

bool ws_wp_nested_lbats_read(const uint8_t *data, uint16_t length, struct ws_lbats_ie *lbats_ie)
{
    struct iobuf_read ie_buf;

    ieee802154_ie_find_nested(data, length, WS_WPIE_LBATS, &ie_buf, true);
    lbats_ie->additional_transmissions = iobuf_pop_u8(&ie_buf);
    lbats_ie->next_transmit_delay      = iobuf_pop_le16(&ie_buf);
    return !ie_buf.err;
}

// LCP-IE can appear several times with different tag values
static void ws_wp_nested_lcp_find_tag(const uint8_t *data, uint16_t length, uint8_t tag, struct iobuf_read *ie_content)
{
    const uint8_t *end = data + length;

    do {
        ieee802154_ie_find_nested(data, length, WS_WPIE_LCP, ie_content, true);
        if (iobuf_pop_u8(ie_content) == tag) {
            ie_content->cnt = 0;
            return;
        }
        if (ie_content->err)
            return;
        length -= ie_content->data + ie_content->data_size - data;
        data = ie_content->data + ie_content->data_size;
    } while (data < end);
    ie_content->err = true;
}

bool ws_wp_nested_lcp_read(const uint8_t *data, uint16_t length, uint8_t tag, struct ws_lcp_ie *ws_lcp)
{
    struct iobuf_read ie_buf;
    uint8_t tmp8;

    ws_wp_nested_lcp_find_tag(data, length, tag, &ie_buf);
    ws_lcp->lfn_channel_plan_tag = iobuf_pop_u8(&ie_buf);
    tmp8 = iobuf_pop_u8(&ie_buf);
    ws_lcp->chan_plan.channel_plan          = FIELD_GET(WS_MASK_SCHEDULE_CHAN_PLAN, tmp8);
    ws_lcp->chan_plan.channel_function      = FIELD_GET(WS_MASK_SCHEDULE_CHAN_FUNC, tmp8);
    ws_lcp->chan_plan.excluded_channel_ctrl = FIELD_GET(WS_MASK_SCHEDULE_CHAN_EXCL, tmp8);
    ws_channel_plan_read(&ie_buf, &ws_lcp->chan_plan);
    ws_channel_function_read(&ie_buf, &ws_lcp->chan_plan);
    ws_channel_excluded_read(&ie_buf, &ws_lcp->chan_plan);
    return !ie_buf.err;
}

struct ws_jm *ws_wp_nested_jm_get_metric(struct ws_jm_ie *jm, uint8_t metric_id)
{
    for (struct ws_jm *metric = jm->metrics; metric->hdr; metric++)
        if (FIELD_GET(WS_MASK_JM_ID, metric->hdr) == metric_id)
            return metric;
    return NULL;
}

bool ws_wp_nested_jm_read(const uint8_t *data, uint16_t length, struct ws_jm_ie *jm)
{
    struct iobuf_read ie_buf;
    uint8_t hdr;
    int i = 0;

    ieee802154_ie_find_nested(data, length, WS_WPIE_JM, &ie_buf, false);
    jm->version = iobuf_pop_u8(&ie_buf);
    while (iobuf_remaining_size(&ie_buf) && i < ARRAY_SIZE(jm->metrics) - 1) {
        hdr = iobuf_pop_u8(&ie_buf);
        if (ie_buf.err)
            return false;
        jm->metrics[i].hdr = hdr;
        iobuf_pop_data(&ie_buf, jm->metrics[i].data,
                       ws_wp_nested_jm_get_metric_len(FIELD_GET(WS_MASK_JM_LEN, hdr)));
        i++;
    }
    if (iobuf_remaining_size(&ie_buf))
        return false;
    return !ie_buf.err;
}
