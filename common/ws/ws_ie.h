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

#ifndef WS_IE_LIB_H_
#define WS_IE_LIB_H_
#include <stdint.h>
#include <stdbool.h>
#include "common/int24.h"
#include "common/specs/ws.h"

#include "common/bits.h"

struct eui64;
struct iobuf_write;
struct ws_fhss_config;
struct ws_phy_config;
struct ws_ie_custom_list;

struct ws_utt_ie {
    uint8_t message_type;
    uint24_t ufsi;            // Filled by MAC
};

struct ws_lutt_ie {
    uint8_t  message_type;
    uint16_t slot_number;     // Filled by MAC
    uint24_t interval_offset; // Filled by MAC
};

struct ws_lbt_ie {
    uint16_t slot_number;     // Filled by MAC
    uint24_t interval_offset; // Filled by MAC
};

struct ws_nr_ie {
    uint8_t node_role: 3;
    uint8_t reserved: 5;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    uint24_t listen_interval_min;
    uint24_t listen_interval_max;
};

struct ws_lus_ie {
    uint24_t listen_interval;
    uint8_t channel_plan_tag;
};

struct ws_flus_ie {
    uint8_t dwell_interval;
    uint8_t channel_plan_tag;
};

struct ws_lnd_ie {
    uint8_t response_threshold;
    uint24_t response_delay;       // Filled by MAC
    uint8_t discovery_slot_time;
    uint8_t discovery_slots;
    uint16_t discovery_first_slot; // Filled by MAC
};

struct ws_lto_ie {
    uint24_t offset;
    uint24_t adjusted_listening_interval;
};

struct ws_lbs_ie {
    uint24_t broadcast_interval;
    uint16_t broadcast_scheduler_id;
    uint8_t channel_plan_tag;
    uint8_t broadcast_sync_period;
};

struct ws_panid_ie {
    uint16_t        panid;
};

struct ws_lbc_ie {
    uint24_t lfn_broadcast_interval;
    uint8_t broadcast_sync_period;
};

struct ws_pom_ie {
    uint8_t phy_op_mode_number: 4;
    uint8_t mdr_command_capable: 1;
    uint8_t reserved: 3;
    uint8_t phy_op_mode_id[FIELD_MAX(WS_MASK_POM_COUNT)];
};

struct ws_bt_ie {
    uint16_t broadcast_slot_number;
    uint24_t broadcast_interval_offset;
};

struct ws_fc_ie {
    uint8_t tx_flow_ctrl;
    uint8_t rx_flow_ctrl;
};

struct ws_lfnver_ie {
    uint16_t lfn_version;
};

struct ws_lgtkhash_ie {
    unsigned active_lgtk_index: 2;
    uint8_t valid_hashs;
    uint8_t gtkhashs[8][4];
};

struct ws_lbats_ie {
    uint8_t additional_transmissions;
    uint16_t next_transmit_delay;
};

struct ws_pan_ie {
    uint16_t pan_size;
    uint16_t routing_cost;
    unsigned use_parent_bs_ie: 1;
    unsigned routing_method: 1;
    unsigned lfn_window_style: 1;
    unsigned reserved: 2;
    unsigned fan_tps_version: 3;
};

/*
 *   Wi-SUN FAN 1.1v09, 6.3.2.3.2.12 Join Metrics Information Element (JM-IE)
 * [...]
 * The List of Metrics field is a variable length list of JM-IE Metrics, which
 * MAY contain zero or up to 4 metrics.
 * [...]
 * The Metric Length field MUST be set to indicate the length of the Metric Data
 * field, where:
 * [...]
 * 4. 3 indicates the Metric Data field is 4 octets in length.
 */
struct ws_jm {
    uint8_t hdr;
    union {
        uint8_t plf;
        uint8_t data[4];
    };
};

struct ws_jm_ie {
    uint8_t version;
    struct ws_jm metrics[5]; // +1 for sentinel
};

struct ws_channel_plan_zero {
    uint8_t regulatory_domain;
    uint8_t operating_class;
};

struct ws_channel_plan_one {
    uint24_t ch0; // kHz
    unsigned channel_spacing: 4;
    uint16_t number_of_channel;
};

struct ws_channel_plan_two {
    uint8_t regulatory_domain;
    uint8_t channel_plan_id;
};

struct ws_channel_function_zero {
    uint16_t fixed_channel;
};

struct ws_channel_function_three {
    uint8_t channel_hop_count;
    const uint8_t *channel_list;
};

struct ws_excluded_channel_range {
    uint8_t number_of_range;
    const uint8_t *range_start;
};

struct ws_excluded_channel_mask {
    const uint8_t *channel_mask;
    uint8_t mask_len_inline;
};

struct ws_generic_channel_info {
    unsigned channel_plan: 3;
    unsigned channel_function: 3;
    unsigned excluded_channel_ctrl: 2;
    union ws_channel_plan {
        struct ws_channel_plan_zero zero;
        struct ws_channel_plan_one one;
        struct ws_channel_plan_two two;
    } plan;
    union ws_channel_function {
        struct ws_channel_function_zero zero;
        /* struct ws_channel_function_one not supported */
        /* struct ws_channel_function_two not supported */
        struct ws_channel_function_three three;
    } function;
    union ws_excluded_channel {
        struct ws_excluded_channel_range range;
        struct ws_excluded_channel_mask mask;
    } excluded_channels;
};

struct ws_lcp_ie {
    uint8_t lfn_channel_plan_tag;
    struct ws_generic_channel_info chan_plan;
};

struct ws_us_ie {
    uint8_t dwell_interval;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    struct ws_generic_channel_info chan_plan;
};

struct ws_bs_ie {
    uint32_t broadcast_interval;
    uint16_t broadcast_schedule_identifier;
    uint8_t dwell_interval;
    uint8_t clock_drift;
    uint8_t timing_accuracy;
    struct ws_generic_channel_info chan_plan;
};

// Wi-SUN FAN 1.1v08 6.3.2.3.2.4 Network Name Information Element (NETNAME-IE)
#define WS_NETNAME_LEN 32

struct ws_netname_ie {
    char netname[WS_NETNAME_LEN + 1];
};

/* WS_WH HEADER IE */
void   ws_wh_utt_write(struct iobuf_write *buf, uint8_t message_type);
void    ws_wh_bt_write(struct iobuf_write *buf);
void    ws_wh_fc_write(struct iobuf_write *buf, uint8_t tx, uint8_t rx);
void   ws_wh_rsl_write(struct iobuf_write *buf, uint8_t rsl);
void    ws_wh_ea_write(struct iobuf_write *buf, const struct eui64 *eui64);
/* Wi-SUN FAN 1.1 */
void  ws_wh_lutt_write(struct iobuf_write *buf, uint8_t message_type);
void   ws_wh_lus_write(struct iobuf_write *buf, struct ws_lus_ie *lus_ie);
void  ws_wh_flus_write(struct iobuf_write *buf, uint24_t dwell_interval, uint8_t tag);
void   ws_wh_lbt_write(struct iobuf_write *buf);
void   ws_wh_lbs_write(struct iobuf_write *buf, uint24_t interval, uint16_t sched_id, uint8_t tag, uint8_t sync_period);
void    ws_wh_nr_write(struct iobuf_write *buf, uint8_t node_role,
                       uint8_t clock_drift, uint8_t timing_accuracy,
                       uint24_t listen_interval_min, uint24_t listen_interval_max);
void   ws_wh_lnd_write(struct iobuf_write *buf, struct ws_lnd_ie *lnd_ie);
void   ws_wh_lto_write(struct iobuf_write *buf, uint24_t offset, uint24_t adjusted_listening_interval);
void ws_wh_panid_write(struct iobuf_write *buf, uint16_t panid);
void   ws_wh_lbc_write(struct iobuf_write *buf, uint24_t interval, uint8_t sync_period);

void ws_wh_sl_utt_write(struct iobuf_write *buf, uint8_t sl_frame_type);

bool ws_wh_utt_read(const uint8_t *data, uint16_t length, struct ws_utt_ie *utt_ie);
bool ws_wh_bt_read(const uint8_t *data, uint16_t length, struct ws_bt_ie *bt_ie);
bool ws_wh_fc_read(const uint8_t *data, uint16_t length, struct ws_fc_ie *fc_ie);
bool ws_wh_rsl_read(const uint8_t *data, uint16_t length, int *rsl);
bool ws_wh_ea_read(const uint8_t *data, uint16_t length, uint8_t eui64[8]);
/*Wi-SUN FAN 1.1 */
bool ws_wh_lutt_read(const uint8_t *data, uint16_t length, struct ws_lutt_ie *lutt_ie);
bool ws_wh_lus_read(const uint8_t *data, uint16_t length, struct ws_lus_ie *lus_ie);
bool ws_wh_flus_read(const uint8_t *data, uint16_t length, struct ws_flus_ie *flus_ie);
bool ws_wh_lbt_read(const uint8_t *data, uint16_t length, struct ws_lbt_ie *lbt_ie);
bool ws_wh_lbs_read(const uint8_t *data, uint16_t length, struct ws_lbs_ie *lbs_ie);
bool ws_wh_lbc_read(const uint8_t *data, uint16_t length, struct ws_lbc_ie *lbc_ie);
bool ws_wh_nr_read(const uint8_t *data, uint16_t length, struct ws_nr_ie *nr_ie);
bool ws_wh_lnd_read(const uint8_t *data, uint16_t length, struct ws_lnd_ie *lnd_ie);
bool ws_wh_lto_read(const uint8_t *data, uint16_t length, struct ws_lto_ie *lto_ie);
bool ws_wh_panid_read(const uint8_t *data, uint16_t length, struct ws_panid_ie *panid_ie);
bool ws_wh_wide_ies_read(struct ws_ie_custom_list *list, const uint8_t *data, uint16_t length, uint16_t frame_type_mask);

bool ws_wh_sl_utt_read(const uint8_t *data, uint16_t length, struct ws_utt_ie *utt_ie);

/* WS_WP_NESTED PAYLOD IE */
void       ws_wp_nested_us_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config);
void       ws_wp_nested_bs_write(struct iobuf_write *buf, const struct ws_fhss_config *fhss_config);
void      ws_wp_nested_pan_write(struct iobuf_write *buf, uint16_t pan_size, uint16_t routing_cost,
                                 uint8_t use_parent_bs_ie, uint8_t routing_method,
                                 uint8_t lfn_window_style, uint8_t tps_version);
void  ws_wp_nested_netname_write(struct iobuf_write *buf, const char *netname);
void   ws_wp_nested_panver_write(struct iobuf_write *buf, uint16_t pan_version);
void  ws_wp_nested_gtkhash_write(struct iobuf_write *buf, const uint8_t gtkhash[4][8]);
uint16_t ws_wp_nested_hopping_schedule_length(const struct ws_fhss_config *fhss_config, bool unicast_schedule);
/* Wi-SUN FAN 1.1 */
void      ws_wp_nested_pom_write(struct iobuf_write *buf, const uint8_t phy_op_modes[FIELD_MAX(WS_MASK_POM_COUNT) + 1], bool mdr_cmd_capable);
void    ws_wp_nested_lbats_write(struct iobuf_write *buf, struct ws_lbats_ie *lbats_ie);
void   ws_wp_nested_lfnver_write(struct iobuf_write *buf, uint16_t version);
void ws_wp_nested_lgtkhash_write(struct iobuf_write *buf, const uint8_t lgtkhash[3][8], uint8_t active_lgtk_index);
void      ws_wp_nested_lcp_write(struct iobuf_write *buf, uint8_t tag, const struct ws_fhss_config *fhss_config);
void       ws_wp_nested_jm_write(struct iobuf_write *buf, const struct ws_jm_ie *jm);

bool ws_wp_nested_us_read(const uint8_t *data, uint16_t length, struct ws_us_ie *us_ie);
bool ws_wp_nested_bs_read(const uint8_t *data, uint16_t length, struct ws_bs_ie *bs_ie);
bool ws_wp_nested_pan_read(const uint8_t *data, uint16_t length, struct ws_pan_ie *pan_ie);
bool ws_wp_nested_panver_read(const uint8_t *data, uint16_t length, uint16_t *pan_version);
bool ws_wp_nested_netname_read(const uint8_t *data, uint16_t length, struct ws_netname_ie *netname);
bool ws_wp_nested_gtkhash_read(const uint8_t *data, uint16_t length, uint8_t gtkhash[4][8]);
/* Wi-SUN FAN 1.1 */
bool ws_wp_nested_pom_read(const uint8_t *data, uint16_t length, struct ws_pom_ie *pom_ie);
bool ws_wp_nested_lbats_read(const uint8_t *data, uint16_t length, struct ws_lbats_ie *lbats_ie);
bool ws_wp_nested_lfnver_read(const uint8_t *data, uint16_t length, struct ws_lfnver_ie *ws_lfnver);
bool ws_wp_nested_lgtkhash_read(const uint8_t *data, uint16_t length, uint8_t lgtkhash[3][8], unsigned *active_lgtk_index);
bool ws_wp_nested_lcp_read(const uint8_t *data, uint16_t length, uint8_t tag, struct ws_lcp_ie *ws_lcp_ie);
struct ws_jm *ws_wp_nested_jm_get_metric(struct ws_jm_ie *jm, uint8_t metric_id);
bool ws_wp_nested_jm_read(const uint8_t *data, uint16_t length, struct ws_jm_ie *jm);
bool ws_wp_nested_wide_ies_read(struct ws_ie_custom_list *list, const uint8_t *data, uint16_t length, uint16_t frame_type_mask);

#endif
