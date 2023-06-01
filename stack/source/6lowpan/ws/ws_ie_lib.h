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
#include "6lowpan/ws/ws_common_defines.h"

struct iobuf_write;
struct ws_pan_information;
struct ws_utt_ie;
struct ws_bt_ie;
struct ws_us_ie;
struct ws_hopping_schedule;
struct ws_fc_ie;
struct ws_pom_ie;

// Wi-SUN Assigned Value Registry 0v24
//   7.1. Wi-SUN Header Information Eement Sub-IDs
// FAN 1.0
#define WS_WHIE_UTT   0x01 // Unicast Timing and Frame Type
#define WS_WHIE_BT    0x02 // Broadcast Timing
#define WS_WHIE_FC    0x03 // Flow Control
#define WS_WHIE_RSL   0x04 // Received Signal Level
#define WS_WHIE_MHDS  0x05 // MHDS
#define WS_WHIE_VH    0x06 // Vendor Header
#define WS_WHIE_EA    0x09 // EAPOL Authenticator EUI-64
// FAN 1.1
#define WS_WHIE_LUTT  0x0a // LFN Unicast Timing and Frame Type
#define WS_WHIE_LBT   0x0b // LFN Broadcast Timing
#define WS_WHIE_NR    0x0c // Node Role
#define WS_WHIE_LUS   0x0d // LFN Unicast Schedule
#define WS_WHIE_FLUS  0x0e // FFN for LFN Unicast Schedule
#define WS_WHIE_LBS   0x0f // LFN Broadcast Schedule
#define WS_WHIE_LND   0x10 // LFN Network Discovery
#define WS_WHIE_LTO   0x11 // LFN Timing Offset
#define WS_WHIE_PANID 0x12 // PAN Identifier
#define WS_WHIE_LBC   0x80 // LFN Broadcast Configuration

// Wi-SUN Assigned Value Registry 0v24
//   7.2. Wi-SUN Payload Information Eement Sub-IDs
// FAN 1.0 short form
#define WS_WPIE_PAN      0x04 // PAN
#define WS_WPIE_NETNAME  0x05 // Network Name
#define WS_WPIE_PANVER   0x06 // PAN Version
#define WS_WPIE_GTKHASH  0x07 // GTK Hash
// FAN 1.1 short form
#define WS_WPIE_POM      0x08 // PHY Operating Modes
#define WS_WPIE_LBATS    0x09 // LFN Broadcast Additional Transmit Schedule
#define WS_WPIE_JM       0x0a // Join Metrics
#define WS_WPIE_LFNVER   0x40 // LFN Version
#define WS_WPIE_LGTKHASH 0x41 // LFN GTK Hash
// FAN 1.0 long form
#define WS_WPIE_US       0x01 // Unicast Schedule
#define WS_WPIE_BS       0x02 // Broadcast Schedule
#define WS_WPIE_VP       0x03 // Vendor Payload
// FAN 1.1 long form
#define WS_WPIE_LCP      0x04 // LFN Channel Plan

// Wi-SUN Assigned Value Registry 0v24
//   8. Join Metric IDs
#define WS_JM_PLF 1 // PAN Load Factor

/**
 * @brief ws_wp_netname_t WS nested payload network name
 */
typedef struct ws_wp_netname {
    uint8_t network_name_length;
    const uint8_t *network_name;
} ws_wp_netname_t;


/* WS_WH HEADER IE */
void   ws_wh_utt_write(struct iobuf_write *buf, uint8_t message_type);
void    ws_wh_bt_write(struct iobuf_write *buf);
void    ws_wh_fc_write(struct iobuf_write *buf, uint8_t tx, uint8_t rx);
void   ws_wh_rsl_write(struct iobuf_write *buf, uint8_t rsl);
void    ws_wh_ea_write(struct iobuf_write *buf, uint8_t eui64[8]);
/* Wi-SUN FAN 1.1 */
void  ws_wh_lutt_write(struct iobuf_write *buf, uint8_t message_type);
void   ws_wh_lus_write(struct iobuf_write *buf, struct ws_lus_ie *lus_ie);
void  ws_wh_flus_write(struct iobuf_write *buf, uint24_t dwell_interval, uint8_t tag);
void   ws_wh_lbt_write(struct iobuf_write *buf, struct ws_lbt_ie *lbt_ie);
void   ws_wh_lbs_write(struct iobuf_write *buf, uint24_t interval, uint16_t sched_id, uint8_t tag, uint8_t sync_period);
void    ws_wh_nr_write(struct iobuf_write *buf, uint8_t node_role,
                       uint8_t clock_drift, uint8_t timing_accuracy,
                       uint24_t listen_interval_min, uint24_t listen_interval_max);
void   ws_wh_lnd_write(struct iobuf_write *buf, struct ws_lnd_ie *lnd_ie);
void   ws_wh_lto_write(struct iobuf_write *buf, struct ws_lto_ie *lto_ie);
void ws_wh_panid_write(struct iobuf_write *buf, uint16_t panid);
void   ws_wh_lbc_write(struct iobuf_write *buf, uint24_t interval, uint8_t sync_period);


bool ws_wh_utt_read(const uint8_t *data, uint16_t length, struct ws_utt_ie *utt_ie);
bool ws_wh_bt_read(const uint8_t *data, uint16_t length, struct ws_bt_ie *bt_ie);
bool ws_wh_fc_read(const uint8_t *data, uint16_t length, struct ws_fc_ie *fc_ie);
bool ws_wh_rsl_read(const uint8_t *data, uint16_t length, int8_t *rsl);
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

/* WS_WP_NESTED PAYLOD IE */
void       ws_wp_nested_us_write(struct iobuf_write *buf, const struct ws_hopping_schedule *hopping_schedule);
void       ws_wp_nested_bs_write(struct iobuf_write *buf, const struct ws_hopping_schedule *hopping_schedule);
void      ws_wp_nested_pan_write(struct iobuf_write *buf, uint16_t pan_size, uint16_t routing_cost, uint8_t tps_version);
void  ws_wp_nested_netname_write(struct iobuf_write *buf, uint8_t *network_name, uint8_t network_name_length);
void   ws_wp_nested_panver_write(struct iobuf_write *buf, uint8_t pan_version);
void  ws_wp_nested_gtkhash_write(struct iobuf_write *buf, const gtkhash_t gtkhash[4]);
uint16_t ws_wp_nested_hopping_schedule_length(struct ws_hopping_schedule *hopping_schedule, bool unicast_schedule);
/* Wi-SUN FAN 1.1 */
void      ws_wp_nested_pom_write(struct iobuf_write *buf, uint8_t phy_op_mode_number, uint8_t *phy_operating_modes, uint8_t mdr_command_capable);
void    ws_wp_nested_lbats_write(struct iobuf_write *buf, struct ws_lbats_ie *lbats_ie);
void   ws_wp_nested_lfnver_write(struct iobuf_write *buf, uint16_t version);
void ws_wp_nested_lgtkhash_write(struct iobuf_write *buf, const gtkhash_t lgtkhash[3], uint8_t active_lgtk_index);
void      ws_wp_nested_lcp_write(struct iobuf_write *buf, uint8_t tag, struct ws_hopping_schedule *hopping_schedule);
void   ws_wp_nested_jm_plf_write(struct iobuf_write *buf, uint8_t version, uint8_t pan_load_factor);

bool ws_wp_nested_us_read(const uint8_t *data, uint16_t length, struct ws_us_ie *us_ie);
bool ws_wp_nested_bs_read(const uint8_t *data, uint16_t length, struct ws_bs_ie *bs_ie);
bool ws_wp_nested_pan_read(const uint8_t *data, uint16_t length, struct ws_pan_information *pan_configuration);
bool ws_wp_nested_panver_read(const uint8_t *data, uint16_t length, uint16_t *pan_version);
bool ws_wp_nested_netname_read(const uint8_t *data, uint16_t length, ws_wp_netname_t *network_name);
bool ws_wp_nested_gtkhash_read(const uint8_t *data, uint16_t length, gtkhash_t gtkhash[4]);
/* Wi-SUN FAN 1.1 */
bool ws_wp_nested_pom_read(const uint8_t *data, uint16_t length, struct ws_pom_ie *pom_ie);
bool ws_wp_nested_lbats_read(const uint8_t *data, uint16_t length, struct ws_lbats_ie *lbats_ie);
bool ws_wp_nested_lfnver_read(const uint8_t *data, uint16_t length, struct ws_lfnver_ie *ws_lfnver);
bool ws_wp_nested_lgtkhash_read(const uint8_t *data, uint16_t length, gtkhash_t lgtkhash[3], unsigned *active_lgtk_index);
bool ws_wp_nested_lcp_read(const uint8_t *data, uint16_t length, uint8_t tag, struct ws_lcp_ie *ws_lcp_ie);


#endif
