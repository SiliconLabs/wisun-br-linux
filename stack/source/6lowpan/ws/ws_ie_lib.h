/*
 * Copyright (c) 2018-2020, Pelion and affiliates.
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
#include "6lowpan/ws/ws_common_defines.h"

struct ws_pan_information;
struct ws_utt_ie;
struct ws_bt_ie;
struct ws_us_ie;
struct ws_hopping_schedule;
struct ws_fc_ie;
struct ws_pom_ie;

/**
 * @brief ws_wp_network_name_t WS nested payload network name
 */
typedef struct ws_wp_network_name {
    uint8_t network_name_length;
    uint8_t *network_name;
} ws_wp_network_name_t;


/* WS_WH HEADER IE */
uint8_t *ws_wh_utt_write(uint8_t *ptr, uint8_t message_type);
uint8_t *ws_wh_bt_write(uint8_t *ptr);
uint8_t *ws_wh_fc_write(uint8_t *ptr, struct ws_fc_ie *fc_ie);
uint8_t *ws_wh_rsl_write(uint8_t *ptr, uint8_t rsl);
uint8_t *ws_wh_vh_write(uint8_t *ptr, uint8_t *vendor_header, uint8_t vendor_header_length);
uint8_t *ws_wh_ea_write(uint8_t *ptr, uint8_t *eui64);
/* Wi-SUN FAN 1.1 */
uint8_t *ws_wh_lutt_write(uint8_t *ptr, uint8_t message_type);
#define ws_wh_lutt_length() 6
uint8_t *ws_wh_lus_write(uint8_t *ptr, struct ws_lus_ie *lus_ie);
#define ws_wh_lus_length() 4
uint8_t *ws_wh_flus_write(uint8_t *ptr, struct ws_flus_ie *flus_ie);
#define ws_wh_flus_length() 2
uint8_t *ws_wh_lbt_write(uint8_t *ptr, struct ws_lbt_ie *lbt_ie);
#define ws_wh_lbt_length() 5
uint8_t *ws_wh_lbs_write(uint8_t *ptr, struct ws_lbs_ie *lbs_ie);
#define ws_wh_lbs_length() 7
uint8_t *ws_wh_nr_write(uint8_t *ptr, struct ws_nr_ie *nr_ie);
uint16_t ws_wh_nr_length(struct ws_nr_ie *nr_ie);
uint8_t *ws_wh_lnd_write(uint8_t *ptr, struct ws_lnd_ie *lnd_ie);
#define ws_wh_lnd_length() 8
uint8_t *ws_wh_lto_write(uint8_t *ptr, struct ws_lto_ie *lto_ie);
#define ws_wh_lto_length() 6
uint8_t *ws_wh_panid_write(uint8_t *ptr, struct ws_panid_ie *panid_ie);
#define ws_wh_panid_length() 2
uint8_t *ws_wh_lbc_write(uint8_t *ptr, uint24_t interval, uint8_t sync_period);
#define ws_wh_lbc_length() 4


bool ws_wh_utt_read(uint8_t *data, uint16_t length, struct ws_utt_ie *utt_ie);
bool ws_wh_bt_read(uint8_t *data, uint16_t length, struct ws_bt_ie *bt_ie);
bool ws_wh_fc_read(uint8_t *data, uint16_t length, struct ws_fc_ie *fc_ie);
bool ws_wh_rsl_read(uint8_t *data, uint16_t length, int8_t *rsl);
bool ws_wh_ea_read(uint8_t *data, uint16_t length, uint8_t *eui64);
/*Wi-SUN FAN 1.1 */
bool ws_wh_lutt_read(uint8_t *data, uint16_t length, struct ws_lutt_ie *lutt_ie);
bool ws_wh_lus_read(uint8_t *data, uint16_t length, struct ws_lus_ie *lus_ie);
bool ws_wh_flus_read(uint8_t *data, uint16_t length, struct ws_flus_ie *flus_ie);
bool ws_wh_lbt_read(uint8_t *data, uint16_t length, struct ws_lbt_ie *lbt_ie);
bool ws_wh_lbs_read(uint8_t *data, uint16_t length, struct ws_lbs_ie *lbs_ie);
bool ws_wh_lbc_read(uint8_t *data, uint16_t length, struct ws_lbc_ie *lbc_ie);
bool ws_wh_nr_read(uint8_t *data, uint16_t length, struct ws_nr_ie *nr_ie);
bool ws_wh_lnd_read(uint8_t *data, uint16_t length, struct ws_lnd_ie *lnd_ie);
bool ws_wh_lto_read(uint8_t *data, uint16_t length, struct ws_lto_ie *lto_ie);
bool ws_wh_panid_read(uint8_t *data, uint16_t length, struct ws_panid_ie *panid_ie);

/* WS_WP_NESTED PAYLOD IE */
uint8_t *ws_wp_base_write(uint8_t *ptr, uint16_t length);
uint8_t *ws_wp_nested_hopping_schedule_write(uint8_t *ptr, struct ws_hopping_schedule *hopping_schedule, bool unicast_schedule);
uint8_t *ws_wp_nested_vp_write(uint8_t *ptr, uint8_t *vendor_payload, uint16_t vendor_payload_length);
uint8_t *ws_wp_nested_pan_info_write(uint8_t *ptr, struct ws_pan_information *pan_configuration);
uint8_t *ws_wp_nested_netname_write(uint8_t *ptr, uint8_t *network_name, uint8_t network_name_length);
uint8_t *ws_wp_nested_pan_ver_write(uint8_t *ptr, struct ws_pan_information *pan_configuration);
uint8_t *ws_wp_nested_gtkhash_write(uint8_t *ptr, gtkhash_t *gtkhash, uint8_t gtkhash_length);
uint16_t ws_wp_nested_hopping_schedule_length(struct ws_hopping_schedule *hopping_schedule, bool unicast_schedule);
/* Wi-SUN FAN 1.1 */
uint8_t *ws_wp_nested_pom_write(uint8_t *ptr, uint8_t phy_op_mode_number, uint8_t *phy_operating_modes, uint8_t mdr_command_capable);
uint16_t ws_wp_nested_pom_length(uint8_t phy_op_mode_number);
uint8_t *ws_wp_nested_lbats_write(uint8_t *ptr, struct ws_lbats_ie *lbats_ie);
#define ws_wp_nested_lbats_length() 3
uint8_t *ws_wp_nested_lfn_version_write(uint8_t *ptr, struct ws_lfnver_ie *ws_lfnver);
#define ws_wp_nested_lfn_version_length() 2
uint8_t *ws_wp_nested_lgtkhash_write(uint8_t *ptr, gtkhash_t *lgtkhash, unsigned active_lgtk_index);
uint16_t ws_wp_nested_lgtkhash_length(gtkhash_t *lgtkhash);
uint8_t *ws_wp_nested_lfn_channel_plan_write(uint8_t *ptr, struct ws_lcp_ie *ws_lcp);
uint16_t ws_wp_nested_lfn_channel_plan_length(struct ws_lcp_ie *ws_lcp);


bool ws_wp_nested_us_read(uint8_t *data, uint16_t length, struct ws_us_ie *us_ie);
bool ws_wp_nested_bs_read(uint8_t *data, uint16_t length, struct ws_bs_ie *bs_ie);
bool ws_wp_nested_pan_read(uint8_t *data, uint16_t length, struct ws_pan_information *pan_configuration);
bool ws_wp_nested_pan_version_read(uint8_t *data, uint16_t length, uint16_t *pan_version);
bool ws_wp_nested_network_name_read(uint8_t *data, uint16_t length, ws_wp_network_name_t *network_name);
gtkhash_t *ws_wp_nested_gtkhash_read(uint8_t *data, uint16_t length);
/* Wi-SUN FAN 1.1 */
bool ws_wp_nested_pom_read(uint8_t *data, uint16_t length, struct ws_pom_ie *pom_ie);
bool ws_wp_nested_lbats_read(uint8_t *data, uint16_t length, struct ws_lbats_ie *lbats_ie);
bool ws_wp_nested_lfn_version_read(uint8_t *data, uint16_t length, struct ws_lfnver_ie *ws_lfnver);
bool ws_wp_nested_lgtkhash_read(uint8_t *data, uint16_t length, gtkhash_t *lgtkhash, unsigned *active_lgtk_index);
bool ws_wp_nested_lfn_channel_plan_read(uint8_t *data, uint16_t length, struct ws_lcp_ie *ws_lcp_ie);


#endif
