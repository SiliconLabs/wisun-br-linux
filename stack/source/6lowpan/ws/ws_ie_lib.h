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

struct iobuf_write;
struct ws_pan_information;
struct ws_utt_ie;
struct ws_bt_ie;
struct ws_us_ie;
struct ws_hopping_schedule;
struct ws_fc_ie;
struct ws_pom_ie;

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
void    ws_wh_fc_write(struct iobuf_write *buf, struct ws_fc_ie *fc_ie);
void   ws_wh_rsl_write(struct iobuf_write *buf, uint8_t rsl);
void    ws_wh_vh_write(struct iobuf_write *buf, uint8_t *vendor_header, uint8_t vendor_header_length);
void    ws_wh_ea_write(struct iobuf_write *buf, uint8_t eui64[8]);
/* Wi-SUN FAN 1.1 */
void  ws_wh_lutt_write(struct iobuf_write *buf, uint8_t message_type);
void   ws_wh_lus_write(struct iobuf_write *buf, struct ws_lus_ie *lus_ie);
void  ws_wh_flus_write(struct iobuf_write *buf, struct ws_flus_ie *flus_ie);
void   ws_wh_lbt_write(struct iobuf_write *buf, struct ws_lbt_ie *lbt_ie);
void   ws_wh_lbs_write(struct iobuf_write *buf, struct ws_lbs_ie *lbs_ie);
void    ws_wh_nr_write(struct iobuf_write *buf, struct ws_nr_ie *nr_ie);
void   ws_wh_lnd_write(struct iobuf_write *buf, struct ws_lnd_ie *lnd_ie);
void   ws_wh_lto_write(struct iobuf_write *buf, struct ws_lto_ie *lto_ie);
void ws_wh_panid_write(struct iobuf_write *buf, struct ws_panid_ie *panid_ie);
void   ws_wh_lbc_write(struct iobuf_write *buf, struct ws_lbc_ie *lbc_ie);


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
int ws_wp_base_write(struct iobuf_write *buf);
void ws_wp_nested_hopping_schedule_write(struct iobuf_write *buf, struct ws_hopping_schedule *hopping_schedule, bool unicast_schedule);
void               ws_wp_nested_vp_write(struct iobuf_write *buf, uint8_t *vendor_payload, uint16_t vendor_payload_length);
void              ws_wp_nested_pan_write(struct iobuf_write *buf, struct ws_pan_information *pan_configuration);
void          ws_wp_nested_netname_write(struct iobuf_write *buf, uint8_t *network_name, uint8_t network_name_length);
void           ws_wp_nested_panver_write(struct iobuf_write *buf, struct ws_pan_information *pan_configuration);
void          ws_wp_nested_gtkhash_write(struct iobuf_write *buf, gtkhash_t gtkhash[4], uint8_t gtkhash_length);
uint16_t ws_wp_nested_hopping_schedule_length(struct ws_hopping_schedule *hopping_schedule, bool unicast_schedule);
/* Wi-SUN FAN 1.1 */
void              ws_wp_nested_pom_write(struct iobuf_write *buf, uint8_t phy_op_mode_number, uint8_t *phy_operating_modes, uint8_t mdr_command_capable);
void            ws_wp_nested_lbats_write(struct iobuf_write *buf, struct ws_lbats_ie *lbats_ie);
void           ws_wp_nested_lfnver_write(struct iobuf_write *buf, struct ws_lfnver_ie *ws_lfnver);
void         ws_wp_nested_lgtkhash_write(struct iobuf_write *buf, gtkhash_t lgtkhash[3], unsigned active_lgtk_index);
void              ws_wp_nested_lcp_write(struct iobuf_write *buf, struct ws_lcp_ie *ws_lcp);

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
bool ws_wp_nested_lcp_read(const uint8_t *data, uint16_t length, struct ws_lcp_ie *ws_lcp_ie);


#endif
