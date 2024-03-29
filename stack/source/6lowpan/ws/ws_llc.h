/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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

#ifndef WS_LLC_H_
#define WS_LLC_H_
#include <stdint.h>
#include <stdbool.h>
#include "common/ns_list.h"
#include "app_wsbrd/rcp_api_legacy.h"

#include "6lowpan/ws/ws_neigh.h"

typedef enum mac_data_priority mac_data_priority_e;
struct net_if;
struct mcps_data_ind;
struct mcps_data_rx_ie_list;
struct ws_pan_information;
struct ws_hopping_schedule;
struct ws_neigh;
struct ws_neighbor_temp_class;
struct mpx_api;

struct wh_ie_list {
    bool utt:   1;
    bool bt:    1;
    bool fc:    1;
    bool rsl:   1;
    bool ea:    1;
    bool lutt:  1;
    bool lbt:   1;
    bool nr:    1;
    bool lus:   1;
    bool flus:  1;
    bool lbs:   1;
    bool lnd:   1;
    bool lto:   1;
    bool panid: 1;
    bool lbc:   1;
};

struct wp_ie_list {
    bool us:       1;
    bool bs:       1;
    bool pan:      1;
    bool netname:  1;
    bool panver:   1;
    bool gtkhash:  1;
    bool lgtkhash: 1;
    bool lfnver:   1;
    bool lcp:      1;
    bool lbats:    1;
    bool pom:      1;
    bool jm:       1;
};

struct ws_llc_mngt_req {
    uint8_t frame_type;
    struct wh_ie_list wh_ies;
    struct wp_ie_list wp_ies;
    struct mlme_security security;
};

typedef struct eapol_temporary_info {
    uint8_t eapol_rx_relay_filter; /*!< seconds for dropping duplicate id */
    uint8_t last_rx_mac_sequency; /*!< Only compared when Timer is active */
    uint16_t eapol_timeout; /*!< EAPOL relay Temporary entry lifetime */
} eapol_temporary_info_t;

/**
 * Neighbor temporary structure for storage FHSS data before create a real Neighbour info
 */
typedef struct ws_neighbor_temp_class {
    struct ws_neigh neigh_info_list;  /*!< Allocated hopping info array*/
    eapol_temporary_info_t eapol_temp_info;
    uint8_t mac64[8];
    uint8_t mpduLinkQuality;
    int8_t signal_dbm;
    ns_list_link_t link;
} ws_neighbor_temp_class_t;

typedef NS_LIST_HEAD(ws_neighbor_temp_class_t, link) ws_neighbor_temp_list_t;

typedef void ws_llc_mngt_ind_cb(struct net_if *net_if, const struct mcps_data_ind *data, const struct mcps_data_rx_ie_list *ie, uint8_t frame_type);
typedef void ws_llc_mngt_cnf_cb(struct net_if *net_if, uint8_t frame_type);

int8_t ws_llc_create(struct net_if *interface,
                     ws_llc_mngt_ind_cb *mngt_ind, ws_llc_mngt_cnf_cb *mngt_cnf);

/**
 * @brief ws_llc_reset Reset ws LLC parametrs and clean messages
 * @param interface Interface pointer
 *
 */
void ws_llc_reset(struct net_if *interface);

/**
 * @brief ws_llc_delete Delete LLC interface. ONLY for Test purpose.
 * @param interface Interface pointer
 *
 */
int8_t ws_llc_delete(struct net_if *interface);

/**
 * @brief ws_llc_mpx_api_get Get MPX api for registration purpose.
 * @param interface Interface pointer
 *
 * @return NULL when MPX is not vailabale
 * @return Pointer to MPX API
 *
 */
struct mpx_api *ws_llc_mpx_api_get(struct net_if *interface);

/**
 * @brief ws_llc_asynch_request ws asynch message request to all giving channels
 * @param interface Interface pointer
 * @param request Asynch message parameters: type, IE and channel list
 *
 * @return 0 Asynch message pushed to MAC
 * @return -1 memory allocate problem
 * @return -2 Parameter problem
 *
 */
int8_t ws_llc_asynch_request(struct net_if *interface, struct ws_llc_mngt_req *request);

int ws_llc_mngt_lfn_request(struct net_if *interface, const struct ws_llc_mngt_req *req,
                            const uint8_t dst[8], mac_data_priority_e priority);

void ws_llc_timer_seconds(struct net_if *interface, uint16_t seconds_update);

bool ws_llc_eapol_relay_forward_filter(struct net_if *interface, const uint8_t *joiner_eui64,
                                       uint8_t mac_sequency, uint64_t rx_timestamp);

ws_neighbor_temp_class_t *ws_llc_get_eapol_temp_entry(struct net_if *interface, const uint8_t *mac64);

int8_t ws_llc_set_mode_switch(struct net_if *interface, int mode, uint8_t phy_mode_id, uint8_t *neighbor_mac_address);

const char *tr_ws_frame(uint8_t frame_type);

typedef struct mcps_data_cnf         mcps_data_cnf_t;
void ws_llc_mac_confirm_cb(int8_t net_if_id, const mcps_data_cnf_t *data,
                           const struct mcps_data_rx_ie_list *conf_data);

typedef struct mcps_data_ind         mcps_data_ind_t;
void ws_llc_mac_indication_cb(int8_t net_if_id, const mcps_data_ind_t *data,
                              const struct mcps_data_rx_ie_list *ie_ext);

#endif
