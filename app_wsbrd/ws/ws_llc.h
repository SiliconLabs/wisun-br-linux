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
#include "common/ws_interface.h"
#include "common/ns_list.h"
#include "common/ws_neigh.h"
#include "app/rcp_api_legacy.h"

#include "ws/ws_common.h"

struct net_if;
struct mcps_data_ind;
struct mcps_data_rx_ie_list;
struct ws_phy_config;
struct ws_neigh;
struct ws_neighbor_temp_class;
struct mpx_api;
struct ws_info;

struct ws_llc_mngt_req {
    uint8_t frame_type;
    struct wh_ie_list wh_ies;
    struct wp_ie_list wp_ies;
    struct mlme_security security;
};

typedef void ws_llc_mngt_ind_cb(struct ws_info *ws_info, const struct mcps_data_ind *data, const struct mcps_data_rx_ie_list *ie, uint8_t frame_type);
typedef void ws_llc_mngt_cnf_cb(struct ws_info *ws_info, uint8_t frame_type);

int8_t ws_llc_create(struct net_if *interface,
                     ws_llc_mngt_ind_cb *mngt_ind, ws_llc_mngt_cnf_cb *mngt_cnf);

/**
 * @brief ws_llc_reset Reset ws LLC parametrs and clean messages
 * @param interface Interface pointer
 *
 */
void ws_llc_reset(struct net_if *interface);

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
 * @param request Asynch message parameters: type, IE and channel list
 *
 * @return 0 Asynch message pushed to MAC
 * @return -1 memory allocate problem
 * @return -2 Parameter problem
 *
 */
int8_t ws_llc_asynch_request(struct ws_info *ws_info, struct ws_llc_mngt_req *request);

int ws_llc_mngt_lfn_request(const struct ws_llc_mngt_req *req,
                            const uint8_t dst[8]);

int8_t ws_llc_set_mode_switch(struct net_if *interface, uint8_t mode, uint8_t phy_mode_id,
                              uint8_t *neighbor_mac_address);

int ws_llc_set_edfe(struct net_if *interface, enum ws_edfe_mode mode, uint8_t *neighbor_mac_address);

const char *tr_ws_frame(uint8_t frame_type);

typedef struct mcps_data_cnf         mcps_data_cnf_t;
void ws_llc_mac_confirm_cb(struct net_if *net_if, const mcps_data_cnf_t *data,
                           const struct mcps_data_rx_ie_list *conf_data);

typedef struct mcps_data_ind         mcps_data_ind_t;
void ws_llc_mac_indication_cb(struct net_if *net_if, struct mcps_data_ind *data,
                              const struct mcps_data_rx_ie_list *ie_ext);

#endif
