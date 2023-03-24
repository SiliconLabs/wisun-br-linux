/*
 * Copyright (c) 2018-2021, Pelion and affiliates.
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
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/channel_list.h"

#include "6lowpan/ws/ws_neighbor_class.h"

struct net_if;
struct mcps_data_ind;
struct mcps_data_ie_list;
struct channel_list;
struct ws_pan_information;
struct mlme_security;
struct ws_hopping_schedule;
struct ws_neighbor_class_entry;
struct mac_neighbor_table_entry;
struct ws_neighbor_temp_class;
struct mpx_api;


/**
 * @brief wh_ie_sub_list_t ws asynch header IE elemnt request list
 */
typedef struct wh_ie_sub_list {
    bool utt_ie: 1;  /**< Unicast Timing and Frame type information */
    bool bt_ie: 1;   /**< Broadcast timing information */
    bool fc_ie: 1;   /**< Flow Control for Extended Direct Frame Exchange */
    bool rsl_ie: 1;  /**< Received Signal Level information */
    bool ea_ie: 1;   /**< EAPOL autheticator EUI-64 header information */
    bool lutt_ie: 1;  /**< LFN Unicast Timing and Frame Type information */
    bool lbt_ie: 1;   /**< LFN Broadcast Timing information */
    bool nr_ie: 1;    /**< Node Role information */
    bool lus_ie: 1;   /**< LFN Unicast Schedule information */
    bool flus_ie: 1;  /**< FFN for LFN unicast Schedule information */
    bool lbs_ie: 1;   /**< LFN Broadcast Schedule information */
    bool lnd_ie: 1;   /**< LFN Network Discovery information */
    bool lto_ie: 1;   /**< LFN Timing information */
    bool panid_ie: 1; /**< PAN Identifier information */
    bool lbc_ie: 1;   /**< LFN Broadcast Configuration information */
} wh_ie_sub_list_t;

/**
 * @brief wp_nested_ie_sub_list_t ws asynch Nested Payload sub IE element request list
 */
typedef struct wp_nested_ie_sub_list {
    bool us_ie: 1;                  /**< Unicast Schedule information */
    bool bs_ie: 1;                  /**< Broadcast Schedule information */
    bool pan_ie: 1;                 /**< PAN Information */
    bool net_name_ie: 1;            /**< Network Name information */
    bool pan_version_ie: 1;         /**< Pan configuration version */
    bool gtkhash_ie: 1;             /**< GTK Hash information */
    bool lgtkhash_ie: 1;            /**< LFN GTK Hash */
    bool lfnver_ie: 1;              /**< LFN Version */
    bool lcp_ie: 1;                 /**< LFN Channel Plan information */
    bool lbats_ie: 1;               /**< LFN Broadcast Additional Transmit Schedule */
    bool pom_ie: 1;                 /**< PHY Operating Modes information */
} wp_nested_ie_sub_list_t;

/**
 * @brief asynch_request_t Asynch message request parameters
 */
typedef struct asynch_request {
    unsigned  message_type: 4;                              /**< Asynch message type: WS_FT_PA, WS_FT_PAS, WS_FT_PC or WS_FT_PCS. */
    wh_ie_sub_list_t wh_requested_ie_list;                  /**< WH-IE header list to message. */
    wp_nested_ie_sub_list_t wp_requested_nested_ie_list;    /**< WP-IE Nested IE list to message. */
    struct mlme_security security;                               /**< Request MAC security paramaters */
} asynch_request_t;


/**
 * @brief LLC neighbour info request parameters
 */
typedef struct llc_neighbour_req {
    struct mac_neighbor_table_entry *neighbor;                  /**< Generic Link Layer Neighbor information entry. */
    struct ws_neighbor_class_entry *ws_neighbor;                /**< Wi-sun Neighbor information entry. */
} llc_neighbour_req_t;

typedef struct eapol_temporary_info {
    uint8_t eapol_rx_relay_filter; /*!< seconds for dropping duplicate id */
    uint8_t last_rx_mac_sequency; /*!< Only compared when Timer is active */
    uint16_t eapol_timeout; /*!< EAPOL relay Temporary entry lifetime */
} eapol_temporary_info_t;

/**
 * Neighbor temporary structure for storage FHSS data before create a real Neighbour info
 */
typedef struct ws_neighbor_temp_class {
    struct ws_neighbor_class_entry neigh_info_list;  /*!< Allocated hopping info array*/
    eapol_temporary_info_t eapol_temp_info;
    uint8_t mac64[8];
    uint8_t mpduLinkQuality;
    int8_t signal_dbm;
    ns_list_link_t link;
} ws_neighbor_temp_class_t;

typedef NS_LIST_HEAD(ws_neighbor_temp_class_t, link) ws_neighbor_temp_list_t;

/**
 * @brief ws_asynch_ind ws asynch data indication
 * @param interface Interface pointer
 * @param data MCPS-DATA.indication specific values
 * @param ie_ext Information element list
 */
typedef void ws_asynch_ind(struct net_if *interface, const struct mcps_data_ind *data, const struct mcps_data_ie_list *ie_ext, uint8_t message_type);

/**
 * @brief ws_asynch_confirm ws asynch data confirmation to asynch message request
 * @param api The API which handled the response
 * @param data MCPS-DATA.confirm specific values
 * @param user_id MPX user ID
 */
typedef void ws_asynch_confirm(struct net_if *interface, uint8_t asynch_message);

/**
 * @brief ws_llc_create ws LLC module create
 * @param interface Interface pointer
 * @param asynch_ind_cb Asynch indication
 * @param ie_ext Information element list
 *
 * Function allocate and init LLC class and init it 2 supported 2 API: ws asynch and MPX user are internally registered.
 */
int8_t ws_llc_create(struct net_if *interface, ws_asynch_ind *asynch_ind_cb, ws_asynch_confirm *asynch_cnf_cb);

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
int8_t ws_llc_asynch_request(struct net_if *interface, asynch_request_t *request);


/**
 * @brief ws_llc_set_network_name Configure WS Network name (Data of WP_PAYLOAD_IE_NETNAME_TYPE IE element)
 * @param interface Interface pointer
 * @param name_length configured network name length
 * @param name pointer to network name this pointer must keep alive when it is configured to LLC
 *
 */
void ws_llc_set_network_name(struct net_if *interface, uint8_t *name, uint8_t name_length);

/**
 * @brief ws_llc_set_gtkhash Configure WS GTK hash information (Data of WP_PAYLOAD_IE_GTKHASH_TYPE IE element)
 * @param interface Interface pointer
 * @param gtkhash pointer to GTK hash which length is 32 bytes this pointer must keep alive when it is configured to LLC
 *
 */
void  ws_llc_set_gtkhash(struct net_if *interface, gtkhash_t *gtkhash);

/**
 * @brief ws_llc_set_lgtkhash Configure WS LFN GTK hash information (Data of WP_PAYLOAD_IE_LGTKHASH_TYPE IE element)
 * @param interface Interface pointer
 * @param gtkhash pointer to LGTK hashes. This pointer must keep alive when it is configured to LLC
 *
 */
void  ws_llc_set_lgtkhash(struct net_if *interface, gtkhash_t *lgtkhash);

/**
 * @brief ws_llc_set_pan_information_pointer Configure WS PAN information (Data of WP_PAYLOAD_IE_PAN_TYPE IE element)
 * @param interface Interface pointer
 * @param pan_information_pointer pointer to Pan information this pointer must keep alive when it is configured to LLC
 *
 */
void ws_llc_set_pan_information_pointer(struct net_if *interface, struct ws_pan_information *pan_information_pointer);

void ws_llc_timer_seconds(struct net_if *interface, uint16_t seconds_update);

void ws_llc_fast_timer(struct net_if *interface, uint16_t ticks);

bool ws_llc_eapol_relay_forward_filter(struct net_if *interface, const uint8_t *joiner_eui64, uint8_t mac_sequency, uint32_t rx_timestamp);

ws_neighbor_temp_class_t *ws_llc_get_multicast_temp_entry(struct net_if *interface, const uint8_t *mac64);

ws_neighbor_temp_class_t *ws_llc_get_eapol_temp_entry(struct net_if *interface, const uint8_t *mac64);



void ws_llc_free_multicast_temp_entry(struct net_if *interface, ws_neighbor_temp_class_t *neighbor);

void ws_llc_set_base_phy_mode_id(struct net_if *interface, uint8_t phy_mode_id);

/**
 * @brief Configure WS POM information (Data of WP_PAYLOAD_IE_POM_TYPE IE element)
 * @param interface Interface pointer
 * @param phy_op_mode_number length of phy_operating_modes
 * @param phy_operating_modes pointer to phy_operating_modes array. This pointer must be kept alive when it is configured to LLC
 *
 */
void ws_llc_set_phy_operating_mode(struct net_if *interface, uint8_t *phy_operating_modes);

int8_t ws_llc_set_mode_switch(struct net_if *interface, int mode, uint8_t phy_mode_id, uint8_t *neighbor_mac_address);

const char *tr_ws_frame(uint8_t frame_type);

typedef struct mcps_data_ind          mcps_data_ind_t;
typedef struct mcps_data_conf         mcps_data_conf_t;
typedef struct mcps_data_conf_payload mcps_data_conf_payload_t;
typedef struct mcps_ack_data_payload  mcps_ack_data_payload_t;
typedef struct mcps_data_ie_list      mcps_data_ie_list_t;

void ws_llc_mac_confirm_cb(int8_t net_if_id, const mcps_data_conf_t *data, const mcps_data_conf_payload_t *conf_data);
void ws_llc_mac_indication_cb(int8_t net_if_id, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext);

#endif
