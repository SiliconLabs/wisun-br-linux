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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/endian.h"
#include "common/string_extra.h"
#include "common/named_values.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "service_libs/random_early_detection/random_early_detection_api.h"
#include "service_libs/etx/etx.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/fhss_ws_extension.h"
#include "stack/ws_management_api.h"

#include "nwk_interface/protocol.h"
#include "security/pana/pana_eap_header.h"
#include "security/eapol/eapol_helper.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_neighbor_class.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_mpx_header.h"
#include "6lowpan/ws/ws_pae_controller.h"
#include "6lowpan/ws/ws_cfg_settings.h"

#include "6lowpan/ws/ws_llc.h"

#define TRACE_GROUP "wllc"

#define LLC_MESSAGE_QUEUE_LIST_SIZE_MAX   16 //Do not config over 30 never
#define MPX_USER_SIZE 2

typedef struct mpx_user {
    uint16_t                user_id;        /**< User ID for identify MPX User */
    mpx_data_confirm        *data_confirm;  /**< User registred MPX Data confirmation call back */
    mpx_data_indication     *data_ind;      /**< User registred MPX Data indication call back */
} mpx_user_t;


typedef struct mpx_class {
    mpx_api_t   mpx_api;                        /**< API for MPX user like Stack and EAPOL */
    mpx_user_t  mpx_user_table[MPX_USER_SIZE];  /**< MPX user list include registered call back pointers and user id's */
    unsigned    mpx_id: 4;                      /**< MPX class sequence number */
} mpx_class_t;


typedef struct llc_ie_params {
    uint16_t                supported_channels;     /**< Configured Channel count. This will define Channel infor mask length to some information element */
    uint16_t                network_name_length;    /**< Network name length */
    uint16_t                vendor_payload_length;  /**< Vendor specific payload length */
    uint8_t                 vendor_header_length;   /**< Vendor specific header length */
    uint8_t                 gtkhash_length;         /**< GTK hash length */
    uint8_t                 phy_op_mode_number;     /**< number of PHY Operating Modes */
    ws_pan_information_t    *pan_configuration;     /**< Pan configururation */
    struct ws_hopping_schedule *hopping_schedule;/**< Channel hopping schedule */
    gtkhash_t               *gtkhash;               /**< Pointer to GTK HASH user must give pointer which include 4 64-bit HASH array */
    uint8_t                 *network_name;          /**< Network name */
    uint8_t                 *vendor_header_data;    /**< Vendor specific header data */
    uint8_t                 *vendor_payload;        /**< Vendor specific payload data */
    uint8_t                 *phy_operating_modes;   /**< PHY Operating Modes */
    /* FAN 1.1 elements */
    ws_nr_ie_t              *node_role;             /**< Node Role */
    ws_lus_ie_t             *lfn_us;                /**< LFN Unicast schedule */
    ws_flus_ie_t            *ffn_lfn_us;            /**< FFN to LFN Unicast schedule */
    ws_lbs_ie_t             *lfn_bs;                /**< LFN Broadcast schedule */
    ws_lnd_ie_t             *lfn_network_discovery; /**< LFN Network Discovery */
    ws_lto_ie_t             *lfn_timing;            /**< LFN Timing */
    ws_panid_ie_t           *pan_id;                /**< PAN ID */
    ws_lbc_ie_t             *lfn_bc;                /**< LFN Broadcast Configuration */
    ws_lcp_ie_t             *lfn_channel_plan;      /**< LCP IE data */
    gtkhash_t               *lgtkhash;              /**< Pointer to LGTK HASH. User must provide a pointer to 3 gtkhash_t */
    ws_lbats_ie_t           *lbats_ie;              /**< LFN Broadcast Additional Transmit Schedule */
} llc_ie_params_t;

/// Enumeration for Mode Switch mode
typedef enum {
    SL_WISUN_MODE_SWITCH_DISABLED     = -1,    /// Mode switch is not allowed
    SL_WISUN_MODE_SWITCH_ENABLED      = 1,     /// Mode switch is allowed for all unicast data frames. PhyModeId is neighbor specific
    SL_WISUN_MODE_SWITCH_DEFAULT      = 0,     /// Mode switch is allowed for all unicast data frames. PhyModeId is global.
} sl_wisun_mode_switch_mode_t;

typedef struct llc_message {
    uint8_t dst_address[8];             /**< Destination address */
    uint16_t pan_id;                    /**< Destination Pan-Id */
    unsigned        message_type: 4;   /**< Frame type to UTT */
    unsigned        mpx_id: 5;          /**< MPX sequence */
    bool            ack_requested: 1;   /**< ACK requested */
    bool            eapol_temporary: 1; /**< EAPOL TX entry index used */
    unsigned        dst_address_type: 2; /**<  Destination address type */
    unsigned        src_address_type: 2; /**<  Source address type */
    uint8_t         msg_handle;         /**< LLC genetaed unique MAC handle */
    uint8_t         mpx_user_handle;    /**< This MPX user defined handle */
    struct iobuf_write ie_buf_header;
    struct iovec    ie_iov_header;
    struct iobuf_write ie_buf_payload;
    struct iovec    ie_iov_payload[2]; // { WP-IE and MPX-IE header, MPX payload }
    mcps_data_req_ie_list_t ie_ext;
    mac_data_priority_e priority;
    ns_list_link_t  link;               /**< List link entry */
} llc_message_t;

typedef NS_LIST_HEAD(llc_message_t, link) llc_message_list_t;

typedef struct temp_entriest {
    ws_neighbor_temp_class_t        neighbour_temporary_table[MAX_NEIGH_TEMPORARY_EAPOL_SIZE];
    ws_neighbor_temp_list_t         active_multicast_temp_neigh;
    ws_neighbor_temp_list_t         active_eapol_temp_neigh;
    ws_neighbor_temp_list_t         free_temp_neigh;
    llc_message_list_t              llc_eap_pending_list;           /**< Active Message list */
    uint16_t                        llc_eap_pending_list_size;      /**< EAPOL active Message list size */
    bool                            active_eapol_session: 1;        /**< Indicating active EAPOL message */
} temp_entriest_t;

/** EDFE response and Enhanced ACK data length */

#define ENHANCED_FRAME_RESPONSE (WH_IE_ELEMENT_HEADER_LENGTH + 2 + WH_IE_ELEMENT_HEADER_LENGTH + 4 + WH_IE_ELEMENT_HEADER_LENGTH + 1 + WH_IE_ELEMENT_HEADER_LENGTH + 5)

typedef struct llc_data_base {
    ns_list_link_t                  link;                           /**< List link entry */

    uint8_t                         mac_handle_base;                /**< Mac handle id base this will be updated by 1 after use */
    uint8_t                         llc_message_list_size;          /**< llc_message_list list size */
    uint16_t                        edfe_rx_wait_timer;
    mpx_class_t                     mpx_data_base;                  /**< MPX data be including USER API Class and user call backs */

    llc_message_list_t              llc_message_list;               /**< Active Message list */
    llc_ie_params_t                 ie_params;                      /**< LLC IE header and Payload data configuration */
    temp_entriest_t                 *temp_entries;

    ws_asynch_ind                   *asynch_ind;                    /**< LLC Asynch data indication call back configured by user */
    ws_asynch_confirm               *asynch_confirm;                /**< LLC Asynch data confirmation call back configured by user */
    ws_neighbor_info_request        *ws_neighbor_info_request_cb;   /**< LLC Neighbour discover API*/
    struct iobuf_write              ws_enhanced_response_elements;
    struct iovec                    ws_header_vector;
    bool                            high_priority_mode;
    uint8_t                         ms_mode;
    uint8_t                         ms_tx_phy_mode_id;
    uint8_t                         base_phy_mode_id;
    struct net_if *interface_ptr;                 /**< List link entry */
} llc_data_base_t;

static NS_LIST_DEFINE(llc_data_base_list, llc_data_base_t, link);

/** LLC message local functions */
static llc_message_t *llc_message_discover_by_mac_handle(uint8_t handle, llc_message_list_t *list);
static llc_message_t *llc_message_discover_by_mpx_id(uint8_t handle, llc_message_list_t *list);
static llc_message_t *llc_message_discover_mpx_user_id(uint8_t handle, uint16_t user_id, llc_message_list_t *list);
static void llc_message_free(llc_message_t *message, llc_data_base_t *llc_base);
static void llc_message_id_allocate(llc_message_t *message, llc_data_base_t *llc_base, bool mpx_user);
static llc_message_t *llc_message_allocate(llc_data_base_t *llc_base);

/** LLC interface sepesific local functions */
static llc_data_base_t *ws_llc_discover_by_interface(struct net_if *interface);
static llc_data_base_t *ws_llc_discover_by_mac(const mac_api_t *api);
static llc_data_base_t *ws_llc_discover_by_mpx(const mpx_api_t *api);

static mpx_user_t *ws_llc_mpx_user_discover(mpx_class_t *mpx_class, uint16_t user_id);
static llc_data_base_t *ws_llc_base_allocate(void);
static void ws_llc_mac_confirm_cb(const mac_api_t *api, const mcps_data_conf_t *data, const mcps_data_conf_payload_t *conf_data);
static void ws_llc_mac_indication_cb(const mac_api_t *api, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext);
static uint16_t ws_mpx_header_size_get(llc_data_base_t *base, uint16_t user_id);
static void ws_llc_mpx_data_request(const mpx_api_t *api, const struct mcps_data_req *data, uint16_t user_id, mac_data_priority_e priority);
static int8_t ws_llc_mpx_data_cb_register(const mpx_api_t *api, mpx_data_confirm *confirm_cb, mpx_data_indication *indication_cb, uint16_t user_id);
static uint16_t ws_llc_mpx_header_size_get(const mpx_api_t *api, uint16_t user_id);
static uint8_t ws_llc_mpx_data_purge_request(const mpx_api_t *api, struct mcps_purge *purge, uint16_t user_id);
static void ws_llc_mpx_init(mpx_class_t *mpx_class);

static void ws_llc_temp_neigh_info_table_reset(temp_entriest_t *base);
#ifndef HAVE_WS_BORDER_ROUTER
static ws_neighbor_temp_class_t *ws_allocate_multicast_temp_entry(temp_entriest_t *base, const uint8_t *mac64);
#endif
static ws_neighbor_temp_class_t *ws_allocate_eapol_temp_entry(temp_entriest_t *base, const uint8_t *mac64);
static void ws_llc_temp_entry_free(temp_entriest_t *base, ws_neighbor_temp_class_t *entry);
static ws_neighbor_temp_class_t *ws_llc_discover_temp_entry(ws_neighbor_temp_list_t *list, const uint8_t *mac64);
static void ws_llc_release_eapol_temp_entry(temp_entriest_t *base, const uint8_t *mac64);
static void ws_llc_rate_handle_tx_conf(llc_data_base_t *base, const mcps_data_conf_t *data, struct mac_neighbor_table_entry *neighbor);


static void ws_llc_mpx_eapol_send(llc_data_base_t *base, llc_message_t *message);

static bool test_skip_first_init_response = false;
static uint8_t test_drop_data_message = 0;


int8_t ws_test_skip_edfe_data_send(int8_t interface_id, bool skip)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur || !ws_info(cur)) {
        return -1;
    }
    test_skip_first_init_response = skip;
    return 0;
}

int8_t  ws_test_drop_edfe_data_frames(int8_t interface_id, uint8_t number_of_dropped_frames)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur || !ws_info(cur)) {
        return -1;
    }
    test_drop_data_message = number_of_dropped_frames;
    return 0;
}

/** Discover Message by message handle id */
static llc_message_t *llc_message_discover_by_mac_handle(uint8_t handle, llc_message_list_t *list)
{
    ns_list_foreach(llc_message_t, message, list) {
        if (message->msg_handle == handle) {
            return message;
        }
    }
    return NULL;
}

static llc_message_t *llc_message_discover_by_mpx_id(uint8_t handle, llc_message_list_t *list)
{
    ns_list_foreach(llc_message_t, message, list) {
        if ((message->message_type == WS_FT_DATA || message->message_type == WS_FT_EAPOL) && message->mpx_id == handle) {
            return message;
        }
    }
    return NULL;
}


static llc_message_t *llc_message_discover_mpx_user_id(uint8_t handle, uint16_t user_id, llc_message_list_t *list)
{
    uint8_t message_type;
    if (user_id == MPX_LOWPAN_ENC_USER_ID) {
        message_type = WS_FT_DATA;
    } else {
        message_type = WS_FT_EAPOL;
    }

    ns_list_foreach(llc_message_t, message, list) {
        if (message->message_type == message_type && message->mpx_user_handle == handle) {
            return message;
        }
    }
    return NULL;
}




//Free message and delete from list
static void llc_message_free(llc_message_t *message, llc_data_base_t *llc_base)
{
    ns_list_remove(&llc_base->llc_message_list, message);
    iobuf_free(&message->ie_buf_header);
    iobuf_free(&message->ie_buf_payload);
    free(message);
    llc_base->llc_message_list_size--;
    random_early_detection_aq_calc(llc_base->interface_ptr->llc_random_early_detection, llc_base->llc_message_list_size);
}

static void llc_message_id_allocate(llc_message_t *message, llc_data_base_t *llc_base, bool mpx_user)
{
    //Guarantee
    while (1) {
        if (llc_message_discover_by_mac_handle(llc_base->mac_handle_base, &llc_base->llc_message_list)) {
            llc_base->mac_handle_base++;
        } else {
            break;
        }
    }
    if (mpx_user) {
        while (1) {
            if (llc_message_discover_by_mpx_id(llc_base->mpx_data_base.mpx_id, &llc_base->llc_message_list)) {
                llc_base->mpx_data_base.mpx_id++;
            } else {
                break;
            }
        }
    }

    //Storage handle and update base
    message->msg_handle = llc_base->mac_handle_base++;
    if (mpx_user) {
        message->mpx_id = llc_base->mpx_data_base.mpx_id++;
    }
}

static llc_message_t *llc_message_allocate(llc_data_base_t *llc_base)
{
    if (llc_base->llc_message_list_size >= LLC_MESSAGE_QUEUE_LIST_SIZE_MAX) {
        return NULL;
    }

    llc_message_t *message = malloc(sizeof(llc_message_t));
    if (!message) {
        return NULL;
    }
    message->ack_requested = false;
    message->eapol_temporary = false;
    message->priority = MAC_DATA_NORMAL_PRIORITY;
    memset(&message->ie_buf_header, 0, sizeof(struct iobuf_write));
    memset(&message->ie_buf_payload, 0, sizeof(struct iobuf_write));
    return message;
}

static llc_data_base_t *ws_llc_discover_by_interface(struct net_if *interface)
{
    ns_list_foreach(llc_data_base_t, base, &llc_data_base_list) {
        if (base->interface_ptr == interface) {
            return base;
        }
    }
    return NULL;
}

static llc_data_base_t *ws_llc_discover_by_mac(const mac_api_t *api)
{
    ns_list_foreach(llc_data_base_t, base, &llc_data_base_list) {
        if (base->interface_ptr->mac_api == api) {
            return base;
        }
    }
    return NULL;
}

static llc_data_base_t *ws_llc_discover_by_mpx(const mpx_api_t *api)
{
    ns_list_foreach(llc_data_base_t, base, &llc_data_base_list) {
        if (&base->mpx_data_base.mpx_api == api) {
            return base;
        }
    }
    return NULL;
}

static inline bool ws_wp_nested_is_empty(wp_nested_ie_sub_list_t requested_list)
{
    return !(requested_list.us_ie
          || requested_list.bs_ie
          || requested_list.vp_ie
          || requested_list.pan_ie
          || requested_list.net_name_ie
          || requested_list.pan_version_ie
          || requested_list.gtkhash_ie
          || requested_list.lgtkhash_ie
          || requested_list.lfnver_ie
          || requested_list.lcp_ie
          || requested_list.lbats_ie
          || requested_list.pom_ie);
}

static mpx_user_t *ws_llc_mpx_user_discover(mpx_class_t *mpx_class, uint16_t user_id)
{
    for (int i = 0; i < MPX_USER_SIZE; i++) {
        if (mpx_class->mpx_user_table[i].user_id == user_id) {
            return &mpx_class->mpx_user_table[i];
        }
    }
    return NULL;
}

static llc_data_base_t *ws_llc_base_allocate(void)
{
    llc_data_base_t *base = malloc(sizeof(llc_data_base_t));
    temp_entriest_t *temp_entries = malloc(sizeof(temp_entriest_t));
    if (!base || !temp_entries) {
        free(base);
        free(temp_entries);
        return NULL;
    }
    memset(base, 0, sizeof(llc_data_base_t));
    memset(temp_entries, 0, sizeof(temp_entriest_t));
    ns_list_init(&temp_entries->active_multicast_temp_neigh);
    ns_list_init(&temp_entries->active_eapol_temp_neigh);
    ns_list_init(&temp_entries->free_temp_neigh);
    ns_list_init(&temp_entries->llc_eap_pending_list);

    //Add to free list to full from static
    for (int i = 0; i < MAX_NEIGH_TEMPORARY_EAPOL_SIZE; i++) {
        ns_list_add_to_end(&temp_entries->free_temp_neigh, &temp_entries->neighbour_temporary_table[i]);
    }
    base->temp_entries = temp_entries;

    ns_list_init(&base->llc_message_list);

    ns_list_add_to_end(&llc_data_base_list, base);
    return base;
}

static void ws_llc_mac_eapol_clear(llc_data_base_t *base)
{
    //Clear active EAPOL Session
    if (base->temp_entries->active_eapol_session) {
        base->temp_entries->active_eapol_session = false;
    }
}


/** WS LLC MAC data extension confirmation  */
static void ws_llc_mac_confirm_cb(const mac_api_t *api, const mcps_data_conf_t *data, const mcps_data_conf_payload_t *conf_data)
{
    (void) conf_data;
    llc_neighbour_req_t neighbor_info = { };
    neighbor_info.ws_neighbor = NULL;
    neighbor_info.neighbor = NULL;
    llc_data_base_t *base = ws_llc_discover_by_mac(api);
    if (!base)
        return;

    struct net_if *interface = base->interface_ptr;
    llc_message_t *message = llc_message_discover_by_mac_handle(data->msduHandle, &base->llc_message_list);
    if (!message)
        return;

    if (message->dst_address_type == MAC_ADDR_MODE_64_BIT)
        base->ws_neighbor_info_request_cb(interface, message->dst_address, &neighbor_info, false);

    if (neighbor_info.neighbor)
        ws_llc_rate_handle_tx_conf(base, data, neighbor_info.neighbor);

    uint8_t message_type = message->message_type;
    uint8_t mpx_user_handle = message->mpx_user_handle;
    if (message->eapol_temporary) {

        if (data->status == MLME_SUCCESS || data->status == MLME_NO_DATA) {
            //Update timeout
            ws_neighbor_temp_class_t *temp_entry = ws_llc_discover_temp_entry(&base->temp_entries->active_eapol_temp_neigh, message->dst_address);
            if (temp_entry) {
                //Update Temporary Lifetime
                temp_entry->eapol_temp_info.eapol_timeout = interface->ws_info->cfg->timing.temp_eapol_min_timeout + 1;
            }
        }
    }
    //ETX update
    if (message->ack_requested && message_type == WS_FT_DATA) {

        bool success = false;

        if (message->dst_address_type == MAC_ADDR_MODE_64_BIT) {
            base->ws_neighbor_info_request_cb(interface, message->dst_address, &neighbor_info, false);
        }
        switch (data->status) {
            case MLME_SUCCESS:
            case MLME_TX_NO_ACK:
            case MLME_NO_DATA:
                if (data->status == MLME_SUCCESS || data->status == MLME_NO_DATA) {
                    success = true;
                }

                if (neighbor_info.ws_neighbor && neighbor_info.neighbor && neighbor_info.neighbor->link_lifetime == WS_NEIGHBOR_LINK_TIMEOUT) {

                    if (!base->high_priority_mode) {
                        //Update ETX only when High priority state is not activated
                        etx_transm_attempts_update(interface->id, 1 + data->tx_retries, success, neighbor_info.neighbor->index, neighbor_info.neighbor->mac64);
                    }
                    ws_utt_ie_t ws_utt;
                    if (ws_wh_utt_read(conf_data->headerIeList, conf_data->headerIeListLength, &ws_utt)) {
                        //UTT header
                        if (success) {
                            neighbor_info.neighbor->lifetime = neighbor_info.neighbor->link_lifetime;
                        }

                        ws_neighbor_class_neighbor_unicast_time_info_update(neighbor_info.ws_neighbor, &ws_utt, data->timestamp, neighbor_info.neighbor->mac64);
                    }

                    int8_t rsl;
                    if (ws_wh_rsl_read(conf_data->headerIeList, conf_data->headerIeListLength, &rsl)) {
                        ws_neighbor_class_rsl_out_calculate(neighbor_info.ws_neighbor, rsl);
                    }
                }

                break;
            default:
                break;
        }

    }
    //Free message
    llc_message_free(message, base);

    if (message_type == WS_FT_DATA || message_type == WS_FT_EAPOL) {
        mpx_user_t *user_cb;
        uint16_t mpx_user_id;
        if (message_type == WS_FT_DATA) {
            mpx_user_id = MPX_LOWPAN_ENC_USER_ID;
        } else {
            mpx_user_id = MPX_KEY_MANAGEMENT_ENC_USER_ID;
            base->temp_entries->active_eapol_session = false;
        }

        user_cb = ws_llc_mpx_user_discover(&base->mpx_data_base, mpx_user_id);
        if (user_cb && user_cb->data_confirm) {
            //Call MPX registered call back
            mcps_data_conf_t data_conf = *data;
            data_conf.msduHandle = mpx_user_handle;
            user_cb->data_confirm(&base->mpx_data_base.mpx_api, &data_conf);
        }

        if (message_type == WS_FT_EAPOL) {
            message = ns_list_get_first(&base->temp_entries->llc_eap_pending_list);
            if (message) {
                //Start A pending EAPOL
                ns_list_remove(&base->temp_entries->llc_eap_pending_list, message);
                base->temp_entries->llc_eap_pending_list_size--;
                random_early_detection_aq_calc(base->interface_ptr->llc_eapol_random_early_detection, base->temp_entries->llc_eap_pending_list_size);
                ws_llc_mpx_eapol_send(base, message);
            }
        } else {
            if (neighbor_info.ws_neighbor && neighbor_info.neighbor && neighbor_info.neighbor->link_lifetime <= WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME) {
                //Remove temp neighbour
                tr_debug("Remove Temp Entry by TX confirm");
                mac_neighbor_table_neighbor_remove(mac_neighbor_info(interface), neighbor_info.neighbor);
            }
        }

        return;
    }
    //Async message Confirmation
    base->asynch_confirm(base->interface_ptr, message_type);

}

static void ws_llc_ack_data_req_ext(const mac_api_t *api, mcps_ack_data_payload_t *data, int8_t rssi, uint8_t lqi)
{
    (void) lqi;
    llc_data_base_t *base = ws_llc_discover_by_mac(api);
    if (!base) {
        return;
    }
    memset(data, 0, sizeof(mcps_ack_data_payload_t));

    iobuf_free(&base->ws_enhanced_response_elements);
    ws_wh_utt_write(&base->ws_enhanced_response_elements, WS_FT_ACK);
    ws_wh_rsl_write(&base->ws_enhanced_response_elements, ws_neighbor_class_rsl_from_dbm_calculate(rssi));
    base->ws_header_vector.iov_base = base->ws_enhanced_response_elements.data;
    base->ws_header_vector.iov_len = base->ws_enhanced_response_elements.len;
    data->ie_elements.headerIeVectorList = &base->ws_header_vector;
    data->ie_elements.headerIovLength = 1;
}


static llc_data_base_t *ws_llc_mpx_frame_common_validates(const mac_api_t *api, const mcps_data_ind_t *data, ws_utt_ie_t ws_utt)
{
    llc_data_base_t *base = ws_llc_discover_by_mac(api);
    if (!base) {
        return NULL;
    }

    if (!base->ie_params.gtkhash && ws_utt.message_type == WS_FT_DATA) {
        return NULL;
    }

    if (data->SrcAddrMode != ADDR_802_15_4_LONG) {
        return NULL;
    }

    struct net_if *interface = base->interface_ptr;

    if (interface->mac_parameters.pan_id != 0xffff && data->SrcPANId != interface->mac_parameters.pan_id) {
        //Drop wrong PAN-id messages in this phase.
        return NULL;
    }

    return base;

}

static mpx_user_t *ws_llc_mpx_header_parse(llc_data_base_t *base, const mcps_data_ie_list_t *ie_ext, mpx_msg_t *mpx_frame)
{
    struct iobuf_read ie_buf;

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_MPX, &ie_buf);
    if (ie_buf.err)
        return NULL;
    if (!ws_llc_mpx_header_frame_parse(ie_buf.data, ie_buf.data_size, mpx_frame))
        return NULL;

    if (mpx_frame->transfer_type != MPX_FT_FULL_FRAME) {
        return NULL; //Support only FULL Frame's
    }

    // Discover MPX handler
    mpx_user_t *user_cb = ws_llc_mpx_user_discover(&base->mpx_data_base, mpx_frame->multiplex_id);
    if (!user_cb || !user_cb->data_ind) {
        return NULL;
    }

    return user_cb;
}


static void ws_llc_data_indication_cb(const mac_api_t *api, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext, ws_utt_ie_t ws_utt)
{
    struct iobuf_read ie_buf;

    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(api, data, ws_utt);
    if (!base) {
        return;
    }

    //Discover MPX header and handler
    mpx_msg_t mpx_frame;
    mpx_user_t *user_cb = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!user_cb) {
        return;
    }

    ws_us_ie_t us_ie;
    bool us_ie_inline = false;
    bool bs_ie_inline = false;
    bool pom_ie_inline = false;
    ws_bs_ie_t ws_bs_ie;
    ws_pom_ie_t pom_ie;
    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, WS_WP_NESTED_IE, &ie_buf);
    us_ie_inline = ws_wp_nested_us_read(ie_buf.data, ie_buf.data_size, &us_ie);
    bs_ie_inline = ws_wp_nested_bs_read(ie_buf.data, ie_buf.data_size, &ws_bs_ie);
    pom_ie_inline = ws_wp_nested_pom_read(ie_buf.data, ie_buf.data_size, &pom_ie);

    struct net_if *interface = base->interface_ptr;

    //Validate Unicast shedule Channel Plan
    if (us_ie_inline &&
            (!ws_bootstrap_validate_channel_plan(&us_ie, NULL, interface) ||
             !ws_bootstrap_validate_channel_function(&us_ie, NULL))) {
        //Channel plan or channel function configuration mismatch
        return;
    }

    if (bs_ie_inline &&
            (!ws_bootstrap_validate_channel_plan(NULL,  &ws_bs_ie, interface) ||
             !ws_bootstrap_validate_channel_function(NULL, &ws_bs_ie))) {
        return;
    }

    //Free Old temporary entry
    if (data->Key.SecurityLevel) {
        ws_llc_release_eapol_temp_entry(base->temp_entries, data->SrcAddr);
    }

    llc_neighbour_req_t neighbor_info;
    bool multicast;
    bool request_new_entry;
    if (data->DstAddrMode == ADDR_802_15_4_LONG) {
        multicast = false;
        request_new_entry = us_ie_inline;
    } else {
        multicast = true;
        request_new_entry = false;
    }

    if (!base->ws_neighbor_info_request_cb(interface, data->SrcAddr, &neighbor_info, request_new_entry)) {
        if (!multicast) {
            //tr_debug("Drop message no neighbor");
            return;
        } else {
#ifndef HAVE_WS_BORDER_ROUTER
            //Allocate temporary entry
            ws_neighbor_temp_class_t *temp_entry = ws_allocate_multicast_temp_entry(base->temp_entries, data->SrcAddr);
            neighbor_info.ws_neighbor = &temp_entry->neigh_info_list;
            //Storage Signal info for future ETX update possibility
            temp_entry->mpduLinkQuality = data->mpduLinkQuality;
            temp_entry->signal_dbm = data->signal_dbm;
#endif
        }
    }

    if (neighbor_info.ws_neighbor) {
        if (!multicast && !data->DSN_suppressed && !ws_neighbor_class_neighbor_duplicate_packet_check(neighbor_info.ws_neighbor, data->DSN, data->timestamp)) {
            tr_info("Drop duplicate message");
            return;
        }

        ws_neighbor_class_neighbor_unicast_time_info_update(neighbor_info.ws_neighbor, &ws_utt, data->timestamp, data->SrcAddr);
        if (us_ie_inline) {
            ws_neighbor_class_neighbor_unicast_schedule_set(interface, neighbor_info.ws_neighbor, &us_ie, data->SrcAddr);
        }
        //Update BS if it is part of message
        if (bs_ie_inline) {
            ws_neighbor_class_neighbor_broadcast_schedule_set(interface, neighbor_info.ws_neighbor, &ws_bs_ie);
        }

        //Update BT if it is part of message
        ws_bt_ie_t ws_bt;
        if (ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_bt)) {
            ws_neighbor_class_neighbor_broadcast_time_info_update(neighbor_info.ws_neighbor, &ws_bt, data->timestamp);
            if (neighbor_info.neighbor && neighbor_info.neighbor->link_role == PRIORITY_PARENT_NEIGHBOUR) {
                ns_fhss_ws_set_parent(interface->ws_info->fhss_api, neighbor_info.neighbor->mac64, &neighbor_info.ws_neighbor->fhss_data.bc_timing_info, false);
            }
        }

        if (data->DstAddrMode == ADDR_802_15_4_LONG) {
            neighbor_info.ws_neighbor->unicast_data_rx = true;
        }

        // Calculate RSL for all UDATA packets heard
        ws_neighbor_class_rf_sensitivity_calculate(interface->ws_info->device_min_sens, data->signal_dbm);
        ws_neighbor_class_rsl_in_calculate(neighbor_info.ws_neighbor, data->signal_dbm);

        if (neighbor_info.neighbor) {
            if (data->Key.SecurityLevel) {
                //SET trusted state
                mac_neighbor_table_trusted_neighbor(mac_neighbor_info(interface), neighbor_info.neighbor, true);
            }
            //
            //Phy CAP info read and store
            if (ws_version_1_1(interface)) {
                if (pom_ie_inline) {
                    mac_neighbor_update_pom(neighbor_info.neighbor, pom_ie.phy_op_mode_number, pom_ie.phy_op_mode_id, pom_ie.mdr_command_capable);
                }
            }
        }
    }

    mcps_data_ind_t data_ind = *data;
    if (!neighbor_info.neighbor) {
        data_ind.Key.SecurityLevel = 0; //Mark unknow device
    }
    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    user_cb->data_ind(&base->mpx_data_base.mpx_api, &data_ind);

}

static void ws_llc_eapol_indication_cb(const mac_api_t *api, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext, ws_utt_ie_t ws_utt)
{
    struct iobuf_read ie_buf;

    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(api, data, ws_utt);
    if (!base) {
        return;
    }

    if (data->DstAddrMode != ADDR_802_15_4_LONG) {
        return;
    }

    //Discover MPX header and handler
    mpx_msg_t mpx_frame;
    mpx_user_t *user_cb = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!user_cb) {
        return;
    }

    ws_us_ie_t us_ie;
    bool us_ie_inline = false;
    bool bs_ie_inline = false;
    ws_bs_ie_t ws_bs_ie;
    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, WS_WP_NESTED_IE, &ie_buf);
    us_ie_inline = ws_wp_nested_us_read(ie_buf.data, ie_buf.data_size, &us_ie);
    bs_ie_inline = ws_wp_nested_bs_read(ie_buf.data, ie_buf.data_size, &ws_bs_ie);

    struct net_if *interface = base->interface_ptr;

    //Validate Unicast shedule Channel Plan
    if (us_ie_inline &&
            (!ws_bootstrap_validate_channel_plan(&us_ie, NULL, interface) ||
             !ws_bootstrap_validate_channel_function(&us_ie, NULL))) {
        //Channel plan or channel function configuration mismatch
        return;
    }

    if (bs_ie_inline &&
            (!ws_bootstrap_validate_channel_plan(NULL,  &ws_bs_ie, interface) ||
             !ws_bootstrap_validate_channel_function(NULL, &ws_bs_ie))) {
        return;
    }

    llc_neighbour_req_t neighbor_info;

    if (!base->ws_neighbor_info_request_cb(interface, data->SrcAddr, &neighbor_info, false)) {
        //Allocate temporary entry
        ws_neighbor_temp_class_t *temp_entry = ws_allocate_eapol_temp_entry(base->temp_entries, data->SrcAddr);
        if (!temp_entry) {
            tr_warn("EAPOL temp pool empty");
            return;
        }
        //Update Temporary Lifetime
        temp_entry->eapol_temp_info.eapol_timeout = interface->ws_info->cfg->timing.temp_eapol_min_timeout + 1;

        neighbor_info.ws_neighbor = &temp_entry->neigh_info_list;
        //Storage Signal info for future ETX update possibility
        temp_entry->mpduLinkQuality = data->mpduLinkQuality;
        temp_entry->signal_dbm = data->signal_dbm;
    }
    uint8_t auth_eui64[8];
    ws_neighbor_class_neighbor_unicast_time_info_update(neighbor_info.ws_neighbor, &ws_utt, data->timestamp, data->SrcAddr);
    if (us_ie_inline) {
        ws_neighbor_class_neighbor_unicast_schedule_set(interface, neighbor_info.ws_neighbor, &us_ie, data->SrcAddr);
    }
    //Update BS if it is part of message
    if (bs_ie_inline) {
        ws_neighbor_class_neighbor_broadcast_schedule_set(interface, neighbor_info.ws_neighbor, &ws_bs_ie);
    }

    //Discover and write Auhtenticator EUI-64
    if (ws_wh_ea_read(ie_ext->headerIeList, ie_ext->headerIeListLength, auth_eui64)) {
        ws_pae_controller_border_router_addr_write(base->interface_ptr, auth_eui64);
    }

    //Update BT if it is part of message
    ws_bt_ie_t ws_bt;
    if (ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_bt)) {
        ws_neighbor_class_neighbor_broadcast_time_info_update(neighbor_info.ws_neighbor, &ws_bt, data->timestamp);
        if (neighbor_info.neighbor) {
            ws_bootstrap_eapol_parent_synch(interface, &neighbor_info);
        }
    }


    mcps_data_ind_t data_ind = *data;
    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    user_cb->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_asynch_indication(const mac_api_t *api, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext, ws_utt_ie_t ws_utt)
{
    struct iobuf_read ie_buf;

    llc_data_base_t *base = ws_llc_discover_by_mac(api);
    if (!base || !base->asynch_ind) {
        return;
    }

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, WS_WP_NESTED_IE, &ie_buf);
    if (ie_buf.err)
        return;

    switch (ws_utt.message_type) {
        case WS_FT_PAN_ADVERT:
        case WS_FT_PAN_CONF:
        case WS_FT_PAN_CONF_SOL:
        case WS_FT_LPA:
        case WS_FT_LPC:
        case WS_FT_LPCS:
            ws_llc_release_eapol_temp_entry(base->temp_entries, data->SrcAddr);
            break;
        default:
            break;
    }

    mcps_data_ie_list_t asynch_ie_list;
    asynch_ie_list.headerIeList = ie_ext->headerIeList,
    asynch_ie_list.headerIeListLength = ie_ext->headerIeListLength;
    // FIXME: Despite the member being called "payloadIeList", we are storing
    // the content of the WP-IE instead.
    asynch_ie_list.payloadIeList       = ie_buf.data;
    asynch_ie_list.payloadIeListLength = ie_buf.data_size;
    base->asynch_ind(base->interface_ptr, data, &asynch_ie_list, ws_utt.message_type);
}

static const struct name_value ws_frames[] = {
    { "adv",       WS_FT_PAN_ADVERT },
    { "adv-sol",   WS_FT_PAN_ADVERT_SOL },
    { "cfg",       WS_FT_PAN_CONF },
    { "cfg-sol",   WS_FT_PAN_CONF_SOL },
    { "data",      WS_FT_DATA },
    { "ack",       WS_FT_ACK },
    { "eapol",     WS_FT_EAPOL },
    { "l-adv",     WS_FT_LPA },
    { "l-adv-sol", WS_FT_LPAS },
    { "l-cfg",     WS_FT_LPC },
    { "l-cfg-sol", WS_FT_LPCS },
    { NULL },
};

static void ws_trace_llc_mac_req(const mcps_data_req_t *data, const llc_message_t *message)
{
    const char *type_str;
    int trace_domain;

    type_str = val_to_str(message->message_type, ws_frames, "[UNK]");
    if (message->message_type == WS_FT_DATA ||
        message->message_type == WS_FT_ACK ||
        message->message_type == WS_FT_EAPOL)
        trace_domain = TR_15_4_DATA;
    else
        trace_domain = TR_15_4_MNGT;
    if (data->DstPANId)
        TRACE(trace_domain, "tx-15.4 %-9s dst:%s panid:%x", type_str, tr_eui64(data->DstAddr), data->DstPANId);
    else
        TRACE(trace_domain, "tx-15.4 %-9s dst:%s", type_str, tr_eui64(data->DstAddr));
}

static void ws_trace_llc_mac_ind(const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext)
{
    const char *type_str;
    ws_lutt_ie_t ws_lutt;
    ws_utt_ie_t ws_utt;
    int message_type;
    int trace_domain;

    if (ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_utt))
        message_type = ws_utt.message_type;
    else if (ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_lutt))
        message_type = ws_lutt.message_type;
    else
        message_type = -1;

    type_str = val_to_str(message_type, ws_frames, "[UNK]");
    if (message_type == WS_FT_DATA ||
        message_type == WS_FT_ACK ||
        message_type == WS_FT_EAPOL)
        trace_domain = TR_15_4_DATA;
    else
        trace_domain = TR_15_4_MNGT;
    if (data->SrcPANId && data->SrcPANId != 0xFFFF)
        TRACE(trace_domain, "rx-15.4 %-9s src:%s panid:%x (%ddBm)", type_str, tr_eui64(data->SrcAddr), data->SrcPANId, data->signal_dbm);
    else
        TRACE(trace_domain, "rx-15.4 %-9s src:%s (%ddBm)", type_str, tr_eui64(data->SrcAddr), data->signal_dbm);
}

/** WS LLC MAC data extension indication  */
static void ws_llc_mac_indication_cb(const mac_api_t *api, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext)
{
    ws_utt_ie_t ws_utt;

    ws_trace_llc_mac_ind(data, ie_ext);

    //Discover Header WH_IE_UTT_TYPE
    if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ws_utt)) {
        // NO UTT header
        return;
    }

    if (ws_utt.message_type < WS_FT_DATA) {
        ws_llc_asynch_indication(api, data, ie_ext, ws_utt);
        return;
    }

    if (ws_utt.message_type == WS_FT_DATA) {
        ws_llc_data_indication_cb(api, data, ie_ext, ws_utt);
        return;
    }

    if (ws_utt.message_type == WS_FT_EAPOL) {
        ws_llc_eapol_indication_cb(api, data, ie_ext, ws_utt);
        return;
    }
}

static uint16_t ws_mpx_header_size_get(llc_data_base_t *base, uint16_t user_id)
{
    //TODO add WS_WP_NESTED_IE support
    uint16_t header_size = 0;
    if (user_id == MPX_LOWPAN_ENC_USER_ID) {
        header_size += 7 + 8 + 5 + 2; //UTT+BTT+ MPX + Padding
        if (base->ie_params.vendor_header_length) {
            header_size += base->ie_params.vendor_header_length + 3;
        }

        if (base->ie_params.vendor_payload_length) {
            header_size += base->ie_params.vendor_payload_length + 2;
        }

        //Dynamic length
        header_size += 2 + WS_WP_SUB_IE_ELEMENT_HEADER_LENGTH + ws_wp_nested_hopping_schedule_length(base->ie_params.hopping_schedule, true) + ws_wp_nested_hopping_schedule_length(base->ie_params.hopping_schedule, false);

    } else if (MPX_KEY_MANAGEMENT_ENC_USER_ID) {
        header_size += 7 + 5 + 2;
        //Dynamic length
        header_size += 2 + WS_WP_SUB_IE_ELEMENT_HEADER_LENGTH + ws_wp_nested_hopping_schedule_length(base->ie_params.hopping_schedule, true);
    }
    return header_size;
}

static bool ws_eapol_handshake_first_msg(uint8_t *pdu, uint16_t length, struct net_if *cur)
{
    if (!ws_eapol_relay_state_active(cur)) {
        return false;
    }

    eapol_pdu_t eapol_pdu;
    uint8_t kmp_type = *pdu++;
    length--;
    if (!eapol_parse_pdu_header(pdu, length, &eapol_pdu)) {
        return false;
    }
    if (eapol_pdu.packet_type == EAPOL_EAP_TYPE) {
        if (eapol_pdu.msg.eap.eap_code == EAP_REQ && eapol_pdu.msg.eap.type == EAP_IDENTITY) {
            return true;
        }
    } else {

        uint8_t key_mask = eapol_pdu_key_mask_get(&eapol_pdu);
        if (kmp_type == 6 && key_mask == KEY_INFO_KEY_ACK) {
            //FWK first message validation
            return true;
        } else if (kmp_type == 7 && key_mask == (KEY_INFO_KEY_ACK | KEY_INFO_KEY_MIC | KEY_INFO_SECURED_KEY_FRAME)) {
            //GWK first message validation
            return true;
        }
    }

    return false;
}

// message->ie_iov_payload[1].iov_len must be set prior to calling this function
static void ws_llc_lowpan_mpx_header_write(llc_message_t *message, uint16_t user_id)
{
    mpx_msg_t mpx_header = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .transaction_id = message->mpx_id,
        .multiplex_id = user_id,
    };
    uint16_t ie_len;
    int ie_offset;

    ie_offset = ieee802154_ie_push_payload(&message->ie_buf_payload, IEEE802154_IE_ID_MPX);
    ws_llc_mpx_header_write(&message->ie_buf_payload, &mpx_header);
    ie_len = message->ie_buf_payload.len - ie_offset - 2 + message->ie_iov_payload[1].iov_len;
    ieee802154_ie_set_len(&message->ie_buf_payload, ie_offset, ie_len, IEEE802154_IE_PAYLOAD_LEN_MASK);
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
}

uint8_t ws_llc_mdr_phy_mode_get(llc_data_base_t *base, const struct mcps_data_req *data)
{

    if (!ws_version_1_1(base->interface_ptr) || !data->TxAckReq || data->msduLength < 500)
        return 0;

    llc_neighbour_req_t neighbor_info;
    uint8_t neighbor_ms_phy_mode_id = 0;

    if (data->TxAckReq &&
        base->ie_params.phy_operating_modes &&
        base->ws_neighbor_info_request_cb(base->interface_ptr, data->DstAddr, &neighbor_info, false)) {
        if (neighbor_info.neighbor->ms_mode == SL_WISUN_MODE_SWITCH_ENABLED)
            neighbor_ms_phy_mode_id = neighbor_info.neighbor->ms_phy_mode_id;
        else if ((neighbor_info.neighbor->ms_mode == SL_WISUN_MODE_SWITCH_DEFAULT) && (base->ms_mode == SL_WISUN_MODE_SWITCH_ENABLED))
            neighbor_ms_phy_mode_id = base->ms_tx_phy_mode_id;
        return mac_neighbor_find_phy_mode_id(neighbor_info.neighbor, neighbor_ms_phy_mode_id);
    }
    return 0;
}

static void ws_llc_lowpan_mpx_data_request(llc_data_base_t *base, mpx_user_t *user_cb, const struct mcps_data_req *data, mac_data_priority_e priority)
{
    int ie_offset;

    //Allocate Message
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        mcps_data_conf_t data_conf;
        memset(&data_conf, 0, sizeof(mcps_data_conf_t));
        data_conf.msduHandle = data->msduHandle;
        data_conf.status = MLME_TRANSACTION_OVERFLOW;
        user_cb->data_confirm(&base->mpx_data_base.mpx_api, &data_conf);
        return;
    }

    //Add To active list
    llc_message_id_allocate(message, base, true);
    base->llc_message_list_size++;
    message->priority = priority;
    random_early_detection_aq_calc(base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);

    mcps_data_req_t data_req;
    uint8_t phy_mode_id = ws_llc_mdr_phy_mode_get(base, data);
    message->mpx_user_handle = data->msduHandle;
    message->ack_requested = data->TxAckReq;
    message->message_type = WS_FT_DATA;
    if (data->TxAckReq) {
        message->dst_address_type = data->DstAddrMode;
        memcpy(message->dst_address, data->DstAddr, 8);
    }
    data_req = *data;
    data_req.msdu = NULL;
    data_req.msduLength = 0;
    data_req.msduHandle = message->msg_handle;

    if (data->ExtendedFrameExchange && data->TxAckReq) {
        data_req.SeqNumSuppressed = true;
        data_req.PanIdSuppressed = true;
        data_req.TxAckReq = true; // This will be changed inside MAC
    } else {
        data_req.ExtendedFrameExchange = false; //Do not accept EDFE for non unicast traffic
        if (!data->TxAckReq) {
            data_req.PanIdSuppressed = false;
            data_req.DstAddrMode = MAC_ADDR_MODE_NONE;
        } else {
            data_req.PanIdSuppressed = true;
        }
    }

    if (data->ExtendedFrameExchange && data->TxAckReq) {
        ws_fc_ie_t fc_ie;
        fc_ie.tx_flow_ctrl = 50;//No data at initial frame
        fc_ie.rx_flow_ctrl = 255;
        //Write Flow control for 1 packet send this will be modified at real data send
        ws_wh_fc_write(&message->ie_buf_header, &fc_ie);
    }
    ws_wh_utt_write(&message->ie_buf_header, message->message_type);
    ws_wh_bt_write(&message->ie_buf_header);
    if (base->ie_params.vendor_header_length)
        ws_wh_vh_write(&message->ie_buf_header, base->ie_params.vendor_header_data, base->ie_params.vendor_header_length);
    message->ie_iov_header.iov_base = message->ie_buf_header.data;
    message->ie_iov_header.iov_len = message->ie_buf_header.len;
    message->ie_ext.headerIeVectorList = &message->ie_iov_header;
    message->ie_ext.headerIovLength = 1;

    ie_offset = ws_wp_base_write(&message->ie_buf_payload);
    ws_wp_nested_hopping_schedule_write(&message->ie_buf_payload, base->ie_params.hopping_schedule, true);
    if (!data->TxAckReq)
        ws_wp_nested_hopping_schedule_write(&message->ie_buf_payload, base->ie_params.hopping_schedule, false);
    // We put only POM-IE if more than 1 phy (base phy + something else)
    if (base->ie_params.phy_operating_modes && base->ie_params.phy_op_mode_number > 1)
        ws_wp_nested_pom_write(&message->ie_buf_payload, base->ie_params.phy_op_mode_number, base->ie_params.phy_operating_modes, 0);

    message->ie_iov_payload[1].iov_base = data->msdu;
    message->ie_iov_payload[1].iov_len = data->msduLength;
    ieee802154_ie_fill_len_payload(&message->ie_buf_payload, ie_offset);
    ws_llc_lowpan_mpx_header_write(message, MPX_LOWPAN_ENC_USER_ID);
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_ext.payloadIeVectorList = message->ie_iov_payload;
    message->ie_ext.payloadIovLength = data->ExtendedFrameExchange ? 0 : 2; // Set Back 2 at response handler

    ws_trace_llc_mac_req(&data_req, message);
    base->interface_ptr->mac_api->mcps_data_req_ext(base->interface_ptr->mac_api, &data_req, &message->ie_ext, NULL, message->priority, phy_mode_id);
}

static void ws_llc_eapol_data_req_init(mcps_data_req_t *data_req, llc_message_t *message)
{
    memset(data_req, 0, sizeof(mcps_data_req_t));
    data_req->TxAckReq = message->ack_requested;
    data_req->DstPANId = message->pan_id;
    data_req->SrcAddrMode = message->src_address_type;
    data_req->ExtendedFrameExchange = false;
    if (!data_req->TxAckReq) {
        data_req->PanIdSuppressed = false;
        data_req->DstAddrMode = MAC_ADDR_MODE_NONE;
    } else {
        data_req->PanIdSuppressed = true;
        data_req->DstAddrMode = message->dst_address_type;
        memcpy(data_req->DstAddr, message->dst_address, 8);
    }


    data_req->msdu = NULL;
    data_req->msduLength = 0;
    data_req->msduHandle = message->msg_handle;

    ws_llc_lowpan_mpx_header_write(message, MPX_KEY_MANAGEMENT_ENC_USER_ID);
}

static void ws_llc_mpx_eapol_send(llc_data_base_t *base, llc_message_t *message)
{
    mcps_data_req_t data_req;

    //Discover Temporary entry
    ws_neighbor_temp_class_t *temp_neigh = ws_llc_discover_temp_entry(&base->temp_entries->active_eapol_temp_neigh, message->dst_address);

    if (temp_neigh) {
        message->eapol_temporary = true;
    } else {
        message->eapol_temporary = false;
    }

    //Allocate message ID
    llc_message_id_allocate(message, base, true);
    base->llc_message_list_size++;
    random_early_detection_aq_calc(base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);
    ws_llc_eapol_data_req_init(&data_req, message);
    base->temp_entries->active_eapol_session = true;

    ws_trace_llc_mac_req(&data_req, message);
    base->interface_ptr->mac_api->mcps_data_req_ext(base->interface_ptr->mac_api, &data_req, &message->ie_ext, NULL, message->priority, 0);
}


static void ws_llc_mpx_eapol_request(llc_data_base_t *base, mpx_user_t *user_cb, const struct mcps_data_req *data, mac_data_priority_e priority)
{
    bool eapol_handshake_first_msg = ws_eapol_handshake_first_msg(data->msdu, data->msduLength, base->interface_ptr);
    int ie_offset;

    //Allocate Message
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        mcps_data_conf_t data_conf;
        memset(&data_conf, 0, sizeof(mcps_data_conf_t));
        data_conf.msduHandle = data->msduHandle;
        data_conf.status = MLME_TRANSACTION_OVERFLOW;
        user_cb->data_confirm(&base->mpx_data_base.mpx_api, &data_conf);
        return;
    }
    message->priority = priority;
    message->mpx_user_handle = data->msduHandle;
    message->ack_requested = data->TxAckReq;

    message->src_address_type = data->SrcAddrMode;
    memcpy(message->dst_address, data->DstAddr, 8);
    message->dst_address_type = data->DstAddrMode;
    message->pan_id = data->DstPANId;
    message->message_type = WS_FT_EAPOL;

    ws_wh_utt_write(&message->ie_buf_header, message->message_type);
    if (ws_eapol_relay_state_active(base->interface_ptr))
        ws_wh_bt_write(&message->ie_buf_header);
    if (eapol_handshake_first_msg) {
        uint8_t eapol_auth_eui64[8];
        ws_pae_controller_border_router_addr_read(base->interface_ptr, eapol_auth_eui64);
        ws_wh_ea_write(&message->ie_buf_header, eapol_auth_eui64);
    }
    message->ie_iov_header.iov_len = message->ie_buf_header.len;
    message->ie_iov_header.iov_base = message->ie_buf_header.data;
    message->ie_ext.headerIeVectorList = &message->ie_iov_header;
    message->ie_ext.headerIovLength = 1;

    ie_offset = ws_wp_base_write(&message->ie_buf_payload);
    ws_wp_nested_hopping_schedule_write(&message->ie_buf_payload, base->ie_params.hopping_schedule, true);
    if (eapol_handshake_first_msg)
        ws_wp_nested_hopping_schedule_write(&message->ie_buf_payload, base->ie_params.hopping_schedule, false);
    ieee802154_ie_fill_len_payload(&message->ie_buf_payload, ie_offset);
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_iov_payload[1].iov_base = data->msdu;
    message->ie_iov_payload[1].iov_len = data->msduLength;
    message->ie_ext.payloadIeVectorList = &message->ie_iov_payload[0];
    message->ie_ext.payloadIovLength = 2;

    if (base->temp_entries->active_eapol_session) {
        //Move to pending list
        ns_list_add_to_end(&base->temp_entries->llc_eap_pending_list, message);
        base->temp_entries->llc_eap_pending_list_size++;
        random_early_detection_aq_calc(base->interface_ptr->llc_eapol_random_early_detection, base->temp_entries->llc_eap_pending_list_size);
    } else {
        ws_llc_mpx_eapol_send(base, message);
    }
}


static void ws_llc_mpx_data_request(const mpx_api_t *api, const struct mcps_data_req *data, uint16_t user_id, mac_data_priority_e priority)
{
    llc_data_base_t *base = ws_llc_discover_by_mpx(api);
    if (!base) {
        return;
    }

    mpx_user_t *user_cb = ws_llc_mpx_user_discover(&base->mpx_data_base, user_id);
    if (!user_cb || !user_cb->data_confirm || !user_cb->data_ind) {
        return;
    }

    if (!base->ie_params.hopping_schedule) {
        tr_error("Missing FHSS configurations");
        mcps_data_conf_t data_conf;
        memset(&data_conf, 0, sizeof(mcps_data_conf_t));
        data_conf.msduHandle = data->msduHandle;
        data_conf.status = MLME_TRANSACTION_OVERFLOW;
        user_cb->data_confirm(&base->mpx_data_base.mpx_api, &data_conf);
        return;
    }

    if (user_id == MPX_KEY_MANAGEMENT_ENC_USER_ID) {
        ws_llc_mpx_eapol_request(base, user_cb, data, priority);
    } else if (user_id == MPX_LOWPAN_ENC_USER_ID) {
        ws_llc_lowpan_mpx_data_request(base, user_cb, data, priority);
    }
}

static void ws_llc_mpx_eui64_purge_request(const mpx_api_t *api, const uint8_t *eui64)
{
    llc_data_base_t *base = ws_llc_discover_by_mpx(api);
    if (!base) {
        return;
    }
    tr_info("LLC purge EAPOL temporary entry: %s", tr_eui64(eui64));
    ws_llc_release_eapol_temp_entry(base->temp_entries, eui64);
}

static int8_t ws_llc_mpx_data_cb_register(const mpx_api_t *api, mpx_data_confirm *confirm_cb, mpx_data_indication *indication_cb, uint16_t user_id)
{
    llc_data_base_t *base = ws_llc_discover_by_mpx(api);
    if (!base) {
        return -1;
    }

    mpx_user_t *user_cb = ws_llc_mpx_user_discover(&base->mpx_data_base, user_id);
    if (!user_cb) {
        return -1;
    }
    user_cb->data_confirm = confirm_cb;
    user_cb->data_ind = indication_cb;
    return 0;
}

static uint16_t ws_llc_mpx_header_size_get(const mpx_api_t *api, uint16_t user_id)
{
    llc_data_base_t *base = ws_llc_discover_by_mpx(api);
    if (!base) {
        return 0;
    }

    return ws_mpx_header_size_get(base, user_id);
}

static uint8_t ws_llc_mpx_data_purge_request(const mpx_api_t *api, struct mcps_purge *purge, uint16_t user_id)
{
    llc_data_base_t *base = ws_llc_discover_by_mpx(api);
    if (!base) {
        return MLME_INVALID_HANDLE;
    }
    llc_message_t *message = llc_message_discover_mpx_user_id(purge->msduHandle, user_id, &base->llc_message_list);
    if (!message) {
        return MLME_INVALID_HANDLE;
    }

    mcps_purge_t purge_req;
    uint8_t purge_status;
    purge_req.msduHandle = message->msg_handle;
    purge_status = base->interface_ptr->mac_api->mcps_purge_req(base->interface_ptr->mac_api, &purge_req);
    if (purge_status == 0) {
        if (message->message_type == WS_FT_EAPOL) {
            ws_llc_mac_eapol_clear(base);
        }
        llc_message_free(message, base);
    }

    return purge_status;
}

static void wc_llc_mpx_priority_set_request(const mpx_api_t *api, bool enable_mode)
{
    llc_data_base_t *base = ws_llc_discover_by_mpx(api);
    if (!base) {
        return;
    }
    base->high_priority_mode = enable_mode;
}

static void ws_llc_mpx_init(mpx_class_t *mpx_class)
{
    //Init Mbed Class and API
    mpx_class->mpx_user_table[0].user_id = MPX_LOWPAN_ENC_USER_ID;
    mpx_class->mpx_user_table[1].user_id = MPX_KEY_MANAGEMENT_ENC_USER_ID;
    mpx_class->mpx_api.mpx_headroom_size_get = &ws_llc_mpx_header_size_get;
    mpx_class->mpx_api.mpx_user_registration = &ws_llc_mpx_data_cb_register;
    mpx_class->mpx_api.mpx_data_request = &ws_llc_mpx_data_request;
    mpx_class->mpx_api.mpx_data_purge = &ws_llc_mpx_data_purge_request;
    mpx_class->mpx_api.mpx_eui64_purge = &ws_llc_mpx_eui64_purge_request;
    mpx_class->mpx_api.mpx_priority_mode_set = &wc_llc_mpx_priority_set_request;
}

static void ws_llc_clean(llc_data_base_t *base)
{
    //Clean Message queue's
    mcps_purge_t purge_req;
    ns_list_foreach_safe(llc_message_t, message, &base->llc_message_list) {
        purge_req.msduHandle = message->msg_handle;
        if (message->message_type == WS_FT_EAPOL) {
            ws_llc_mac_eapol_clear(base);
        }
        llc_message_free(message, base);
        base->interface_ptr->mac_api->mcps_purge_req(base->interface_ptr->mac_api, &purge_req);

    }

    ns_list_foreach_safe(llc_message_t, message, &base->temp_entries->llc_eap_pending_list) {
        ns_list_remove(&base->temp_entries->llc_eap_pending_list, message);
        free(message);
    }
    base->temp_entries->llc_eap_pending_list_size = 0;
    base->temp_entries->active_eapol_session = false;
    memset(&base->ie_params, 0, sizeof(llc_ie_params_t));

    ws_llc_temp_neigh_info_table_reset(base->temp_entries);
    //Disable High Priority mode
    base->high_priority_mode = false;
}

static void ws_llc_temp_entry_free(temp_entriest_t *base, ws_neighbor_temp_class_t *entry)
{
    //Pointer is static add to free list
    if (entry >= &base->neighbour_temporary_table[0] && entry <= &base->neighbour_temporary_table[MAX_NEIGH_TEMPORARY_EAPOL_SIZE - 1]) {
        ns_fhss_ws_drop_neighbor(entry->mac64);
        ns_list_add_to_end(&base->free_temp_neigh, entry);
    }
}


static void ws_llc_temp_neigh_info_table_reset(temp_entriest_t *base)
{
    //Empty active list eapol list
    ns_list_foreach_safe(ws_neighbor_temp_class_t, entry, &base->active_eapol_temp_neigh) {
        ns_list_remove(&base->active_eapol_temp_neigh, entry);
        ws_llc_temp_entry_free(base, entry);
    }

    ns_list_foreach_safe(ws_neighbor_temp_class_t, entry, &base->active_multicast_temp_neigh) {
        ns_list_remove(&base->active_multicast_temp_neigh, entry);
        ws_llc_temp_entry_free(base, entry);
    }
}

static ws_neighbor_temp_class_t *ws_llc_discover_temp_entry(ws_neighbor_temp_list_t *list, const uint8_t *mac64)
{
    ns_list_foreach(ws_neighbor_temp_class_t, entry, list) {
        if (memcmp(entry->mac64, mac64, 8) == 0) {
            return entry;
        }
    }
    return NULL;
}

static void ws_llc_release_eapol_temp_entry(temp_entriest_t *base, const uint8_t *mac64)
{
    ws_neighbor_temp_class_t *neighbor = ws_llc_discover_temp_entry(&base->active_eapol_temp_neigh, mac64);
    if (!neighbor) {
        return;
    }

    ns_list_remove(&base->active_eapol_temp_neigh, neighbor);
    ws_llc_temp_entry_free(base, neighbor);

}

#define MS_FALLBACK_MIN_SAMPLE 50
#define MS_FALLBACK_MAX_SAMPLE 1000
// Mode Switch rate management function
static void ws_llc_rate_handle_tx_conf(llc_data_base_t *base, const mcps_data_conf_t *data, struct mac_neighbor_table_entry *neighbor)
{
    uint8_t i;

    if (data->success_phy_mode_id == base->base_phy_mode_id)
        neighbor->ms_tx_count++;

    if (data->tx_retries) {
        // Look for mode switch retries
        for (i = 0; i < MAX_PHY_MODE_ID_PER_FRAME; i++) {
            if (data->retry_per_rate[i].phy_mode_id == base->base_phy_mode_id) {
                neighbor->ms_retries_count += data->retry_per_rate[i].retries;
            }
        }
    }

    // Mode switch fallback management
    if (neighbor->ms_tx_count + neighbor->ms_retries_count > MS_FALLBACK_MIN_SAMPLE) {
        if (neighbor->ms_retries_count > 4 * neighbor->ms_tx_count) {
            // Fallback: disable mode switch
            base->ms_mode = SL_WISUN_MODE_SWITCH_DISABLED;

            WARN("mode switch disabled for %s with phy_mode_id %d", tr_eui64(neighbor->mac64), neighbor->ms_phy_mode_id);

            neighbor->ms_tx_count = 0;
            neighbor->ms_retries_count = 0;
        }
    }

    if (neighbor->ms_tx_count + neighbor->ms_retries_count > MS_FALLBACK_MAX_SAMPLE) {
        neighbor->ms_tx_count = 0;
        neighbor->ms_retries_count = 0;
    }
}

ws_neighbor_temp_class_t *ws_llc_get_multicast_temp_entry(struct net_if *interface, const uint8_t *mac64)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return NULL;
    }

    return ws_llc_discover_temp_entry(&base->temp_entries->active_multicast_temp_neigh, mac64);
}

ws_neighbor_temp_class_t *ws_llc_get_eapol_temp_entry(struct net_if *interface, const uint8_t *mac64)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return NULL;
    }

    return ws_llc_discover_temp_entry(&base->temp_entries->active_eapol_temp_neigh, mac64);
}


static void ws_init_temporary_neigh_data(ws_neighbor_temp_class_t *entry, const uint8_t *mac64)
{
    //Clear Old data
    memset(&entry->neigh_info_list, 0, sizeof(ws_neighbor_class_entry_t));
    entry->neigh_info_list.rsl_in = RSL_UNITITIALIZED;
    entry->neigh_info_list.rsl_out = RSL_UNITITIALIZED;
    memcpy(entry->mac64, mac64, 8);
    entry->eapol_temp_info.eapol_rx_relay_filter = 0;
}



#ifndef HAVE_WS_BORDER_ROUTER
static ws_neighbor_temp_class_t *ws_allocate_multicast_temp_entry(temp_entriest_t *base, const uint8_t *mac64)
{

    ws_neighbor_temp_class_t *entry = ws_llc_discover_temp_entry(&base->active_multicast_temp_neigh, mac64);
    if (entry) {
        ns_list_remove(&base->active_multicast_temp_neigh, entry);
        ns_list_add_to_start(&base->active_multicast_temp_neigh, entry);
        return entry;
    }

    if (ns_list_count(&base->active_multicast_temp_neigh) < MAX_NEIGH_TEMPORARY_MULTICAST_SIZE) {
        entry = ns_list_get_first(&base->free_temp_neigh);
    }

    if (entry) {
        ns_list_remove(&base->free_temp_neigh, entry);
    } else {
        //Replace last entry and put it to first
        entry = ns_list_get_last(&base->active_multicast_temp_neigh);
        ns_fhss_ws_drop_neighbor(entry->mac64);
        ns_list_remove(&base->active_multicast_temp_neigh, entry);
    }
    //Add to list
    ns_list_add_to_start(&base->active_multicast_temp_neigh, entry);
    //Clear Old data
    ws_init_temporary_neigh_data(entry, mac64);
    return entry;
}
#endif

static ws_neighbor_temp_class_t *ws_allocate_eapol_temp_entry(temp_entriest_t *base, const uint8_t *mac64)
{

    ws_neighbor_temp_class_t *entry = ws_llc_discover_temp_entry(&base->active_eapol_temp_neigh, mac64);
    if (entry) {
        //TODO referesh Timer here
        return entry;
    }

    //Take static if there is still space for multicast
    if (ns_list_count(&base->free_temp_neigh) > (MAX_NEIGH_TEMPORARY_MULTICAST_SIZE - ns_list_count(&base->active_multicast_temp_neigh))) {
        entry = ns_list_get_first(&base->free_temp_neigh);
        ns_list_remove(&base->free_temp_neigh, entry);
    }

    //Add to list
    if (entry) {
        ns_list_add_to_start(&base->active_eapol_temp_neigh, entry);
        //Clear Old data
        ws_init_temporary_neigh_data(entry, mac64);
    }
    return entry;
}

void ws_llc_free_multicast_temp_entry(struct net_if *cur, ws_neighbor_temp_class_t *neighbor)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(cur);
    if (!base) {
        return;
    }
    ns_fhss_ws_drop_neighbor(neighbor->mac64);
    ns_list_remove(&base->temp_entries->active_multicast_temp_neigh, neighbor);
    ns_list_add_to_end(&base->temp_entries->free_temp_neigh, neighbor);
}


static void  ws_llc_build_edfe_response(llc_data_base_t *base, mcps_edfe_response_t *response_message, ws_fc_ie_t fc_ie)
{
    iobuf_free(&base->ws_enhanced_response_elements);
    ws_wh_fc_write(&base->ws_enhanced_response_elements, &fc_ie);
    ws_wh_utt_write(&base->ws_enhanced_response_elements, WS_FT_DATA);
    ws_wh_bt_write(&base->ws_enhanced_response_elements);
    ws_wh_rsl_write(&base->ws_enhanced_response_elements, ws_neighbor_class_rsl_from_dbm_calculate(response_message->rssi));
    base->ws_header_vector.iov_base = base->ws_enhanced_response_elements.data;
    base->ws_header_vector.iov_len = base->ws_enhanced_response_elements.len;

    memset(&response_message->ie_response, 0, sizeof(mcps_data_req_ie_list_t));
    response_message->ie_response.headerIeVectorList = &base->ws_header_vector;
    response_message->ie_response.headerIovLength = 1;
    response_message->SrcAddrMode = MAC_ADDR_MODE_NONE;
    response_message->wait_response = false;
    response_message->PanIdSuppressed = true;
}

static void ws_llc_build_edfe_frame(llc_message_t *message, mcps_edfe_response_t *response_message)
{
    struct iobuf_write ie_buf = { };
    ws_fc_ie_t fc_ie = {
        .tx_flow_ctrl = 0, // Put Data with Handshake
        .rx_flow_ctrl = 255,
    };

    memset(&response_message->ie_response, 0, sizeof(mcps_data_req_ie_list_t));
    //Write Flow control for 1 packet send this will be modified at real data send
    ws_wh_fc_write(&ie_buf, &fc_ie);
    memcpy(message->ie_buf_header.data, ie_buf.data, ie_buf.len);
    iobuf_free(&ie_buf);
    response_message->ie_response.headerIeVectorList = &message->ie_iov_header;
    response_message->ie_response.headerIovLength = 1;
    response_message->ie_response.payloadIeVectorList = &message->ie_iov_payload[0];
    response_message->ie_response.payloadIovLength = 2;
    response_message->SrcAddrMode = MAC_ADDR_MODE_NONE;
    response_message->wait_response = true;
    response_message->PanIdSuppressed = true;
    //tr_debug("FC:Send Data frame");
    response_message->edfe_message_status = MCPS_EDFE_TX_FRAME;
}

static void ws_llc_mcps_edfe_handler(const mac_api_t *api, mcps_edfe_response_t *response_message)
{
    // INSIDE this shuold not print anything
    response_message->edfe_message_status = MCPS_EDFE_NORMAL_FRAME;
    llc_data_base_t *base = ws_llc_discover_by_mac(api);
    if (!base) {
        return;
    }
    //Discover Here header FC-IE element
    ws_fc_ie_t fc_ie;
    if (!ws_wh_fc_read(response_message->ie_elements.headerIeList, response_message->ie_elements.headerIeListLength, &fc_ie)) {
        return;
    }
    //tr_debug("Flow ctrl(%u TX,%u RX)", fc_ie.tx_flow_ctrl, fc_ie.rx_flow_ctrl);
    if (fc_ie.tx_flow_ctrl == 0 && fc_ie.rx_flow_ctrl) {

        llc_message_t *message = NULL;
        if (response_message->use_message_handle_to_discover) {
            message = llc_message_discover_by_mac_handle(response_message->message_handle, &base->llc_message_list);
        }

        if (!message) {
            //tr_debug("FC:Send a Final Frame");
            if (test_drop_data_message) {
                test_drop_data_message--;
                base->edfe_rx_wait_timer += 99;
                response_message->edfe_message_status = MCPS_EDFE_MALFORMED_FRAME;
                return;
            }
            fc_ie.rx_flow_ctrl = 0;
            base->edfe_rx_wait_timer = 0;
            ws_llc_build_edfe_response(base, response_message, fc_ie);
            response_message->edfe_message_status = MCPS_EDFE_FINAL_FRAME_TX;
        } else {
            if (test_skip_first_init_response) {
                //Skip data send and test timeout at Slave side
                test_skip_first_init_response = false;
                response_message->edfe_message_status = MCPS_EDFE_FINAL_FRAME_RX;
                return;
            }
            ws_llc_build_edfe_frame(message, response_message);
        }

    } else if (fc_ie.tx_flow_ctrl == 0 && fc_ie.rx_flow_ctrl == 0) {
        //tr_debug("FC:Received a Final Frame");
        base->edfe_rx_wait_timer = 0;
        response_message->edfe_message_status = MCPS_EDFE_FINAL_FRAME_RX;
    } else if (fc_ie.tx_flow_ctrl && fc_ie.rx_flow_ctrl) {
        base->edfe_rx_wait_timer = fc_ie.tx_flow_ctrl + 99;
        fc_ie.tx_flow_ctrl = 0;
        fc_ie.rx_flow_ctrl = 255;
        //tr_debug("FC:Send a response");
        //Enable or refesh timeout timer
        ws_llc_build_edfe_response(base, response_message, fc_ie);
        response_message->edfe_message_status = MCPS_EDFE_RESPONSE_FRAME;
    }
}

int8_t ws_llc_create(struct net_if *interface, ws_asynch_ind *asynch_ind_cb, ws_asynch_confirm *asynch_cnf_cb, ws_neighbor_info_request *ws_neighbor_info_request_cb)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (base) {
        ws_llc_clean(base);
        return 0;
    }

    //Allocate Data base
    base = ws_llc_base_allocate();
    if (!base) {
        return -2;
    }

    base->interface_ptr = interface;
    base->asynch_ind = asynch_ind_cb;
    base->asynch_confirm = asynch_cnf_cb;
    base->ws_neighbor_info_request_cb = ws_neighbor_info_request_cb;
    //Register MAC Extensions
    base->interface_ptr->mac_api->mac_mcps_extension_enable(base->interface_ptr->mac_api, &ws_llc_mac_indication_cb, &ws_llc_mac_confirm_cb, &ws_llc_ack_data_req_ext);
    base->interface_ptr->mac_api->mac_mcps_edfe_enable(base->interface_ptr->mac_api, &ws_llc_mcps_edfe_handler);
    //Init MPX class
    ws_llc_mpx_init(&base->mpx_data_base);
    ws_llc_temp_neigh_info_table_reset(base->temp_entries);
    return 0;
}

int8_t ws_llc_delete(struct net_if *interface)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return -1;
    }

    ws_llc_clean(base);

    ns_list_remove(&llc_data_base_list, base);
    //Disable Mac extension
    base->interface_ptr->mac_api->mac_mcps_extension_enable(base->interface_ptr->mac_api, NULL, NULL, NULL);
    free(base->temp_entries);
    free(base);
    return 0;
}



void ws_llc_reset(struct net_if *interface)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }
    ws_llc_clean(base);
}

mpx_api_t *ws_llc_mpx_api_get(struct net_if *interface)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return NULL;
    }
    return &base->mpx_data_base.mpx_api;
}

int8_t ws_llc_asynch_request(struct net_if *interface, asynch_request_t *request)
{
    int ie_offset;

    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base || !base->ie_params.hopping_schedule) {
        return -1;
    }

    if (base->high_priority_mode) {
        //Drop asynch messages at High Priority mode
        return -1;
    }

    if (request->message_type == WS_FT_PAN_ADVERT) {
        if (interface->pan_advert_running)
            return -1;
        else
            interface->pan_advert_running = true;
    } else if (request->message_type == WS_FT_PAN_CONF) {
        if (interface->pan_config_running)
            return -1;
        else
            interface->pan_config_running = true;
    }

    //Allocate LLC message pointer
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        if (base->asynch_confirm) {
            base->asynch_confirm(interface, request->message_type);
        }
        return 0;
    }

    //Add To active list
    llc_message_id_allocate(message, base, false);
    base->llc_message_list_size++;
    random_early_detection_aq_calc(base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);
    message->message_type = request->message_type;


    mcps_data_req_t data_req;
    memset(&data_req, 0, sizeof(mcps_data_req_t));
    data_req.SeqNumSuppressed = true;
    data_req.SrcAddrMode = MAC_ADDR_MODE_64_BIT;
    data_req.Key = request->security;
    data_req.msduHandle = message->msg_handle;
    data_req.ExtendedFrameExchange = false;
    if (request->message_type == WS_FT_PAN_ADVERT_SOL) {
        // PANID not know yet must be supressed
        data_req.PanIdSuppressed = true;
    }

    if (request->wh_requested_ie_list.utt_ie)
        ws_wh_utt_write(&message->ie_buf_header, message->message_type);
    if (request->wh_requested_ie_list.bt_ie)
        ws_wh_bt_write(&message->ie_buf_header);
    if (request->wh_requested_ie_list.lutt_ie)
        ws_wh_lutt_write(&message->ie_buf_header, message->message_type);
    if (request->wh_requested_ie_list.lbt_ie)
        ws_wh_lbt_write(&message->ie_buf_header, NULL);
    if (request->wh_requested_ie_list.nr_ie)
        ws_wh_nr_write(&message->ie_buf_header, base->ie_params.node_role);
    if (request->wh_requested_ie_list.lus_ie)
        ws_wh_lus_write(&message->ie_buf_header, base->ie_params.lfn_us);
    if (request->wh_requested_ie_list.flus_ie)
        ws_wh_flus_write(&message->ie_buf_header, base->ie_params.ffn_lfn_us);
    if (request->wh_requested_ie_list.lbs_ie)
        ws_wh_lbs_write(&message->ie_buf_header, base->ie_params.lfn_bs);
    if (request->wh_requested_ie_list.lnd_ie)
        ws_wh_lnd_write(&message->ie_buf_header, base->ie_params.lfn_network_discovery);
    if (request->wh_requested_ie_list.lto_ie)
        ws_wh_lto_write(&message->ie_buf_header, base->ie_params.lfn_timing);
    if (request->wh_requested_ie_list.panid_ie)
        ws_wh_panid_write(&message->ie_buf_header, base->ie_params.pan_id);
    if (request->wh_requested_ie_list.lbc_ie)
        ws_wh_lbc_write(&message->ie_buf_header, base->ie_params.lfn_bc);
    message->ie_iov_header.iov_base = message->ie_buf_header.data;
    message->ie_iov_header.iov_len = message->ie_buf_header.len;
    message->ie_ext.headerIeVectorList = &message->ie_iov_header;
    message->ie_ext.headerIovLength = 1;

    if (!ws_wp_nested_is_empty(request->wp_requested_nested_ie_list)) {
        ie_offset = ws_wp_base_write(&message->ie_buf_payload);
        if (request->wp_requested_nested_ie_list.us_ie)
            ws_wp_nested_hopping_schedule_write(&message->ie_buf_payload, base->ie_params.hopping_schedule, true);
        if (request->wp_requested_nested_ie_list.bs_ie)
            ws_wp_nested_hopping_schedule_write(&message->ie_buf_payload, base->ie_params.hopping_schedule, false);
        if (request->wp_requested_nested_ie_list.pan_ie)
            ws_wp_nested_pan_write(&message->ie_buf_payload, base->ie_params.pan_configuration);
        if (request->wp_requested_nested_ie_list.net_name_ie)
            ws_wp_nested_netname_write(&message->ie_buf_payload, base->ie_params.network_name, base->ie_params.network_name_length);
        if (request->wp_requested_nested_ie_list.pan_version_ie)
            ws_wp_nested_panver_write(&message->ie_buf_payload, base->ie_params.pan_configuration);
        if (request->wp_requested_nested_ie_list.gtkhash_ie)
            ws_wp_nested_gtkhash_write(&message->ie_buf_payload, base->ie_params.gtkhash, base->ie_params.gtkhash_length);
        if (request->wp_requested_nested_ie_list.vp_ie)
            ws_wp_nested_vp_write(&message->ie_buf_payload, base->ie_params.vendor_payload, base->ie_params.vendor_payload_length);
        if (ws_version_1_1(interface)) {
            // We put only POM-IE if more than 1 phy (base phy + something else)
            if (request->wp_requested_nested_ie_list.pom_ie && base->ie_params.phy_operating_modes && base->ie_params.phy_op_mode_number > 1)
                ws_wp_nested_pom_write(&message->ie_buf_payload, base->ie_params.phy_op_mode_number, base->ie_params.phy_operating_modes, 0);
            if (request->wp_requested_nested_ie_list.lcp_ie)
                ws_wp_nested_lcp_write(&message->ie_buf_payload, base->ie_params.lfn_channel_plan);
            if (request->wp_requested_nested_ie_list.lfnver_ie) {
                ws_lfnver_ie_t lfn_ver;
                //Write LFN Version
                lfn_ver.lfn_version = interface->ws_info->pan_information.lpan_version;
                ws_wp_nested_lfnver_write(&message->ie_buf_payload, &lfn_ver);
            }
            if (request->wp_requested_nested_ie_list.lgtkhash_ie)
                ws_wp_nested_lgtkhash_write(&message->ie_buf_payload, base->ie_params.lgtkhash, ws_pae_controller_lgtk_active_index_get(interface));
            if (request->wp_requested_nested_ie_list.lbats_ie)
                ws_wp_nested_lbats_write(&message->ie_buf_payload, base->ie_params.lbats_ie);
        }
        ieee802154_ie_fill_len_payload(&message->ie_buf_payload, ie_offset);
    }
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_ext.payloadIeVectorList = &message->ie_iov_payload[0];
    message->ie_ext.payloadIovLength = 1;

    ws_trace_llc_mac_req(&data_req, message);
    base->interface_ptr->mac_api->mcps_data_req_ext(base->interface_ptr->mac_api, &data_req, &message->ie_ext, &request->channel_list, message->priority, 0);

    return 0;
}

int8_t ws_llc_set_mode_switch(struct net_if *interface, int mode, uint8_t phy_mode_id, uint8_t *neighbor_mac_address)
{
    llc_data_base_t *llc = ws_llc_discover_by_interface(interface);
    llc_neighbour_req_t neighbor_info;
    uint8_t peer_phy_mode_id;
    uint8_t wisun_broadcast_mac_addr[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    neighbor_info.ws_neighbor = NULL;
    neighbor_info.neighbor = NULL;

    if (!llc) // Invalid LLC context
        return -1;

    if (mode != SL_WISUN_MODE_SWITCH_DISABLED &&
        mode != SL_WISUN_MODE_SWITCH_ENABLED &&
        mode != SL_WISUN_MODE_SWITCH_DEFAULT)
        BUG();

    if (mode == SL_WISUN_MODE_SWITCH_ENABLED) {
        bool found = false;
        uint8_t i;

        if (!llc->ie_params.phy_operating_modes)
            return -2;

        // Check Mode Switch PhyModeId is valid in our own phy list
        for (i = 0; i < llc->ie_params.phy_op_mode_number; i++) {
            if (phy_mode_id == llc->ie_params.phy_operating_modes[i]) {
                found = true;
                break;
            }
        }

        if (!found) // Invalid PhyModeId
            return -3;
    }

    if (!memcmp(neighbor_mac_address, wisun_broadcast_mac_addr, 8)) {
        if (mode == SL_WISUN_MODE_SWITCH_DEFAULT)
            return -6;

        // Configure default mode switch rate
        llc->ms_tx_phy_mode_id = phy_mode_id;
        llc->ms_mode = mode;
    } else {
        // Specific neighbor address
        if (llc->ws_neighbor_info_request_cb(llc->interface_ptr, neighbor_mac_address, &neighbor_info, false) == false) {
            // Wrong peer
            return -5;
        } else {
            if (mode == SL_WISUN_MODE_SWITCH_ENABLED) {
                // Check Mode Switch PhyModeId is valid in the neighbor list
                peer_phy_mode_id = mac_neighbor_find_phy_mode_id(neighbor_info.neighbor,
                                                                 phy_mode_id);
                if (peer_phy_mode_id != phy_mode_id) // Invalid PhyModeId
                    return -4;
                neighbor_info.neighbor->ms_phy_mode_id = phy_mode_id;
            } else {
                neighbor_info.neighbor->ms_phy_mode_id = 0;
            }

            neighbor_info.neighbor->ms_mode = mode;

            // Reset counters
            neighbor_info.neighbor->ms_tx_count = 0;
            neighbor_info.neighbor->ms_retries_count = 0;
        }
    }

    return 0;
}

void ws_llc_set_vendor_header_data(struct net_if *interface, uint8_t *vendor_header, uint8_t vendor_header_length)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }
    base->ie_params.vendor_header_data = vendor_header;
    base->ie_params.vendor_header_length = vendor_header_length;
}


void ws_llc_set_vendor_payload_data(struct net_if *interface, uint8_t *vendor_payload, uint8_t vendor_payload_length)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    base->ie_params.vendor_payload = vendor_payload;
    base->ie_params.vendor_payload_length = vendor_payload_length;
}


void ws_llc_set_network_name(struct net_if *interface, uint8_t *name, uint8_t name_length)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    base->ie_params.network_name = name;
    base->ie_params.network_name_length = name_length;
}

void ws_llc_set_gtkhash(struct net_if *interface, gtkhash_t *gtkhash)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    base->ie_params.gtkhash = gtkhash;
    if (base->ie_params.gtkhash) {
        base->ie_params.gtkhash_length = 32;
    } else {
        base->ie_params.gtkhash_length = 0;
    }
}

void ws_llc_set_lgtkhash(struct net_if *interface, gtkhash_t *lgtkhash)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    base->ie_params.lgtkhash = lgtkhash;
}

void ws_llc_set_pan_information_pointer(struct net_if *interface, struct ws_pan_information *pan_information_pointer)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    base->ie_params.pan_configuration = pan_information_pointer;
}

void ws_llc_hopping_schedule_config(struct net_if *interface, struct ws_hopping_schedule *hopping_schedule)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }
    base->ie_params.hopping_schedule = hopping_schedule;
}

void ws_llc_set_phy_operating_mode(struct net_if *interface, uint8_t *phy_operating_modes)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    int i;

    if (!base)
        return;
    base->ie_params.phy_op_mode_number = 0;
    base->ie_params.phy_operating_modes = NULL;
    for (i = 0; phy_operating_modes && phy_operating_modes[i]; i++)
        base->ie_params.phy_op_mode_number++;
    if (base->ie_params.phy_op_mode_number)
        base->ie_params.phy_operating_modes = phy_operating_modes;
}

void ws_llc_fast_timer(struct net_if *interface, uint16_t ticks)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base || !base->edfe_rx_wait_timer) {
        return;
    }

    if (ticks > 0xffff / 100) {
        ticks = 0xffff;
    } else if (ticks == 0) {
        ticks = 1;
    } else {
        ticks *= 100;
    }

    if (base->edfe_rx_wait_timer > ticks) {
        base->edfe_rx_wait_timer -= ticks;
    } else {
        base->edfe_rx_wait_timer = 0;
        tr_debug("EDFE Data Wait Timeout");
        //MAC edfe wait data timeout
        if (interface->mac_api && interface->mac_api->mlme_req) {
            mlme_set_t set_req;
            uint8_t value = 0;
            set_req.attr = macEdfeForceStop;
            set_req.attr_index = 0;
            set_req.value_pointer = &value;
            set_req.value_size = 1;
            interface->mac_api->mlme_req(interface->mac_api, MLME_SET, &set_req);
        }
    }
}

void ws_llc_timer_seconds(struct net_if *interface, uint16_t seconds_update)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    ns_list_foreach_safe(ws_neighbor_temp_class_t, entry, &base->temp_entries->active_eapol_temp_neigh) {
        if (entry->eapol_temp_info.eapol_timeout <= seconds_update) {
            ns_fhss_ws_drop_neighbor(entry->mac64);
            ns_list_remove(&base->temp_entries->active_eapol_temp_neigh, entry);
            ns_list_add_to_end(&base->temp_entries->free_temp_neigh, entry);
        } else {
            entry->eapol_temp_info.eapol_timeout -= seconds_update;
            if (entry->eapol_temp_info.eapol_rx_relay_filter == 0) {
                //No active filter period
                continue;
            }

            //Update filter time
            if (entry->eapol_temp_info.eapol_rx_relay_filter <= seconds_update) {
                entry->eapol_temp_info.eapol_rx_relay_filter = 0;
            } else {
                entry->eapol_temp_info.eapol_rx_relay_filter -= seconds_update;
            }
        }
    }
}

bool ws_llc_eapol_relay_forward_filter(struct net_if *interface, const uint8_t *joiner_eui64, uint8_t mac_sequency, uint32_t rx_timestamp)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return false;
    }

    ws_neighbor_temp_class_t *neighbor = ws_llc_discover_temp_entry(&base->temp_entries->active_eapol_temp_neigh, joiner_eui64);
    if (!neighbor) {
        llc_neighbour_req_t neighbor_info;
        //Discover here Normal Neighbour
        if (!base->ws_neighbor_info_request_cb(interface, joiner_eui64, &neighbor_info, false)) {
            return false;
        }
        return ws_neighbor_class_neighbor_duplicate_packet_check(neighbor_info.ws_neighbor, mac_sequency, rx_timestamp);
    }

    if (neighbor->eapol_temp_info.eapol_rx_relay_filter && neighbor->eapol_temp_info.last_rx_mac_sequency == mac_sequency) {
        return false;
    }
    neighbor->eapol_temp_info.last_rx_mac_sequency = mac_sequency;
    neighbor->eapol_temp_info.eapol_rx_relay_filter = 6; //Activate 5-5.99 seconds filter time
    return true;

}

void ws_llc_set_base_phy_mode_id(struct net_if *interface, uint8_t phy_mode_id)
{
    llc_data_base_t *llc = ws_llc_discover_by_interface(interface);

    if (llc)
        llc->base_phy_mode_id = phy_mode_id;
}


