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
#include "common/utils.h"
#include "common/version.h"
#include "service_libs/random_early_detection/random_early_detection_api.h"
#include "service_libs/etx/etx.h"
#include "stack/mac/mac_common_defines.h"
#include "stack/mac/mac_api.h"
#include "stack/mac/mac_mcps.h"
#include "stack/mac/fhss_ws_extension.h"
#include "stack/ws_management_api.h"
#include "stack/timers.h"

#include "app_wsbrd/wsbr.h"
#include "app_wsbrd/wsbr_mac.h"
#include "app_wsbrd/rcp_api.h"
#include "nwk_interface/protocol.h"
#include "security/pana/pana_eap_header.h"
#include "security/eapol/eapol_helper.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/ws/ws_common_defines.h"
#include "6lowpan/ws/ws_common.h"
#include "6lowpan/ws/ws_bootstrap.h"
#include "6lowpan/ws/ws_bootstrap_ffn.h"
#include "6lowpan/ws/ws_ie_lib.h"
#include "6lowpan/ws/ws_ie_validation.h"
#include "6lowpan/ws/ws_neighbor_class.h"
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
    uint8_t                 gtkhash_length;         /**< GTK hash length */
    uint8_t                 phy_op_mode_number;     /**< number of PHY Operating Modes */
    uint8_t                 *network_name;          /**< Network name */
    uint8_t                 *phy_operating_modes;   /**< PHY Operating Modes */
    /* FAN 1.1 elements */
    ws_lus_ie_t             *lfn_us;                /**< LFN Unicast schedule */
    ws_flus_ie_t            *ffn_lfn_us;            /**< FFN to LFN Unicast schedule */
    ws_lbs_ie_t             *lfn_bs;                /**< LFN Broadcast schedule */
    ws_lnd_ie_t             *lfn_network_discovery; /**< LFN Network Discovery */
    ws_lto_ie_t             *lfn_timing;            /**< LFN Timing */
    ws_panid_ie_t           *pan_id;                /**< PAN ID */
    ws_lcp_ie_t             *lfn_channel_plan;      /**< LCP IE data */
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

typedef struct llc_data_base {
    ns_list_link_t                  link;                           /**< List link entry */

    uint8_t                         mac_handle_base;                /**< Mac handle id base this will be updated by 1 after use */
    uint8_t                         llc_message_list_size;          /**< llc_message_list list size */
    uint16_t                        edfe_rx_wait_timer;
    mpx_class_t                     mpx_data_base;                  /**< MPX data be including USER API Class and user call backs */

    llc_message_list_t              llc_message_list;               /**< Active Message list */
    llc_ie_params_t                 ie_params;                      /**< LLC IE header and Payload data configuration */
    temp_entriest_t                 temp_entries;

    ws_mngt_ind                     *mngt_ind; // indication callback for Wi-SUN management frames (PA/PAS/PC/PCS/LPA/LPAS/LPC/LPCS)
    ws_asynch_confirm               *asynch_confirm;                /**< LLC Asynch data confirmation call back configured by user */
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
static llc_data_base_t *ws_llc_discover_by_interface(const struct net_if *interface);
static llc_data_base_t *ws_llc_discover_by_mpx(const mpx_api_t *api);

static mpx_user_t *ws_llc_mpx_user_discover(mpx_class_t *mpx_class, uint16_t user_id);
static llc_data_base_t *ws_llc_base_allocate(void);
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

static uint8_t ws_llc_get_node_role(struct net_if *interface, const uint8_t eui64[8])
{
    llc_neighbour_req_t neighbor;

    if (ws_bootstrap_neighbor_get(interface, eui64, &neighbor))
        return neighbor.neighbor->node_role;
    else
        return WS_NR_ROLE_UNKNOWN;
}

int8_t ws_test_skip_edfe_data_send(int8_t interface_id, bool skip)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur)
        return -1;
    test_skip_first_init_response = skip;
    return 0;
}

int8_t  ws_test_drop_edfe_data_frames(int8_t interface_id, uint8_t number_of_dropped_frames)
{
    struct net_if *cur = protocol_stack_interface_info_get_by_id(interface_id);
    if (!cur)
        return -1;
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

    llc_message_t *message = calloc(1, sizeof(llc_message_t));
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

static llc_data_base_t *ws_llc_discover_by_interface(const struct net_if *interface)
{
    ns_list_foreach(llc_data_base_t, base, &llc_data_base_list) {
        if (base->interface_ptr == interface) {
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

static inline bool ws_wp_ie_is_empty(struct wp_ie_list wp_ies)
{
    return !(wp_ies.us
          || wp_ies.bs
          || wp_ies.pan
          || wp_ies.netname
          || wp_ies.panver
          || wp_ies.gtkhash
          || wp_ies.lgtkhash
          || wp_ies.lfnver
          || wp_ies.lcp
          || wp_ies.lbats
          || wp_ies.pom);
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
    if (!base) {
        free(base);
        return NULL;
    }
    memset(base, 0, sizeof(llc_data_base_t));
    ns_list_init(&base->temp_entries.active_multicast_temp_neigh);
    ns_list_init(&base->temp_entries.active_eapol_temp_neigh);
    ns_list_init(&base->temp_entries.free_temp_neigh);
    ns_list_init(&base->temp_entries.llc_eap_pending_list);

    //Add to free list to full from static
    for (int i = 0; i < MAX_NEIGH_TEMPORARY_EAPOL_SIZE; i++)
        ns_list_add_to_end(&base->temp_entries.free_temp_neigh,
                           &base->temp_entries.neighbour_temporary_table[i]);

    ns_list_init(&base->llc_message_list);

    ns_list_add_to_end(&llc_data_base_list, base);
    return base;
}

static void ws_llc_mac_eapol_clear(llc_data_base_t *base)
{
    //Clear active EAPOL Session
    if (base->temp_entries.active_eapol_session)
        base->temp_entries.active_eapol_session = false;
}

static void ws_llc_eapol_confirm(struct llc_data_base *base, struct llc_message *msg,
                                 const struct mcps_data_conf *confirm)
{
    struct mcps_data_conf mpx_confirm;
    struct mpx_user *mpx_usr;

    base->temp_entries.active_eapol_session = false;

    mpx_usr = ws_llc_mpx_user_discover(&base->mpx_data_base, MPX_KEY_MANAGEMENT_ENC_USER_ID);
    if (mpx_usr && mpx_usr->data_confirm) {
        mpx_confirm = *confirm;
        mpx_confirm.msduHandle = msg->mpx_user_handle;
        mpx_usr->data_confirm(&base->mpx_data_base.mpx_api, &mpx_confirm);
    }

    msg = ns_list_get_first(&base->temp_entries.llc_eap_pending_list);
    if (msg) {
        ns_list_remove(&base->temp_entries.llc_eap_pending_list, msg);
        base->temp_entries.llc_eap_pending_list_size--;
        random_early_detection_aq_calc(base->interface_ptr->llc_eapol_random_early_detection,
                                       base->temp_entries.llc_eap_pending_list_size);
        ws_llc_mpx_eapol_send(base, msg);
    }
}

static void ws_llc_data_confirm(struct llc_data_base *base, struct llc_message *msg,
                                const struct mcps_data_conf *confirm,
                                const mcps_data_conf_payload_t *confirm_data,
                                struct llc_neighbour_req *neighbor_llc)
{
    const bool success = confirm->status == MLME_SUCCESS || confirm->status == MLME_NO_DATA;
    struct mcps_data_conf mpx_confirm;
    struct mpx_user *mpx_usr;
    struct ws_lutt_ie ie_lutt;
    struct ws_utt_ie ie_utt;
    int8_t ie_rsl;

    if (msg->ack_requested) {
        switch (confirm->status) {
        case MLME_SUCCESS:
        case MLME_TX_NO_ACK:
        case MLME_NO_DATA:
            if (!neighbor_llc->ws_neighbor || !neighbor_llc->neighbor)
                break;
            if (neighbor_llc->neighbor->link_lifetime != WS_NEIGHBOR_LINK_TIMEOUT)
                break;
            if (!base->high_priority_mode)
                etx_transm_attempts_update(base->interface_ptr->id, confirm->tx_retries + 1, success,
                                           neighbor_llc->neighbor->index, neighbor_llc->neighbor->mac64);
            if (ws_wh_utt_read(confirm_data->headerIeList, confirm_data->headerIeListLength, &ie_utt)) {
                if (success)
                    neighbor_llc->neighbor->lifetime = neighbor_llc->neighbor->link_lifetime;
                ws_neighbor_class_ut_update(neighbor_llc->ws_neighbor, ie_utt.ufsi, confirm->timestamp,
                                            neighbor_llc->neighbor->mac64);
            }
            if (ws_wh_lutt_read(confirm_data->headerIeList, confirm_data->headerIeListLength, &ie_lutt)) {
                if (success)
                    neighbor_llc->neighbor->lifetime = neighbor_llc->neighbor->link_lifetime;
                ws_neighbor_class_lut_update(neighbor_llc->ws_neighbor, ie_lutt.slot_number, ie_lutt.interval_offset,
                                             confirm->timestamp, neighbor_llc->neighbor->mac64);
            }
            if (ws_wh_rsl_read(confirm_data->headerIeList, confirm_data->headerIeListLength, &ie_rsl))
                ws_neighbor_class_rsl_out_calculate(neighbor_llc->ws_neighbor, ie_rsl);
            break;
        }
    }

    mpx_usr = ws_llc_mpx_user_discover(&base->mpx_data_base, MPX_LOWPAN_ENC_USER_ID);
    if (mpx_usr && mpx_usr->data_confirm) {
        mpx_confirm = *confirm;
        mpx_confirm.msduHandle = msg->mpx_user_handle;
        mpx_usr->data_confirm(&base->mpx_data_base.mpx_api, &mpx_confirm);
    }

    if (!neighbor_llc->ws_neighbor || !neighbor_llc->neighbor)
        return;
    if (neighbor_llc->neighbor->link_lifetime > WS_NEIGHBOUR_TEMPORARY_NEIGH_MAX_LIFETIME)
        return;

    tr_debug("remove temporary MAC neighbor by TX confirm (%s)", tr_eui64(neighbor_llc->neighbor->mac64));
    mac_neighbor_table_neighbor_remove(base->interface_ptr->mac_parameters.mac_neighbor_table, neighbor_llc->neighbor);
}

void ws_llc_mac_confirm_cb(int8_t net_if_id, const mcps_data_conf_t *data, const mcps_data_conf_payload_t *conf_data)
{
    struct net_if *net_if = protocol_stack_interface_info_get_by_id(net_if_id);
    struct ws_neighbor_temp_class *neighbor_tmp;
    struct llc_neighbour_req neighbor_llc = { };
    struct llc_data_base *base;
    struct llc_message *msg;

    base = ws_llc_discover_by_interface(net_if);
    if (!base)
        return;
    msg = llc_message_discover_by_mac_handle(data->msduHandle, &base->llc_message_list);
    if (!msg)
        return;

    if (msg->dst_address_type == MAC_ADDR_MODE_64_BIT)
        ws_bootstrap_neighbor_get(net_if, msg->dst_address, &neighbor_llc);

    if (neighbor_llc.neighbor)
        ws_llc_rate_handle_tx_conf(base, data, neighbor_llc.neighbor);

    if (msg->eapol_temporary && (data->status == MLME_SUCCESS || data->status == MLME_NO_DATA)) {
        neighbor_tmp = ws_llc_discover_temp_entry(&base->temp_entries.active_eapol_temp_neigh, msg->dst_address);
        if (neighbor_tmp)
            neighbor_tmp->eapol_temp_info.eapol_timeout = net_if->ws_info.cfg->timing.temp_eapol_min_timeout + 1;
    }

    switch (msg->message_type) {
    case WS_FT_DATA:
        ws_llc_data_confirm(base, msg, data, conf_data, &neighbor_llc);
        break;
    case WS_FT_EAPOL:
        ws_llc_eapol_confirm(base, msg, data);
        break;
    case WS_FT_PA:
    case WS_FT_PAS:
    case WS_FT_PC:
    case WS_FT_PCS:
        base->asynch_confirm(net_if, msg->message_type);
        break;
    }

    llc_message_free(msg, base);
}

static llc_data_base_t *ws_llc_mpx_frame_common_validates(const struct net_if *net_if, const mcps_data_ind_t *data, uint8_t frame_type)
{
    struct llc_data_base *base = ws_llc_discover_by_interface(net_if);
    uint16_t pan_id;

    if (!base) {
        return NULL;
    }

    if (data->SrcAddrMode != ADDR_802_15_4_LONG) {
        TRACE(TR_DROP, "drop %-9s: invalid source address mode", tr_ws_frame(frame_type));
        return NULL;
    }

    pan_id = base->interface_ptr->mac_parameters.pan_id;
    if (pan_id != 0xffff && data->SrcPANId != pan_id) {
        TRACE(TR_DROP, "drop %-9s: invalid source PAN ID", tr_ws_frame(frame_type));
        return NULL;
    }

    return base;

}

static mpx_user_t *ws_llc_mpx_header_parse(llc_data_base_t *base, const mcps_data_ie_list_t *ie_ext, mpx_msg_t *mpx_frame)
{
    struct iobuf_read ie_buf;
    struct mpx_user *mpx_usr;

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_MPX, &ie_buf);
    if (ie_buf.err) {
        TRACE(TR_DROP, "drop %-9s: missing MPX-IE", "15.4");
        return NULL;
    }
    if (!ws_llc_mpx_header_frame_parse(ie_buf.data, ie_buf.data_size, mpx_frame)) {
        TRACE(TR_DROP, "drop %-9s: malformed MPX-IE", "15.4");
        return NULL;
    }

    if (mpx_frame->transfer_type != MPX_FT_FULL_FRAME) {
        TRACE(TR_DROP, "drop %-9s: unsupported MPX transfer type", "15.4");
        return NULL;
    }

    // Discover MPX handler
    mpx_usr = ws_llc_mpx_user_discover(&base->mpx_data_base, mpx_frame->multiplex_id);
    if (!mpx_usr || !mpx_usr->data_ind) {
        TRACE(TR_DROP, "drop %-9s: unsupported MPX multiplex ID", "15.4");
        return NULL;
    }

    return mpx_usr;
}

static void ws_llc_data_ffn_ind(const struct net_if *net_if, const mcps_data_ind_t *data,
                                const mcps_data_ie_list_t *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_DATA);
    mcps_data_ind_t data_ind = *data;
    llc_neighbour_req_t neighbor;
    bool has_us, has_bs, has_pom;
    bool req_new_ngb, multicast;
    struct ws_utt_ie ie_utt;
    struct ws_bt_ie ie_bt;
    struct iobuf_read ie_wp;
    struct ws_pom_ie ie_pom;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    mpx_user_t *mpx_user;
    mpx_msg_t mpx_frame;

    if (!base)
        return;
    mpx_user = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!mpx_user)
        return;

    if (data->Key.SecurityLevel != SEC_ENC_MIC64) {
        TRACE(TR_DROP, "drop %-9s: unencrypted frame", tr_ws_frame(WS_FT_DATA));
        return;
    }

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_WP, &ie_wp);
    has_us = ws_wp_nested_us_read(ie_wp.data, ie_wp.data_size, &ie_us);
    has_bs = ws_wp_nested_bs_read(ie_wp.data, ie_wp.data_size, &ie_bs);
    has_pom = ws_wp_nested_pom_read(ie_wp.data, ie_wp.data_size, &ie_pom);

    if (has_us && !ws_ie_validate_us(&base->interface_ptr->ws_info, &ie_us))
        return;
    has_bs = ws_wp_nested_bs_read(ie_wp.data, ie_wp.data_size, &ie_bs);
    if (has_bs && !ws_ie_validate_bs(&base->interface_ptr->ws_info, &ie_bs))
        return;

    if (data->Key.SecurityLevel)
        ws_llc_release_eapol_temp_entry(&base->temp_entries, data->SrcAddr);

    if (data->DstAddrMode == ADDR_802_15_4_LONG) {
        multicast = false;
        req_new_ngb = has_us;
    } else {
        multicast = true;
        req_new_ngb = false;
    }

    if (!ws_bootstrap_neighbor_get(base->interface_ptr, data->SrcAddr, &neighbor) &&
        !(req_new_ngb && ws_bootstrap_neighbor_add(base->interface_ptr, data->SrcAddr, &neighbor, WS_NR_ROLE_ROUTER))) {
        if (!multicast) {
            //tr_debug("Drop message no neighbor");
            return;
        } else {
#ifndef HAVE_WS_BORDER_ROUTER
            ws_neighbor_temp_class_t *tmp = ws_allocate_multicast_temp_entry(&base->temp_entries, data->SrcAddr);

            neighbor.ws_neighbor = &tmp->neigh_info_list;
            tmp->mpduLinkQuality = data->mpduLinkQuality;
            tmp->signal_dbm = data->signal_dbm;
#endif
        }
    }

    if (neighbor.ws_neighbor) {
        if (!multicast && !data->DSN_suppressed &&
            !ws_neighbor_class_neighbor_duplicate_packet_check(neighbor.ws_neighbor, data->DSN, data->timestamp)) {
            tr_info("Drop duplicate message");
            return;
        }

        if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_utt))
            BUG("missing UTT-IE in data frame from FFN");
        ws_neighbor_class_ut_update(neighbor.ws_neighbor, ie_utt.ufsi, data->timestamp, data->SrcAddr);
        if (ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_bt)) {
            ws_neighbor_class_bt_update(neighbor.ws_neighbor, ie_bt.broadcast_slot_number,
                                        ie_bt.broadcast_interval_offset, data->timestamp);
            if (neighbor.neighbor && neighbor.neighbor->link_role == PRIORITY_PARENT_NEIGHBOUR) {
                base->interface_ptr->ws_info.fhss_conf.fhss_bc_dwell_interval = neighbor.ws_neighbor->fhss_data.ffn.bc_dwell_interval_ms;
                base->interface_ptr->ws_info.fhss_conf.fhss_broadcast_interval = neighbor.ws_neighbor->fhss_data.ffn.bc_interval_ms;
                rcp_set_fhss_parent(neighbor.neighbor->mac64, &neighbor.ws_neighbor->fhss_data, false);
            }
        }
        if (has_us)
            ws_neighbor_class_us_update(base->interface_ptr, neighbor.ws_neighbor, &ie_us.chan_plan,
                                        ie_us.dwell_interval, data->SrcAddr);
        if (has_bs)
            ws_neighbor_class_bs_update(base->interface_ptr, neighbor.ws_neighbor, &ie_bs.chan_plan, ie_bs.dwell_interval,
                                        ie_bs.broadcast_interval, ie_bs.broadcast_schedule_identifier);

        if (data->DstAddrMode == ADDR_802_15_4_LONG)
            neighbor.ws_neighbor->unicast_data_rx = true;

        // Calculate RSL for all UDATA packets heard
        ws_neighbor_class_rsl_in_calculate(neighbor.ws_neighbor, data->signal_dbm);

        if (neighbor.neighbor) {
            if (data->Key.SecurityLevel)
                mac_neighbor_table_trusted_neighbor(base->interface_ptr->mac_parameters.mac_neighbor_table, neighbor.neighbor, true);
            if (ws_version_1_1(base->interface_ptr) && has_pom)
                mac_neighbor_update_pom(neighbor.neighbor, ie_pom.phy_op_mode_number,
                                        ie_pom.phy_op_mode_id, ie_pom.mdr_command_capable);
        }
    }

    if (!neighbor.neighbor)
        data_ind.Key.SecurityLevel = 0;
    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_data_lfn_ind(const struct net_if *net_if, const mcps_data_ind_t *data,
                                const mcps_data_ie_list_t *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_DATA);
    mcps_data_ind_t data_ind = *data;
    bool has_lus, has_lcp, has_pom;
    llc_neighbour_req_t neighbor;
    struct ws_lutt_ie ie_lutt;
    struct iobuf_read ie_wp;
    struct ws_lus_ie ie_lus;
    struct ws_lcp_ie ie_lcp;
    struct ws_pom_ie ie_pom;
    mpx_user_t *mpx_user;
    mpx_msg_t mpx_frame;

    if (!base)
        return;
    mpx_user = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!mpx_user)
        return;

    // TODO: Factorize this code with LPCS and EAPOL LFN indication
    has_lus = ws_wh_lus_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lus);
    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_WP, &ie_wp);
    has_pom = ws_wp_nested_pom_read(ie_wp.data, ie_wp.data_size, &ie_pom);
    has_lcp = false;
    if (has_lus && ie_lus.channel_plan_tag != WS_CHAN_PLAN_TAG_CURRENT) {
        has_lcp = ws_wp_nested_lcp_read(ie_ext->headerIeList, ie_ext->headerIeListLength,
                                        ie_lus.channel_plan_tag, &ie_lcp);
        if (!has_lcp) {
            TRACE(TR_DROP, "drop %-9s: missing LCP-IE required by LUS-IE", tr_ws_frame(WS_FT_DATA));
            return;
        }
        if (!ws_ie_validate_lcp(&base->interface_ptr->ws_info, &ie_lcp))
            return;
    }

    if (data->Key.SecurityLevel)
        ws_llc_release_eapol_temp_entry(&base->temp_entries, data->SrcAddr);

    if (!ws_bootstrap_neighbor_get(base->interface_ptr, data->SrcAddr, &neighbor)) {
        TRACE(TR_DROP, "drop %-9s: unknown neighbor %s", tr_ws_frame(WS_FT_DATA), tr_eui64(data->SrcAddr));
        return;
    }

    if (!data->DstAddrMode && !data->DSN_suppressed &&
        !ws_neighbor_class_neighbor_duplicate_packet_check(neighbor.ws_neighbor, data->DSN, data->timestamp)) {
        TRACE(TR_DROP, "drop %-9s: duplicate message", tr_ws_frame(WS_FT_DATA));
        return;
    }

    if (!ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt))
        BUG("Missing LUTT-IE in ULAD frame from LFN");
    ws_neighbor_class_lut_update(neighbor.ws_neighbor, ie_lutt.slot_number, ie_lutt.interval_offset,
                                 data->timestamp, data->SrcAddr);
    if (has_lus)
        ws_neighbor_class_lus_update(base->interface_ptr, neighbor.ws_neighbor,
                                     has_lcp ? &ie_lcp.chan_plan : NULL,
                                     ie_lus.listen_interval);

    if (data->DstAddrMode == ADDR_802_15_4_LONG)
        neighbor.ws_neighbor->unicast_data_rx = true;

    // Calculate RSL for all UDATA packets heard
    ws_neighbor_class_rsl_in_calculate(neighbor.ws_neighbor, data->signal_dbm);

    if (neighbor.neighbor) {
        if (data->Key.SecurityLevel)
            mac_neighbor_table_trusted_neighbor(base->interface_ptr->mac_parameters.mac_neighbor_table, neighbor.neighbor, true);
        if (has_pom)
            mac_neighbor_update_pom(neighbor.neighbor, ie_pom.phy_op_mode_number,
                                    ie_pom.phy_op_mode_id, ie_pom.mdr_command_capable);
        ws_bootstrap_neighbor_set_stable(base->interface_ptr, data->SrcAddr);
    }

    if (!neighbor.neighbor)
        data_ind.Key.SecurityLevel = 0;
    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static bool ws_llc_eapol_neighbor_get(llc_data_base_t *base, const mcps_data_ind_t *data, llc_neighbour_req_t *neighbor)
{
    ws_neighbor_temp_class_t *tmp;

    if (ws_bootstrap_neighbor_get(base->interface_ptr, data->SrcAddr, neighbor))
        return true;

    tmp = ws_allocate_eapol_temp_entry(&base->temp_entries, data->SrcAddr);
    if (!tmp) {
        WARN("EAPOL temporary pool empty");
        return false;
    }

    neighbor->ws_neighbor = &tmp->neigh_info_list;
    tmp->eapol_temp_info.eapol_timeout = base->interface_ptr->ws_info.cfg->timing.temp_eapol_min_timeout + 1;
    tmp->mpduLinkQuality = data->mpduLinkQuality;
    tmp->signal_dbm = data->signal_dbm;
    return true;
}

static void ws_llc_eapol_ffn_ind(const struct net_if *net_if, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_EAPOL);
    mcps_data_ind_t data_ind = *data;
    llc_neighbour_req_t neighbor;
    struct ws_utt_ie ie_utt;
    struct ws_bt_ie ie_bt;
    struct iobuf_read ie_wp;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    uint8_t auth_eui64[8];
    mpx_user_t *mpx_user;
    mpx_msg_t mpx_frame;
    bool has_us, has_bs;

    if (!base)
        return;
    mpx_user = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!mpx_user)
        return;

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_WP, &ie_wp);
    has_us = ws_wp_nested_us_read(ie_wp.data, ie_wp.data_size, &ie_us);
    if (has_us && !ws_ie_validate_us(&base->interface_ptr->ws_info, &ie_us))
        return;
    has_bs = ws_wp_nested_bs_read(ie_wp.data, ie_wp.data_size, &ie_bs);
    if (has_bs && !ws_ie_validate_bs(&base->interface_ptr->ws_info, &ie_bs))
        return;

    if (!ws_llc_eapol_neighbor_get(base, data, &neighbor))
        return;

    if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_utt))
        BUG("missing UTT-IE in EAPOL frame from FFN");
    ws_neighbor_class_ut_update(neighbor.ws_neighbor, ie_utt.ufsi, data->timestamp, data->SrcAddr);
    if (ws_wh_bt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_bt)) {
        ws_neighbor_class_bt_update(neighbor.ws_neighbor, ie_bt.broadcast_slot_number,
                                    ie_bt.broadcast_interval_offset, data->timestamp);
        if (neighbor.neighbor)
            ws_bootstrap_ffn_eapol_parent_synch(base->interface_ptr, &neighbor);
    }
    if (has_us)
        ws_neighbor_class_us_update(base->interface_ptr, neighbor.ws_neighbor, &ie_us.chan_plan,
                                    ie_us.dwell_interval, data->SrcAddr);
    if (has_bs)
        ws_neighbor_class_bs_update(base->interface_ptr, neighbor.ws_neighbor, &ie_bs.chan_plan, ie_bs.dwell_interval,
                                    ie_bs.broadcast_interval, ie_bs.broadcast_schedule_identifier);
    if (ws_wh_ea_read(ie_ext->headerIeList, ie_ext->headerIeListLength, auth_eui64))
        ws_pae_controller_border_router_addr_write(base->interface_ptr, auth_eui64);

    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_eapol_lfn_ind(const struct net_if *net_if, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_EAPOL);
    mcps_data_ind_t data_ind = *data;
    llc_neighbour_req_t neighbor;
    struct ws_lutt_ie ie_lutt;
    struct ws_lus_ie ie_lus;
    struct iobuf_read ie_wp;
    struct ws_lcp_ie ie_lcp;
    bool has_lus, has_lcp;
    mpx_user_t *mpx_user;
    mpx_msg_t mpx_frame;

    if (!base)
        return;
    mpx_user = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!mpx_user)
        return;

    has_lus = ws_wh_lus_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lus);
    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_WP, &ie_wp);
    has_lcp = false;
    // TODO: Factorize this code with LPCS and MPX LFN indication
    if (has_lus && ie_lus.channel_plan_tag != WS_CHAN_PLAN_TAG_CURRENT) {
        has_lcp = ws_wp_nested_lcp_read(ie_ext->headerIeList, ie_ext->headerIeListLength,
                                        ie_lus.channel_plan_tag, &ie_lcp);
        if (!has_lcp) {
            TRACE(TR_DROP, "drop %-9s: missing LCP-IE required by LUS-IE", tr_ws_frame(WS_FT_EAPOL));
            return;
        }
        if (!ws_ie_validate_lcp(&base->interface_ptr->ws_info, &ie_lcp))
            return;
    }

    if (!ws_llc_eapol_neighbor_get(base, data, &neighbor))
        return;

    if (!ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt))
        BUG("Missing LUTT-IE in EAPOL frame from LFN");
    ws_neighbor_class_lut_update(neighbor.ws_neighbor, ie_lutt.slot_number, ie_lutt.interval_offset,
                                 data->timestamp, data->SrcAddr);
    if (has_lus)
        ws_neighbor_class_lus_update(base->interface_ptr, neighbor.ws_neighbor,
                                     has_lcp ? &ie_lcp.chan_plan : NULL,
                                     ie_lus.listen_interval);

    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_mngt_ind(const struct net_if *net_if, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext, uint8_t frame_type)
{
    struct llc_data_base *base = ws_llc_discover_by_interface(net_if);
    struct mcps_data_ie_list ie_list;
    struct iobuf_read ie_buf;

    if (!base || !base->mngt_ind)
        return;

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_WP, &ie_buf);
    if (ie_buf.err) {
        TRACE(TR_DROP, "drop %-9s: missing WP-IE", tr_ws_frame(frame_type));
        return;
    }

    ws_llc_release_eapol_temp_entry(&base->temp_entries, data->SrcAddr);

    ie_list.headerIeList = ie_ext->headerIeList,
    ie_list.headerIeListLength = ie_ext->headerIeListLength;
    // FIXME: Despite the member being called "payloadIeList", we are storing
    // the content of the WP-IE instead.
    ie_list.payloadIeList       = ie_buf.data;
    ie_list.payloadIeListLength = ie_buf.data_size;
    base->mngt_ind(base->interface_ptr, data, &ie_list, frame_type);
}

static const struct name_value ws_frames[] = {
    { "adv",       WS_FT_PA },
    { "adv-sol",   WS_FT_PAS },
    { "cfg",       WS_FT_PC },
    { "cfg-sol",   WS_FT_PCS },
    { "data",      WS_FT_DATA },
    { "ack",       WS_FT_ACK },
    { "eapol",     WS_FT_EAPOL },
    { "l-adv",     WS_FT_LPA },
    { "l-adv-sol", WS_FT_LPAS },
    { "l-cfg",     WS_FT_LPC },
    { "l-cfg-sol", WS_FT_LPCS },
    { "l-tsync",   WS_FT_LTS },
    { NULL },
};

const char *tr_ws_frame(uint8_t type)
{
    return val_to_str(type, ws_frames, "unknown");
}

static void ws_trace_llc_mac_req(const mcps_data_req_t *data, const llc_message_t *message)
{
    const char *type_str;
    int trace_domain;

    type_str = tr_ws_frame(message->message_type);
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

    type_str = tr_ws_frame(message_type);
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

static inline bool ws_is_frame_mngt(uint8_t frame_type)
{
    bool ret = false;

    ret |= frame_type == WS_FT_PA;
    ret |= frame_type == WS_FT_PAS;
    ret |= frame_type == WS_FT_PC;
    ret |= frame_type == WS_FT_PCS;
    ret |= frame_type == WS_FT_LPA;
    ret |= frame_type == WS_FT_LPAS;
    ret |= frame_type == WS_FT_LPC;
    ret |= frame_type == WS_FT_LPCS;
    return ret;
}

/** WS LLC MAC data extension indication  */
void ws_llc_mac_indication_cb(int8_t net_if_id, const mcps_data_ind_t *data, const mcps_data_ie_list_t *ie_ext)
{
    struct net_if *net_if = protocol_stack_interface_info_get_by_id(net_if_id);
    bool has_utt, has_lutt;
    ws_lutt_ie_t ie_lutt;
    ws_utt_ie_t ie_utt;
    uint8_t frame_type;

    ws_trace_llc_mac_ind(data, ie_ext);

    has_utt  = ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_utt);
    has_lutt = ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt);
    if (!has_utt && !has_lutt) {
        TRACE(TR_DROP, "drop %-9s: missing (L)UTT-IE", "15.4");
        return;
    } else if (has_utt && has_lutt) {
        TRACE(TR_DROP, "drop %-9s: both UTT-IE and LUTT-IE present", "15.4");
        return;
    }
    frame_type = has_utt ? ie_utt.message_type : ie_lutt.message_type;

    if (has_lutt && version_older_than(net_if->rcp->version_api, 0, 25, 0)) {
        TRACE(TR_DROP, "drop %-9s: LFN parenting requires RCP API >= 0.23.0", tr_ws_frame(frame_type));
        return;
    }

    if (ws_is_frame_mngt(frame_type)) {
        ws_llc_mngt_ind(net_if, data, ie_ext, frame_type);
    } else if (frame_type == WS_FT_DATA) {
        if (has_utt)
            ws_llc_data_ffn_ind(net_if, data, ie_ext);
        else
            ws_llc_data_lfn_ind(net_if, data, ie_ext);
    } else if (frame_type == WS_FT_EAPOL) {
        if (has_utt)
            ws_llc_eapol_ffn_ind(net_if, data, ie_ext);
        else
            ws_llc_eapol_lfn_ind(net_if, data, ie_ext);
    } else {
        TRACE(TR_DROP, "drop %-9s: unsupported frame type (0x%02x)", "15.4", frame_type);
    }
}

static uint16_t ws_mpx_header_size_get(llc_data_base_t *base, uint16_t user_id)
{
    //TODO add IEEE802154_IE_ID_WP support
    uint16_t header_size = 0;
    if (user_id == MPX_LOWPAN_ENC_USER_ID) {
        header_size += 7 + 8 + 5 + 2; //UTT+BTT+ MPX + Padding

        //Dynamic length
        header_size += 2 + 2 /* WP-IE header */ +
                       ws_wp_nested_hopping_schedule_length(&base->interface_ptr->ws_info.hopping_schedule, true) +
                       ws_wp_nested_hopping_schedule_length(&base->interface_ptr->ws_info.hopping_schedule, false);
    } else if (MPX_KEY_MANAGEMENT_ENC_USER_ID) {
        header_size += 7 + 5 + 2;
        //Dynamic length
        header_size += 2 + 2 /* WP-IE header */ +
                       ws_wp_nested_hopping_schedule_length(&base->interface_ptr->ws_info.hopping_schedule, true);
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
        ws_bootstrap_neighbor_get(base->interface_ptr, data->DstAddr, &neighbor_info)) {
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
    data_req.priority = message->priority;
    data_req.phy_id = ws_llc_mdr_phy_mode_get(base, data);

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
    if (ws_llc_get_node_role(base->interface_ptr, message->dst_address) == WS_NR_ROLE_LFN)
        data_req.fhss_type = data_req.DstAddrMode ? HIF_FHSS_TYPE_LFN_UC : HIF_FHSS_TYPE_LFN_BC;
    else
        data_req.fhss_type = data_req.DstAddrMode ? HIF_FHSS_TYPE_FFN_UC : HIF_FHSS_TYPE_FFN_BC;

    if (data->ExtendedFrameExchange && data->TxAckReq)
        //Write Flow control for 1 packet send this will be modified at real data send
        ws_wh_fc_write(&message->ie_buf_header, 50, 255); // No data at initial frame
    ws_wh_utt_write(&message->ie_buf_header, message->message_type);
    ws_wh_bt_write(&message->ie_buf_header);
    message->ie_iov_header.iov_base = message->ie_buf_header.data;
    message->ie_iov_header.iov_len = message->ie_buf_header.len;
    message->ie_ext.headerIeVectorList = &message->ie_iov_header;
    message->ie_ext.headerIovLength = 1;

    ie_offset = ieee802154_ie_push_payload(&message->ie_buf_payload, IEEE802154_IE_ID_WP);
    ws_wp_nested_us_write(&message->ie_buf_payload, &base->interface_ptr->ws_info.hopping_schedule);
    if (!data->TxAckReq)
        ws_wp_nested_bs_write(&message->ie_buf_payload, &base->interface_ptr->ws_info.hopping_schedule);
    // We put only POM-IE if more than 1 phy (base phy + something else)
    if (ws_version_1_1(base->interface_ptr) &&
        base->ie_params.phy_operating_modes &&
        base->ie_params.phy_op_mode_number > 1)
        ws_wp_nested_pom_write(&message->ie_buf_payload, base->ie_params.phy_op_mode_number,
                               base->ie_params.phy_operating_modes, 0);

    message->ie_iov_payload[1].iov_base = data->msdu;
    message->ie_iov_payload[1].iov_len = data->msduLength;
    ieee802154_ie_fill_len_payload(&message->ie_buf_payload, ie_offset);
    ws_llc_lowpan_mpx_header_write(message, MPX_LOWPAN_ENC_USER_ID);
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_ext.payloadIeVectorList = message->ie_iov_payload;
    message->ie_ext.payloadIovLength = data->ExtendedFrameExchange ? 0 : 2; // Set Back 2 at response handler

    ws_trace_llc_mac_req(&data_req, message);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &message->ie_ext);
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
    data_req->priority = message->priority;
    ws_llc_lowpan_mpx_header_write(message, MPX_KEY_MANAGEMENT_ENC_USER_ID);
}

static void ws_llc_mpx_eapol_send(llc_data_base_t *base, llc_message_t *message)
{
    mcps_data_req_t data_req;

    //Discover Temporary entry
    ws_neighbor_temp_class_t *temp_neigh = ws_llc_discover_temp_entry(&base->temp_entries.active_eapol_temp_neigh, message->dst_address);

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
    base->temp_entries.active_eapol_session = true;
    BUG_ON(data_req.DstAddrMode != MAC_ADDR_MODE_64_BIT); // EAPOL frames are unicast
    if (ws_llc_get_node_role(base->interface_ptr, message->dst_address) == WS_NR_ROLE_LFN)
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_UC;
    else
        data_req.fhss_type = HIF_FHSS_TYPE_FFN_UC;

    ws_trace_llc_mac_req(&data_req, message);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &message->ie_ext);
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

    ie_offset = ieee802154_ie_push_payload(&message->ie_buf_payload, IEEE802154_IE_ID_WP);
    ws_wp_nested_us_write(&message->ie_buf_payload, &base->interface_ptr->ws_info.hopping_schedule);
    if (eapol_handshake_first_msg)
        ws_wp_nested_bs_write(&message->ie_buf_payload, &base->interface_ptr->ws_info.hopping_schedule);
    ieee802154_ie_fill_len_payload(&message->ie_buf_payload, ie_offset);
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_iov_payload[1].iov_base = data->msdu;
    message->ie_iov_payload[1].iov_len = data->msduLength;
    message->ie_ext.payloadIeVectorList = &message->ie_iov_payload[0];
    message->ie_ext.payloadIovLength = 2;

    if (base->temp_entries.active_eapol_session) {
        //Move to pending list
        ns_list_add_to_end(&base->temp_entries.llc_eap_pending_list, message);
        base->temp_entries.llc_eap_pending_list_size++;
        random_early_detection_aq_calc(base->interface_ptr->llc_eapol_random_early_detection, base->temp_entries.llc_eap_pending_list_size);
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
    ws_llc_release_eapol_temp_entry(&base->temp_entries, eui64);
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

    if (version_older_than(g_ctxt.rcp.version_api, 0, 4, 0))
        return MLME_UNSUPPORTED_ATTRIBUTE;
    rcp_tx_drop(message->msg_handle);
    if (message->message_type == WS_FT_EAPOL) {
        ws_llc_mac_eapol_clear(base);
    }
    llc_message_free(message, base);
    return 0;
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
    ns_list_foreach_safe(llc_message_t, message, &base->llc_message_list) {
        if (message->message_type == WS_FT_EAPOL) {
            ws_llc_mac_eapol_clear(base);
        }
        llc_message_free(message, base);
        if (!version_older_than(g_ctxt.rcp.version_api, 0, 4, 0))
            rcp_tx_drop(message->msg_handle);
    }

    ns_list_foreach_safe(llc_message_t, message, &base->temp_entries.llc_eap_pending_list) {
        ns_list_remove(&base->temp_entries.llc_eap_pending_list, message);
        free(message);
    }
    base->temp_entries.llc_eap_pending_list_size = 0;
    base->temp_entries.active_eapol_session = false;
    memset(&base->ie_params, 0, sizeof(llc_ie_params_t));

    ws_llc_temp_neigh_info_table_reset(&base->temp_entries);
    //Disable High Priority mode
    base->high_priority_mode = false;
}

static void ws_llc_temp_entry_free(temp_entriest_t *base, ws_neighbor_temp_class_t *entry)
{
    //Pointer is static add to free list
    if (entry >= &base->neighbour_temporary_table[0] && entry <= &base->neighbour_temporary_table[MAX_NEIGH_TEMPORARY_EAPOL_SIZE - 1]) {
        if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
            rcp_drop_fhss_neighbor(entry->mac64);
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

    return ws_llc_discover_temp_entry(&base->temp_entries.active_multicast_temp_neigh, mac64);
}

ws_neighbor_temp_class_t *ws_llc_get_eapol_temp_entry(struct net_if *interface, const uint8_t *mac64)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return NULL;
    }

    return ws_llc_discover_temp_entry(&base->temp_entries.active_eapol_temp_neigh, mac64);
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
        rcp_drop_fhss_neighbor(entry->mac64);
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
    struct llc_data_base *llc_base = container_of(base, struct llc_data_base, temp_entries);
    struct ws_info *ws_info = &llc_base->interface_ptr->ws_info;

    ws_neighbor_temp_class_t *entry = ws_llc_discover_temp_entry(&base->active_eapol_temp_neigh, mac64);
    if (entry) {
        entry->eapol_temp_info.eapol_timeout = ws_info->cfg->timing.temp_eapol_min_timeout + 1;
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
    if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
        rcp_drop_fhss_neighbor(neighbor->mac64);
    ns_list_remove(&base->temp_entries.active_multicast_temp_neigh, neighbor);
    ns_list_add_to_end(&base->temp_entries.free_temp_neigh, neighbor);
}

int8_t ws_llc_create(struct net_if *interface, ws_mngt_ind *mngt_ind_cb, ws_asynch_confirm *asynch_cnf_cb)
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
    base->mngt_ind = mngt_ind_cb;
    base->asynch_confirm = asynch_cnf_cb;
    //Init MPX class
    ws_llc_mpx_init(&base->mpx_data_base);
    ws_llc_temp_neigh_info_table_reset(&base->temp_entries);
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

// TODO: Factorize this further with EAPOL and MPX requests?
static void ws_llc_prepare_ie(llc_data_base_t *base, llc_message_t *msg,
                              struct wh_ie_list wh_ies, struct wp_ie_list wp_ies)
{
    struct ws_info *info = &base->interface_ptr->ws_info;
    int ie_offset;

    if (wh_ies.utt)
        ws_wh_utt_write(&msg->ie_buf_header, msg->message_type);
    if (wh_ies.bt)
        ws_wh_bt_write(&msg->ie_buf_header);
    if (wh_ies.lutt)
        ws_wh_lutt_write(&msg->ie_buf_header, msg->message_type);
    if (wh_ies.lbt)
        ws_wh_lbt_write(&msg->ie_buf_header, NULL);
    if (wh_ies.nr)
        // TODO: Provide clock drift and timing accuracy
        // TODO: Make the LFN listening interval configurable (currently it is 5s-4.66h)
        ws_wh_nr_write(&msg->ie_buf_header, WS_NR_ROLE_BR, 255, 0, 5000, 1680000);
    if (wh_ies.lus)
        ws_wh_lus_write(&msg->ie_buf_header, base->ie_params.lfn_us);
    if (wh_ies.flus)
        // Only a single chan plan tag is supported. (0)
        ws_wh_flus_write(&msg->ie_buf_header, info->cfg->fhss.fhss_uc_dwell_interval, 0);
    if (wh_ies.lbs)
        // Only a single chan plan tag is supported. (0)
        // TODO: use a separate LFN BSI
        ws_wh_lbs_write(&msg->ie_buf_header, info->cfg->fhss.lfn_bc_interval,
                        info->hopping_schedule.fhss_bsi, 0,
                        info->cfg->fhss.lfn_bc_sync_period);
    if (wh_ies.lnd)
        ws_wh_lnd_write(&msg->ie_buf_header, base->ie_params.lfn_network_discovery);
    if (wh_ies.lto)
        ws_wh_lto_write(&msg->ie_buf_header, base->ie_params.lfn_timing);
    if (wh_ies.panid)
        ws_wh_panid_write(&msg->ie_buf_header, info->network_pan_id);
    if (wh_ies.lbc)
        ws_wh_lbc_write(&msg->ie_buf_header, info->cfg->fhss.lfn_bc_interval,
                        info->cfg->fhss.lfn_bc_sync_period);
    msg->ie_iov_header.iov_base = msg->ie_buf_header.data;
    msg->ie_iov_header.iov_len = msg->ie_buf_header.len;
    msg->ie_ext.headerIeVectorList = &msg->ie_iov_header;
    msg->ie_ext.headerIovLength = 1;

    if (!ws_wp_ie_is_empty(wp_ies)) {
        ie_offset = ieee802154_ie_push_payload(&msg->ie_buf_payload, IEEE802154_IE_ID_WP);
        if (wp_ies.us)
            ws_wp_nested_us_write(&msg->ie_buf_payload, &info->hopping_schedule);
        if (wp_ies.bs)
            ws_wp_nested_bs_write(&msg->ie_buf_payload, &info->hopping_schedule);
        if (wp_ies.pan)
            ws_wp_nested_pan_write(&msg->ie_buf_payload, info->pan_information.pan_size,
                                   info->pan_information.routing_cost, info->pan_information.version);
        if (wp_ies.netname)
            ws_wp_nested_netname_write(&msg->ie_buf_payload, base->ie_params.network_name, base->ie_params.network_name_length);
        if (wp_ies.panver)
            ws_wp_nested_panver_write(&msg->ie_buf_payload, info->pan_information.pan_version);
        if (wp_ies.gtkhash)
            ws_wp_nested_gtkhash_write(&msg->ie_buf_payload, ws_pae_controller_gtk_hash_ptr_get(base->interface_ptr));
        if (ws_version_1_1(base->interface_ptr)) {
            // We put only POM-IE if more than 1 phy (base phy + something else)
            if (wp_ies.pom && base->ie_params.phy_operating_modes && base->ie_params.phy_op_mode_number > 1)
                ws_wp_nested_pom_write(&msg->ie_buf_payload, base->ie_params.phy_op_mode_number, base->ie_params.phy_operating_modes, 0);
            if (wp_ies.lcp)
                // Only unicast schedule using tag 0 is supported
                ws_wp_nested_lcp_write(&msg->ie_buf_payload, 0, &base->interface_ptr->ws_info.hopping_schedule);
            if (wp_ies.lfnver)
                ws_wp_nested_lfnver_write(&msg->ie_buf_payload, info->pan_information.lpan_version);
            if (wp_ies.lgtkhash)
                ws_wp_nested_lgtkhash_write(&msg->ie_buf_payload, ws_pae_controller_lgtk_hash_ptr_get(base->interface_ptr),
                                            ws_pae_controller_lgtk_active_index_get(base->interface_ptr));
            if (wp_ies.lbats)
                ws_wp_nested_lbats_write(&msg->ie_buf_payload, base->ie_params.lbats_ie);
            if (wp_ies.jm && info->pan_information.jm_plf != UINT8_MAX)
                ws_wp_nested_jm_plf_write(&msg->ie_buf_payload, info->pan_information.jm_version, info->pan_information.jm_plf);
        }
        ieee802154_ie_fill_len_payload(&msg->ie_buf_payload, ie_offset);
    }
    msg->ie_iov_payload[0].iov_len = msg->ie_buf_payload.len;
    msg->ie_iov_payload[0].iov_base = msg->ie_buf_payload.data;
    msg->ie_ext.payloadIeVectorList = &msg->ie_iov_payload[0];
    msg->ie_ext.payloadIovLength = 1;
}

int8_t ws_llc_asynch_request(struct net_if *interface, struct ws_llc_mngt_req *request)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base)
        return -1;

    if (base->high_priority_mode) {
        //Drop asynch messages at High Priority mode
        return -1;
    }

    if (request->frame_type == WS_FT_PA) {
        if (interface->pan_advert_running)
            return -1;
        else
            interface->pan_advert_running = true;
    } else if (request->frame_type == WS_FT_PC) {
        if (interface->pan_config_running)
            return -1;
        else
            interface->pan_config_running = true;
    }

    //Allocate LLC message pointer
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        if (base->asynch_confirm) {
            base->asynch_confirm(interface, request->frame_type);
        }
        return 0;
    }

    //Add To active list
    llc_message_id_allocate(message, base, false);
    base->llc_message_list_size++;
    random_early_detection_aq_calc(base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);
    message->message_type = request->frame_type;


    mcps_data_req_t data_req;
    memset(&data_req, 0, sizeof(mcps_data_req_t));
    data_req.SeqNumSuppressed = true;
    data_req.SrcAddrMode = MAC_ADDR_MODE_64_BIT;
    data_req.Key = request->security;
    data_req.msduHandle = message->msg_handle;
    data_req.ExtendedFrameExchange = false;
    if (request->frame_type == WS_FT_PAS)
        data_req.PanIdSuppressed = true;
    data_req.priority = message->priority;
    data_req.fhss_type = HIF_FHSS_TYPE_ASYNC;

    ws_llc_prepare_ie(base, message, request->wh_ies, request->wp_ies);
    ws_trace_llc_mac_req(&data_req, message);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &message->ie_ext);

    return 0;
}

// TODO: Factorize this with MPX and EAPOL
// The Wi-SUN spec uses the term "directed frames" for LPA and LPC, but it
// seems to just mean unicast.
int ws_llc_mngt_lfn_request(struct net_if *interface, const struct ws_llc_mngt_req *req,
                            const uint8_t dst[8], mac_data_priority_e priority)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    mcps_data_req_t data_req = {
        .SeqNumSuppressed = true,
        .PanIdSuppressed  = true,
        .SrcAddrMode = MAC_ADDR_MODE_64_BIT,
        .DstAddrMode = dst ? MAC_ADDR_MODE_64_BIT : MAC_ADDR_MODE_NONE,
        .Key = req->security,
        .priority  = priority,
    };
    llc_message_t *msg;

    if (!base)
        return -1;

    msg = llc_message_allocate(base);
    if (!msg) {
        WARN("%s: tx abort", __func__);
        // FIXME: No confirmation callback
        return 0;
    }

    // Add To active list
    llc_message_id_allocate(msg, base, false);
    base->llc_message_list_size++;
    random_early_detection_aq_calc(interface->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, msg);
    msg->message_type = req->frame_type;
    msg->priority     = priority;

    if (dst)
        memcpy(data_req.DstAddr, dst, sizeof(data_req.DstAddr));
#ifdef HAVE_WS_BORDER_ROUTER
    else if (req->wh_ies.lbt)
        ws_timer_start(WS_TIMER_LTS); // FIXME: This timer should be restarted at confirmation instead
#endif
    if (!dst)
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_BC;
    else if (req->frame_type == WS_FT_LPA)
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_PA;
    else
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_UC;
    data_req.msduHandle = msg->msg_handle;

    ws_llc_prepare_ie(base, msg, req->wh_ies, req->wp_ies);
    ws_trace_llc_mac_req(&data_req, msg);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &msg->ie_ext);
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
        if (!ws_bootstrap_neighbor_get(llc->interface_ptr, neighbor_mac_address, &neighbor_info)) {
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

void ws_llc_set_network_name(struct net_if *interface, uint8_t *name, uint8_t name_length)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    base->ie_params.network_name = name;
    base->ie_params.network_name_length = name_length;
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
        rcp_abort_edfe();
    }
}

void ws_llc_timer_seconds(struct net_if *interface, uint16_t seconds_update)
{
    llc_data_base_t *base = ws_llc_discover_by_interface(interface);
    if (!base) {
        return;
    }

    ns_list_foreach_safe(ws_neighbor_temp_class_t, entry, &base->temp_entries.active_eapol_temp_neigh) {
        if (entry->eapol_temp_info.eapol_timeout <= seconds_update) {
            if (version_older_than(g_ctxt.rcp.version_api, 0, 25, 0))
                rcp_drop_fhss_neighbor(entry->mac64);
            ns_list_remove(&base->temp_entries.active_eapol_temp_neigh, entry);
            ns_list_add_to_end(&base->temp_entries.free_temp_neigh, entry);
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

    ws_neighbor_temp_class_t *neighbor = ws_llc_discover_temp_entry(&base->temp_entries.active_eapol_temp_neigh, joiner_eui64);
    if (!neighbor) {
        llc_neighbour_req_t neighbor_info;
        //Discover here Normal Neighbour
        if (!ws_bootstrap_neighbor_get(interface, joiner_eui64, &neighbor_info))
            return false;
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


