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
#include <inttypes.h>
#include <errno.h>
#include <math.h>
#include "common/log.h"
#include "common/bits.h"
#include "common/endian.h"
#include "common/string_extra.h"
#include "common/named_values.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/ieee802154_ie.h"
#include "common/iobuf.h"
#include "common/time_extra.h"
#include "common/mathutils.h"
#include "common/memutils.h"
#include "common/mpx.h"
#include "common/ws_regdb.h"
#include "common/version.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ieee802159.h"
#include "common/specs/ws.h"
#include "common/random_early_detection.h"
#include "common/ws_ie.h"

#include "app/wsbrd.h"
#include "app/wsbr_mac.h"
#include "app/rcp_api_legacy.h"
#include "net/timers.h"
#include "net/protocol.h"
#include "security/pana/pana_eap_header.h"
#include "security/eapol/eapol_helper.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "ws/ws_common.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_ie_validation.h"
#include "ws/ws_pae_controller.h"

#include "ws/ws_llc.h"

#define TRACE_GROUP "wllc"

#define LLC_MESSAGE_QUEUE_LIST_SIZE_MAX   16 //Do not config over 30 never
#define MPX_USER_SIZE 2

#define TX_CONFIRM_EXTENSIVE_FFN_SEC 5
#define TX_CONFIRM_EXTENSIVE_LFN_MULTIPLIER 3

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
    uint8_t                 gtkhash_length;         /**< GTK hash length */
    /* FAN 1.1 elements */
    struct ws_lus_ie        *lfn_us;                /**< LFN Unicast schedule */
    struct ws_flus_ie       *ffn_lfn_us;            /**< FFN to LFN Unicast schedule */
    struct ws_lbs_ie        *lfn_bs;                /**< LFN Broadcast schedule */
    struct ws_lnd_ie        *lfn_network_discovery; /**< LFN Network Discovery */
    struct ws_lto_ie        *lfn_timing;            /**< LFN Timing */
    struct ws_panid_ie      *pan_id;                /**< PAN ID */
    struct ws_lcp_ie        *lfn_channel_plan;      /**< LCP IE data */
    struct ws_lbats_ie      *lbats_ie;              /**< LFN Broadcast Additional Transmit Schedule */
} llc_ie_params_t;

// FIXME: This contains many redundant information with mcps_data_req_t.
typedef struct llc_message {
    uint8_t dst_address[8];             /**< Destination address */
    uint16_t pan_id;                    /**< Destination Pan-Id */
    unsigned        message_type: 4;   /**< Frame type to UTT */
    unsigned        mpx_id: 5;          /**< MPX sequence */
    bool            ack_requested: 1;   /**< ACK requested */
    unsigned        dst_address_type: 2; /**<  Destination address type */
    unsigned        src_address_type: 2; /**<  Source address type */
    uint8_t         msg_handle;         /**< LLC genetaed unique MAC handle */
    uint8_t         mpx_user_handle;    /**< This MPX user defined handle */
    struct iobuf_write ie_buf_header;
    struct iovec    ie_iov_header;
    struct iobuf_write ie_buf_payload;
    struct iovec    ie_iov_payload[2]; // { WP-IE and MPX-IE header, MPX payload }
    mcps_data_req_ie_list_t ie_ext;
    time_t tx_time;
    struct mlme_security security;
    struct rcp_rate_info rate_list[4];
    ns_list_link_t  link;               /**< List link entry */
} llc_message_t;

typedef NS_LIST_HEAD(llc_message_t, link) llc_message_list_t;

typedef struct temp_entriest {
    llc_message_list_t              llc_eap_pending_list;           /**< Active Message list */
    uint16_t                        llc_eap_pending_list_size;      /**< EAPOL active Message list size */
    bool                            active_eapol_session: 1;        /**< Indicating active EAPOL message */
} temp_entriest_t;

/** EDFE response and Enhanced ACK data length */

typedef struct llc_data_base {
    ns_list_link_t                  link;                           /**< List link entry */

    uint8_t                         mac_handle_base;                /**< Mac handle id base this will be updated by 1 after use */
    uint8_t                         llc_message_list_size;          /**< llc_message_list list size */
    mpx_class_t                     mpx_data_base;                  /**< MPX data be including USER API Class and user call backs */

    llc_message_list_t              llc_message_list;               /**< Active Message list */
    llc_ie_params_t                 ie_params;                      /**< LLC IE header and Payload data configuration */
    temp_entriest_t                 temp_entries;

    ws_llc_mngt_ind_cb              *mngt_ind;                      /* Called when Wi-SUN management frame (PA/PAS/PC/PCS/LPA/LPAS/LPC/LPCS) is received */
    ws_llc_mngt_cnf_cb              *mngt_cnf;                      /* Called when RCP confirms transmission of a Wi-SUN management frame (PA/PAS/PC/PCS/LPA/LPAS/LPC/LPCS) */
    struct iobuf_write              ws_enhanced_response_elements;
    struct iovec                    ws_header_vector;
    bool                            high_priority_mode;
    struct net_if *interface_ptr;                 /**< List link entry */
} llc_data_base_t;

static llc_data_base_t g_llc_base;

/** LLC message local functions */
static llc_message_t *llc_message_discover_by_mac_handle(uint8_t handle, llc_message_list_t *list);
static llc_message_t *llc_message_discover_by_mpx_id(uint8_t handle, llc_message_list_t *list);
static void llc_message_free(llc_message_t *message, llc_data_base_t *llc_base);
static void llc_message_id_allocate(llc_message_t *message, llc_data_base_t *llc_base, bool mpx_user);
static llc_message_t *llc_message_allocate(llc_data_base_t *llc_base);

static mpx_user_t *ws_llc_mpx_user_discover(mpx_class_t *mpx_class, uint16_t user_id);
static uint16_t ws_mpx_header_size_get(llc_data_base_t *base, uint16_t user_id);
static void ws_llc_mpx_data_request(const mpx_api_t *api, const struct mcps_data_req *data, uint16_t user_id);
static int8_t ws_llc_mpx_data_cb_register(const mpx_api_t *api, mpx_data_confirm *confirm_cb, mpx_data_indication *indication_cb, uint16_t user_id);
static uint16_t ws_llc_mpx_header_size_get(const mpx_api_t *api, uint16_t user_id);
static void ws_llc_mpx_init(mpx_class_t *mpx_class);

static void ws_llc_rate_handle_tx_conf(llc_data_base_t *base, const mcps_data_cnf_t *data, struct ws_neigh *neighbor);


static void ws_llc_mpx_eapol_send(llc_data_base_t *base, llc_message_t *message);

static uint8_t ws_llc_get_node_role(struct net_if *interface, const uint8_t eui64[8])
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, eui64);

    if (ws_neigh)
        return ws_neigh->node_role;
    else
        return WS_NR_ROLE_UNKNOWN;
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

//Free message and delete from list
static void llc_message_free(llc_message_t *message, llc_data_base_t *llc_base)
{
    ns_list_remove(&llc_base->llc_message_list, message);
    iobuf_free(&message->ie_buf_header);
    iobuf_free(&message->ie_buf_payload);
    free(message);
    llc_base->llc_message_list_size--;
    red_aq_calc(&llc_base->interface_ptr->llc_random_early_detection, llc_base->llc_message_list_size);
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
    memset(&message->ie_buf_header, 0, sizeof(struct iobuf_write));
    memset(&message->ie_buf_payload, 0, sizeof(struct iobuf_write));
    return message;
}

static inline bool ws_wp_ie_is_empty(const struct wp_ie_list *wp_ies)
{
    return !(wp_ies->us
          || wp_ies->bs
          || wp_ies->pan
          || wp_ies->netname
          || wp_ies->panver
          || wp_ies->gtkhash
          || wp_ies->lgtkhash
          || wp_ies->lfnver
          || wp_ies->lcp
          || wp_ies->lbats
          || wp_ies->pom);
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

static void ws_llc_mac_eapol_clear(llc_data_base_t *base)
{
    //Clear active EAPOL Session
    if (base->temp_entries.active_eapol_session)
        base->temp_entries.active_eapol_session = false;
}

static void ws_llc_eapol_confirm(struct llc_data_base *base, struct llc_message *msg,
                                 const struct mcps_data_cnf *confirm)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&base->interface_ptr->ws_info.neighbor_storage, msg->dst_address);
    struct mcps_data_cnf mpx_confirm;
    struct mpx_user *mpx_usr;
    uint8_t mlme_status;

    WARN_ON(!ws_neigh);
    base->temp_entries.active_eapol_session = false;

    mlme_status = mlme_status_from_hif(confirm->hif.status);
    if (ws_neigh && mlme_status == MLME_SUCCESS)
        ws_neigh_refresh(&base->interface_ptr->ws_info.neighbor_storage, ws_neigh, ws_neigh->lifetime_s);

    mpx_usr = ws_llc_mpx_user_discover(&base->mpx_data_base, MPX_ID_KMP);
    if (mpx_usr && mpx_usr->data_confirm) {
        mpx_confirm = *confirm;
        mpx_confirm.hif.handle = msg->mpx_user_handle;
        mpx_usr->data_confirm(&base->mpx_data_base.mpx_api, &mpx_confirm);
    }

    msg = ns_list_get_first(&base->temp_entries.llc_eap_pending_list);
    if (msg) {
        ns_list_remove(&base->temp_entries.llc_eap_pending_list, msg);
        base->temp_entries.llc_eap_pending_list_size--;
        red_aq_calc(&base->interface_ptr->llc_eapol_random_early_detection,
                    base->temp_entries.llc_eap_pending_list_size);
        ws_llc_mpx_eapol_send(base, msg);
    }
}

// ETSI EN 300 220-1 v3.1.1 - 5.13 Adaptive Power Control
#define ETSI_APC_ATTENUATION_DB 75
#define ETSI_APC_POWER_LIMIT_DBM 7

/*
 * Adapt TX power linearly based on the measured attenuation.
 *
 *  TX   ^
 * power |                ,---------
 *       |  1dBm per dB  /   configured
 *       |            \ /       power
 *       |             /
 *  7dBm +   ---------'
 *       |  APC limit
 *       +------------+---------------->
 *                  75dB           attenuation
 *
 * Some margins are applied for safety. One reason for this is that RAIL
 * reports the average power and not the peak.
 */
static int etsi_apc_calc_txpow(int conf_txpow_dbm, // TX power configured in wsbrd.conf
                               int real_txpow_dbm, // TX power used for this transmission
                               int rsl_dbm,        // RX power from neighbor
                               int margin_db)
{
    const int attenuation_threshold_db = ETSI_APC_ATTENUATION_DB + 1; // Safety margin
    const int limit_dbm = ETSI_APC_POWER_LIMIT_DBM - margin_db;
    const int attenuation_db = real_txpow_dbm - rsl_dbm;

    if (attenuation_db < attenuation_threshold_db)
        return MIN(conf_txpow_dbm, limit_dbm);
    else
        return MIN(conf_txpow_dbm, limit_dbm + attenuation_db - attenuation_threshold_db);
}

static void ws_llc_update_txpow(const struct ws_info *ws_info,
                                struct ws_neigh *neigh,
                                uint8_t phy_mode_id,
                                int8_t rsl_dbm)
{
    const struct phy_params *phy_params;

    phy_params = ws_regdb_phy_params(phy_mode_id, 0);
    if (phy_params && phy_params->modulation == MODULATION_OFDM)
        neigh->apc_txpow_dbm_ofdm = etsi_apc_calc_txpow(ws_info->tx_power_dbm,
                                                        ws_info->tx_power_dbm, // TODO: get from CNF_DATA_TX
                                                        rsl_dbm, 11); // 10dB average-to-peak + 1dB margin
    else
        neigh->apc_txpow_dbm = etsi_apc_calc_txpow(ws_info->tx_power_dbm,
                                                   ws_info->tx_power_dbm, // TODO: get from CNF_DATA_TX
                                                   rsl_dbm, 1); // 1dB margin
}

static const struct rcp_rate_info *ws_llc_success_rate(const struct rcp_rate_info rate_list[4],
                                                       uint8_t tx_attempts)
{
    for (int i = 0; i < 4; i++) {
        if (tx_attempts <= rate_list[i].tx_attempts)
            return &rate_list[i];
        tx_attempts -= rate_list[i].tx_attempts;
    }
    WARN("%s(): unexpected retry count", __func__);
    return NULL;
}

static void ws_llc_data_confirm(struct llc_data_base *base, struct llc_message *msg,
                                const struct mcps_data_cnf *confirm,
                                const struct mcps_data_rx_ie_list *confirm_data,
                                struct ws_neigh *ws_neigh)
{
    const uint8_t mlme_status = mlme_status_from_hif(confirm->hif.status);
    struct ws_info *ws_info = &base->interface_ptr->ws_info;
    const struct rcp_rate_info *rate;
    struct mcps_data_cnf mpx_confirm;
    struct mpx_user *mpx_usr;
    struct ws_lutt_ie ie_lutt;
    struct ws_utt_ie ie_utt;
    int ie_rsl;

    if (msg->ack_requested) {
        switch (mlme_status) {
        case MLME_SUCCESS:
        case MLME_TX_NO_ACK:
            if (!ws_neigh)
                break;
            if (ws_neigh->lifetime_s == WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME)
                break;
            if (ws_wh_utt_read(confirm_data->headerIeList, confirm_data->headerIeListLength, &ie_utt)) {
                if (mlme_status == MLME_SUCCESS)
                    ws_neigh_refresh(&ws_info->neighbor_storage, ws_neigh, ws_neigh->lifetime_s);
                ws_neigh_ut_update(&ws_neigh->fhss_data, ie_utt.ufsi, confirm->hif.timestamp_us, ws_neigh->mac64);
                ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, confirm->hif.timestamp_us, ws_neigh->mac64);
            }
            if (ws_wh_lutt_read(confirm_data->headerIeList, confirm_data->headerIeListLength, &ie_lutt))
                if (mlme_status == MLME_SUCCESS)
                    ws_neigh_refresh(&ws_info->neighbor_storage, ws_neigh, ws_neigh->lifetime_s);
            if (ws_wh_rsl_read(confirm_data->headerIeList, confirm_data->headerIeListLength, &ie_rsl)) {
                ws_neigh->rsl_out_dbm = ws_neigh_ewma_next(ws_neigh->rsl_out_dbm, ie_rsl);
                rate = ws_llc_success_rate(msg->rate_list, confirm->hif.tx_retries + 1);
                ws_llc_update_txpow(ws_info, ws_neigh,
                                    rate ? rate->phy_mode_id : ws_info->phy_config.phy_mode_id_ms_base,
                                    ie_rsl);
            }
            break;
        }
    }

    mpx_usr = ws_llc_mpx_user_discover(&base->mpx_data_base, MPX_ID_6LOWPAN);
    if (mpx_usr && mpx_usr->data_confirm) {
        mpx_confirm = *confirm;
        mpx_confirm.hif.handle = msg->mpx_user_handle;
        mpx_usr->data_confirm(&base->mpx_data_base.mpx_api, &mpx_confirm);
    }
}

static bool tx_confirm_extensive(struct ws_neigh *ws_neigh, time_t tx_confirm_duration)
{
    if (!ws_neigh)
        return false;

    if (ws_neigh->node_role == WS_NR_ROLE_LFN) {
        if (ws_neigh->fhss_data.lfn.uc_listen_interval_ms)
            return tx_confirm_duration * 1000 >= ws_neigh->fhss_data.lfn.uc_listen_interval_ms * TX_CONFIRM_EXTENSIVE_LFN_MULTIPLIER;
        else
            return tx_confirm_duration * 1000 >= ws_neigh->fhss_data_unsecured.lfn.uc_listen_interval_ms * TX_CONFIRM_EXTENSIVE_LFN_MULTIPLIER;
    }
    return tx_confirm_duration >= TX_CONFIRM_EXTENSIVE_FFN_SEC;
}

void ws_llc_mac_confirm_cb(struct net_if *net_if, const mcps_data_cnf_t *data,
                           const struct mcps_data_rx_ie_list *conf_data)
{
    struct llc_data_base *base = &g_llc_base;
    struct ws_neigh *ws_neigh = NULL;
    struct mcps_data_cnf data_cpy = *data;
    struct llc_message *msg;
    time_t tx_confirm_duration;

    msg = llc_message_discover_by_mac_handle(data_cpy.hif.handle, &base->llc_message_list);
    if (!msg)
        return;

    if (data_cpy.hif.status != HIF_STATUS_SUCCESS)
        TRACE(TR_TX_ABORT, "tx-abort: tx failure status=%s dst=%s", hif_status_str(data_cpy.hif.status),
              tr_eui64(msg->dst_address));

    if (msg->security.SecurityLevel && data_cpy.hif.frame_counter)
        ws_pae_controller_nw_frame_counter_indication_cb(net_if->id, msg->security.KeyIndex, data_cpy.hif.frame_counter);

    if (msg->dst_address_type == IEEE802154_ADDR_MODE_64_BIT)
        ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, msg->dst_address);

    if (ws_neigh) {
        if (data_cpy.sec.SecurityLevel) {
            BUG_ON(data->sec.KeyIndex < 1 || data->sec.KeyIndex > 7);
            if (ws_neigh->frame_counter_min[data_cpy.sec.KeyIndex - 1] > data_cpy.sec.frame_counter ||
                ws_neigh->frame_counter_min[data_cpy.sec.KeyIndex - 1] == UINT32_MAX) {
                data_cpy.hif.status = HIF_STATUS_NOACK;
                TRACE(TR_TX_ABORT, "tx-abort %-9s: invalid frame counter key-idx=%u cnt=%"PRIu32" cnt-min=%"PRIu32,
                      "15.4", data_cpy.sec.KeyIndex, data_cpy.sec.frame_counter,
                      ws_neigh->frame_counter_min[data_cpy.sec.KeyIndex - 1]);
            } else {
                ws_neigh->frame_counter_min[data_cpy.sec.KeyIndex - 1] = add32sat(data_cpy.sec.frame_counter, 1);
            }
        }

        ws_llc_rate_handle_tx_conf(base, data, ws_neigh);
    }

    tx_confirm_duration = time_get_elapsed(CLOCK_MONOTONIC, msg->tx_time);

    switch (msg->message_type) {
    case WS_FT_DATA:
        if (tx_confirm_extensive(ws_neigh, tx_confirm_duration))
            WARN("frame spent %"PRIu64" sec in MAC", (uint64_t)tx_confirm_duration);
        ws_llc_data_confirm(base, msg, &data_cpy, conf_data, ws_neigh);
        break;
    case WS_FT_EAPOL:
        if (tx_confirm_extensive(ws_neigh, tx_confirm_duration))
            WARN("frame spent %"PRIu64" sec in MAC", (uint64_t)tx_confirm_duration);
        ws_llc_eapol_confirm(base, msg, &data_cpy);
        break;
    case WS_FT_PA:
    case WS_FT_PAS:
    case WS_FT_PC:
    case WS_FT_PCS:
        base->mngt_cnf(&net_if->ws_info, msg->message_type);
        break;
    }

    llc_message_free(msg, base);
}

static llc_data_base_t *ws_llc_mpx_frame_common_validates(const struct net_if *net_if, const mcps_data_ind_t *data, uint8_t frame_type)
{
    struct llc_data_base *base = &g_llc_base;

    if (data->SrcAddrMode != ADDR_802_15_4_LONG) {
        TRACE(TR_DROP, "drop %-9s: invalid source address mode", tr_ws_frame(frame_type));
        return NULL;
    }

    if (data->SrcPANId != base->interface_ptr->ws_info.pan_information.pan_id) {
        TRACE(TR_DROP, "drop %-9s: invalid source PAN ID", tr_ws_frame(frame_type));
        return NULL;
    }

    return base;

}

static mpx_user_t *ws_llc_mpx_header_parse(llc_data_base_t *base,
                                           const struct mcps_data_rx_ie_list *ie_ext,
                                           struct mpx_ie *mpx_frame)
{
    struct iobuf_read ie_buf;
    struct mpx_user *mpx_usr;

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_MPX, &ie_buf);
    if (ie_buf.err) {
        TRACE(TR_DROP, "drop %-9s: missing MPX-IE", "15.4");
        return NULL;
    }
    if (!mpx_ie_parse(ie_buf.data, ie_buf.data_size, mpx_frame)) {
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

static void ws_llc_data_ffn_ind(struct net_if *net_if, const mcps_data_ind_t *data,
                                const struct mcps_data_rx_ie_list *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_DATA);
    struct ws_neigh *ws_neigh;
    mcps_data_ind_t data_ind = *data;
    bool has_us, has_bs, has_pom;
    struct ws_utt_ie ie_utt;
    struct iobuf_read ie_wp;
    struct ws_pom_ie ie_pom;
    bool duplicated = false;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    mpx_user_t *mpx_user;
    struct mpx_ie mpx_frame;
    bool add_neighbor;

    if (!base)
        return;
    mpx_user = ws_llc_mpx_header_parse(base, ie_ext, &mpx_frame);
    if (!mpx_user)
        return;

    if (data->Key.SecurityLevel != IEEE802154_SEC_LEVEL_ENC_MIC64) {
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

    add_neighbor = false;
    ws_neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);

    if (!ws_neigh) {
        add_neighbor = (data->DstAddrMode == ADDR_802_15_4_LONG && has_us);
    } else if (ws_neigh->node_role != WS_NR_ROLE_ROUTER) {
        WARN("node changed role");
        ws_neigh_del(&net_if->ws_info.neighbor_storage, ws_neigh->mac64);
        add_neighbor = true;
    }
    if (add_neighbor) {
        ws_neigh = ws_neigh_add(&net_if->ws_info.neighbor_storage, data->SrcAddr, WS_NR_ROLE_ROUTER,
                                net_if->ws_info.tx_power_dbm, net_if->ws_info.key_index_mask);
        BUG_ON(!ws_neigh);
    }

    if (ws_neigh) {
        if (data->DstAddrMode == ADDR_802_15_4_LONG && !data->DSN_suppressed)
            duplicated = !ws_neigh_duplicate_packet_check(ws_neigh, data->DSN, data->hif.timestamp_us);

        if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_utt))
            BUG("missing UTT-IE in data frame from FFN");
        ws_neigh_ut_update(&ws_neigh->fhss_data, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
        ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
        if (has_us && !duplicated) {
            ws_neigh_us_update(&base->interface_ptr->ws_info.fhss_config, &ws_neigh->fhss_data, &ie_us.chan_plan,
                                        ie_us.dwell_interval);
            ws_neigh_us_update(&base->interface_ptr->ws_info.fhss_config, &ws_neigh->fhss_data_unsecured, &ie_us.chan_plan,
                                        ie_us.dwell_interval);
        }
        if (data->DstAddrMode == ADDR_802_15_4_LONG)
            ws_neigh->unicast_data_rx = true;

        // Calculate RSL for all UDATA packets heard
        ws_neigh->rsl_in_dbm = ws_neigh_ewma_next(ws_neigh->rsl_in_dbm, data->hif.rx_power_dbm);
        ws_neigh->rx_power_dbm = data->hif.rx_power_dbm;
        ws_neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(ws_neigh->rsl_in_dbm_unsecured, data->hif.rx_power_dbm);
        ws_neigh->rx_power_dbm_unsecured = data->hif.rx_power_dbm;
        ws_neigh->lqi = data->hif.lqi;
        ws_neigh->lqi_unsecured = data->hif.lqi;

        if (data->Key.SecurityLevel)
            ws_neigh_trust(&net_if->ws_info.neighbor_storage, ws_neigh);
        if (has_pom && base->interface_ptr->ws_info.phy_config.phy_op_modes[0] && !duplicated)
            ws_neigh->pom_ie = ie_pom;
        if (duplicated) {
            TRACE(TR_DROP, "drop %-9s: duplicate message", tr_ws_frame(WS_FT_DATA));
            return;
        }
    }

    if (!ws_neigh)
        data_ind.Key.SecurityLevel = 0;
    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_data_lfn_ind(struct net_if *net_if, const mcps_data_ind_t *data,
                                const struct mcps_data_rx_ie_list *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_DATA);
    struct ws_neigh *ws_neigh;
    mcps_data_ind_t data_ind = *data;
    bool has_lus, has_lcp, has_pom;
    struct ws_lutt_ie ie_lutt;
    struct iobuf_read ie_wp;
    struct ws_lus_ie ie_lus;
    struct ws_lcp_ie ie_lcp;
    struct ws_pom_ie ie_pom;
    bool duplicated = false;
    mpx_user_t *mpx_user;
    struct mpx_ie mpx_frame;

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

    ws_neigh = ws_neigh_get(&base->interface_ptr->ws_info.neighbor_storage, data->SrcAddr);
    if (!ws_neigh) {
        TRACE(TR_DROP, "drop %-9s: unknown neighbor %s", tr_ws_frame(WS_FT_DATA), tr_eui64(data->SrcAddr));
        return;
    }

    if (!data->DstAddrMode && !data->DSN_suppressed)
        duplicated = !ws_neigh_duplicate_packet_check(ws_neigh, data->DSN, data->hif.timestamp_us);

    if (!ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt))
        BUG("Missing LUTT-IE in ULAD frame from LFN");
    if (has_lus && !duplicated) {
        ws_neigh_lut_update(&ws_neigh->fhss_data, ie_lutt.slot_number, ie_lutt.interval_offset,
                            data->hif.timestamp_us);
        ws_neigh_lut_update(&ws_neigh->fhss_data_unsecured, ie_lutt.slot_number, ie_lutt.interval_offset,
                            data->hif.timestamp_us);
        ws_neigh->lto_info.offset_adjusted = ws_neigh_lus_update(&base->interface_ptr->ws_info.fhss_config,
                                                                 &ws_neigh->fhss_data,
                                                                 has_lcp ? &ie_lcp.chan_plan : NULL,
                                                                 ie_lus.listen_interval, &ws_neigh->lto_info);
        ws_neigh_lus_update(&base->interface_ptr->ws_info.fhss_config, &ws_neigh->fhss_data_unsecured,
                            has_lcp ? &ie_lcp.chan_plan : NULL,
                            ie_lus.listen_interval, &ws_neigh->lto_info);
    }

    if (data->DstAddrMode == ADDR_802_15_4_LONG)
        ws_neigh->unicast_data_rx = true;

    // Calculate RSL for all UDATA packets heard
    ws_neigh->rsl_in_dbm = ws_neigh_ewma_next(ws_neigh->rsl_in_dbm, data->hif.rx_power_dbm);
    ws_neigh->rx_power_dbm = data->hif.rx_power_dbm;
    ws_neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(ws_neigh->rsl_in_dbm_unsecured, data->hif.rx_power_dbm);
    ws_neigh->rx_power_dbm_unsecured = data->hif.rx_power_dbm;
    ws_neigh->lqi = data->hif.lqi;
    ws_neigh->lqi_unsecured = data->hif.lqi;

    if (data->Key.SecurityLevel)
        ws_neigh_trust(&net_if->ws_info.neighbor_storage, ws_neigh);
    if (ws_neigh->lifetime_s == WS_NEIGHBOUR_TEMPORARY_ENTRY_LIFETIME)
        ws_neigh_refresh(&net_if->ws_info.neighbor_storage, ws_neigh, WS_NEIGHBOR_LINK_TIMEOUT);
    else
        ws_neigh_refresh(&net_if->ws_info.neighbor_storage, ws_neigh, ws_neigh->lifetime_s);
    if (has_pom && !duplicated)
        ws_neigh->pom_ie = ie_pom;
    if (duplicated) {
        TRACE(TR_DROP, "drop %-9s: duplicate message", tr_ws_frame(WS_FT_DATA));
        return;
    }

    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static struct ws_neigh *ws_llc_neigh_fetch(llc_data_base_t *base, const mcps_data_ind_t *data, uint8_t node_role)
{
    struct ws_neigh *ws_neigh = ws_neigh_get(&base->interface_ptr->ws_info.neighbor_storage,
                                                                           data->SrcAddr);

    if (ws_neigh)
        return ws_neigh;
    return ws_neigh_add(&base->interface_ptr->ws_info.neighbor_storage, data->SrcAddr, node_role,
                        base->interface_ptr->ws_info.tx_power_dbm, base->interface_ptr->ws_info.key_index_mask);
}

static void ws_llc_eapol_ffn_ind(struct net_if *net_if, const mcps_data_ind_t *data,
                                 const struct mcps_data_rx_ie_list *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_EAPOL);
    struct ws_neigh *ws_neigh = NULL;
    mcps_data_ind_t data_ind = *data;
    struct ws_utt_ie ie_utt;
    struct iobuf_read ie_wp;
    bool duplicated = false;
    struct ws_us_ie ie_us;
    struct ws_bs_ie ie_bs;
    mpx_user_t *mpx_user;
    struct mpx_ie mpx_frame;
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

    ws_neigh = ws_llc_neigh_fetch(base, data, WS_NR_ROLE_ROUTER);
    if (!ws_neigh)
        return;

    ws_neigh_refresh(&net_if->ws_info.neighbor_storage, ws_neigh, ws_neigh->lifetime_s);
    ws_neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(ws_neigh->rsl_in_dbm_unsecured, data->hif.rx_power_dbm);
    ws_neigh->rx_power_dbm_unsecured = data->hif.rx_power_dbm;
    ws_neigh->lqi_unsecured = data->hif.lqi;

    if (!data->DSN_suppressed)
        duplicated = !ws_neigh_duplicate_packet_check(ws_neigh, data->DSN, data->hif.timestamp_us);

    if (!ws_wh_utt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_utt))
        BUG("missing UTT-IE in EAPOL frame from FFN");
    ws_neigh_ut_update(&ws_neigh->fhss_data_unsecured, ie_utt.ufsi, data->hif.timestamp_us, data->SrcAddr);
    if (has_us && !duplicated)
        ws_neigh_us_update(&base->interface_ptr->ws_info.fhss_config,
                           &ws_neigh->fhss_data_unsecured,
                           &ie_us.chan_plan, ie_us.dwell_interval);
    if (duplicated) {
        TRACE(TR_DROP, "drop %-9s: duplicate message", tr_ws_frame(WS_FT_DATA));
        return;
    }

    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_eapol_lfn_ind(struct net_if *net_if, const mcps_data_ind_t *data,
                                 const struct mcps_data_rx_ie_list *ie_ext)
{
    llc_data_base_t *base = ws_llc_mpx_frame_common_validates(net_if, data, WS_FT_EAPOL);
    struct ws_neigh *ws_neigh = NULL;
    mcps_data_ind_t data_ind = *data;
    struct ws_lutt_ie ie_lutt;
    struct ws_lus_ie ie_lus;
    struct iobuf_read ie_wp;
    struct ws_lcp_ie ie_lcp;
    bool duplicated = false;
    bool has_lus, has_lcp;
    mpx_user_t *mpx_user;
    struct mpx_ie mpx_frame;

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

    ws_neigh = ws_llc_neigh_fetch(base, data, WS_NR_ROLE_LFN);
    if (!ws_neigh)
        return;

    ws_neigh_refresh(&net_if->ws_info.neighbor_storage, ws_neigh, ws_neigh->lifetime_s);
    ws_neigh->rsl_in_dbm_unsecured = ws_neigh_ewma_next(ws_neigh->rsl_in_dbm_unsecured, data->hif.rx_power_dbm);
    ws_neigh->rx_power_dbm_unsecured = data->hif.rx_power_dbm;
    ws_neigh->lqi_unsecured = data->hif.lqi;

    if (!data->DSN_suppressed)
        duplicated = !ws_neigh_duplicate_packet_check(ws_neigh, data->DSN, data->hif.timestamp_us);

    if (!ws_wh_lutt_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_lutt))
        BUG("Missing LUTT-IE in EAPOL frame from LFN");
    if (has_lus && !duplicated) {
        ws_neigh_lut_update(&ws_neigh->fhss_data_unsecured, ie_lutt.slot_number, ie_lutt.interval_offset,
                            data->hif.timestamp_us);
        ws_neigh->lto_info.offset_adjusted = ws_neigh_lus_update(&base->interface_ptr->ws_info.fhss_config, &ws_neigh->fhss_data_unsecured,
                                                                 has_lcp ? &ie_lcp.chan_plan : NULL,
                                                                 ie_lus.listen_interval, &ws_neigh->lto_info);
    }
    if (duplicated) {
        TRACE(TR_DROP, "drop %-9s: duplicate message", tr_ws_frame(WS_FT_DATA));
        return;
    }

    data_ind.msdu_ptr = mpx_frame.frame_ptr;
    data_ind.msduLength = mpx_frame.frame_length;
    mpx_user->data_ind(&base->mpx_data_base.mpx_api, &data_ind);
}

static void ws_llc_mngt_ind(const struct net_if *net_if, const mcps_data_ind_t *data,
                            const struct mcps_data_rx_ie_list *ie_ext, uint8_t frame_type)
{
    struct llc_data_base *base = &g_llc_base;
    struct mcps_data_rx_ie_list ie_list;
    struct iobuf_read ie_buf;

    if (!base->mngt_ind)
        return;

    ieee802154_ie_find_payload(ie_ext->payloadIeList, ie_ext->payloadIeListLength, IEEE802154_IE_ID_WP, &ie_buf);
    if (ie_buf.err) {
        TRACE(TR_DROP, "drop %-9s: missing WP-IE", tr_ws_frame(frame_type));
        return;
    }

    ie_list.headerIeList = ie_ext->headerIeList,
    ie_list.headerIeListLength = ie_ext->headerIeListLength;
    // FIXME: Despite the member being called "payloadIeList", we are storing
    // the content of the WP-IE instead.
    ie_list.payloadIeList       = ie_buf.data;
    ie_list.payloadIeListLength = ie_buf.data_size;
    base->mngt_ind(&base->interface_ptr->ws_info, data, &ie_list, frame_type);
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

static void ws_trace_llc_mac_ind(const mcps_data_ind_t *data,
                                 const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_lutt_ie ws_lutt;
    struct ws_utt_ie ws_utt;
    const char *type_str;
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
        TRACE(trace_domain, "rx-15.4 %-9s src:%s panid:%x (%ddBm)", type_str, tr_eui64(data->SrcAddr), data->SrcPANId, data->hif.rx_power_dbm);
    else
        TRACE(trace_domain, "rx-15.4 %-9s src:%s (%ddBm)", type_str, tr_eui64(data->SrcAddr), data->hif.rx_power_dbm);
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
void ws_llc_mac_indication_cb(struct net_if *net_if, struct mcps_data_ind *data,
                              const struct mcps_data_rx_ie_list *ie_ext)
{
    struct ws_neigh *neigh;
    struct ws_lutt_ie ie_lutt;
    struct ws_utt_ie ie_utt;
    struct ws_fc_ie ie_fc;
    bool has_utt, has_lutt;
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

    if (has_lutt && !net_if->ws_info.enable_lfn) {
        TRACE(TR_DROP, "drop %-9s: LFN support disabled", tr_ws_frame(frame_type));
        return;
    }

    neigh = ws_neigh_get(&net_if->ws_info.neighbor_storage, data->SrcAddr);
    if (neigh && data->Key.SecurityLevel) {
        BUG_ON(data->Key.KeyIndex < 1 || data->Key.KeyIndex > 7);
        if (neigh->frame_counter_min[data->Key.KeyIndex - 1] > data->Key.frame_counter ||
            neigh->frame_counter_min[data->Key.KeyIndex - 1] == UINT32_MAX) {
            TRACE(TR_DROP, "drop %-9s: invalid frame counter key-idx=%u cnt=%"PRIu32" cnt-min=%"PRIu32,
                  "15.4", data->Key.KeyIndex, data->Key.frame_counter,
                  neigh->frame_counter_min[data->Key.KeyIndex - 1]);
            return;
        }
        neigh->frame_counter_min[data->Key.KeyIndex - 1] = add32sat(data->Key.frame_counter, 1);
    }

    // HACK: In FAN 1.0 the source address is elided in EDFE response frames
    if (ws_wh_fc_read(ie_ext->headerIeList, ie_ext->headerIeListLength, &ie_fc)) {
        if (data->SrcAddrMode == IEEE802154_ADDR_MODE_64_BIT) {
            memcpy(net_if->ws_info.edfe_src, data->SrcAddr, 8);
        } else {
            memcpy(data->SrcAddr, net_if->ws_info.edfe_src, 8);
            data->SrcAddrMode = IEEE802154_ADDR_MODE_64_BIT;
        }
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
static void ws_llc_prepare_ie(llc_data_base_t *base, llc_message_t *msg,
                              const struct wh_ie_list *wh_ies,
                              const struct wp_ie_list *wp_ies)
{
    struct ws_info *info = &base->interface_ptr->ws_info;
    uint16_t pan_size = (info->pan_information.test_pan_size == -1) ?
                         rpl_target_count(&base->interface_ptr->rpl_root) : info->pan_information.test_pan_size;
    struct ws_ie_custom *ie_custom;
    bool has_ie_custom_wp = false;
    int ie_offset;
    uint8_t plf;

    if (info->pan_information.jm.mask & BIT(WS_JM_PLF)) {
        plf = MIN(100 * pan_size / info->pan_information.max_pan_size, 100);
        if (plf != info->pan_information.jm.plf) {
            info->pan_information.jm.plf = plf;
            info->pan_information.jm.version++;
        }
    }

    if (wh_ies->fc)
        ws_wh_fc_write(&msg->ie_buf_header, 50, 255);
    if (wh_ies->utt)
        ws_wh_utt_write(&msg->ie_buf_header, msg->message_type);
    if (wh_ies->bt)
        ws_wh_bt_write(&msg->ie_buf_header);
    if (wh_ies->ea)
        ws_wh_ea_write(&msg->ie_buf_header, base->interface_ptr->rcp->eui64.u8);
    if (wh_ies->lutt)
        ws_wh_lutt_write(&msg->ie_buf_header, msg->message_type);
    if (wh_ies->lbt)
        ws_wh_lbt_write(&msg->ie_buf_header);
    if (wh_ies->nr)
        // TODO: Provide clock drift and timing accuracy
        // TODO: Make the LFN listening interval configurable (currently it is 5s-4.66h)
        ws_wh_nr_write(&msg->ie_buf_header, WS_NR_ROLE_BR, 255, 0, 5000, 1680000);
    if (wh_ies->lus)
        ws_wh_lus_write(&msg->ie_buf_header, base->ie_params.lfn_us);
    if (wh_ies->flus)
        // Only a single chan plan tag is supported. (0)
        ws_wh_flus_write(&msg->ie_buf_header, info->fhss_config.uc_dwell_interval, 0);
    if (wh_ies->lbs)
        // Only a single chan plan tag is supported. (0)
        // TODO: use a separate LFN BSI
        ws_wh_lbs_write(&msg->ie_buf_header, info->fhss_config.lfn_bc_interval,
                        info->fhss_config.bsi, 0,
                        info->fhss_config.lfn_bc_sync_period);
    if (wh_ies->lnd)
        ws_wh_lnd_write(&msg->ie_buf_header, base->ie_params.lfn_network_discovery);
    if (wh_ies->lto)
        ws_wh_lto_write(&msg->ie_buf_header, base->ie_params.lfn_timing->offset,
                        base->ie_params.lfn_timing->adjusted_listening_interval);
    if (wh_ies->panid)
        ws_wh_panid_write(&msg->ie_buf_header, info->pan_information.pan_id);
    if (wh_ies->lbc)
        ws_wh_lbc_write(&msg->ie_buf_header, info->fhss_config.lfn_bc_interval,
                        info->fhss_config.lfn_bc_sync_period);
    SLIST_FOREACH(ie_custom, &info->ie_custom_list, link) {
        if (!(ie_custom->frame_type_mask & BIT(msg->message_type)))
            continue;
        if (ie_custom->ie_type == WS_IE_CUSTOM_TYPE_HEADER)
            iobuf_push_data(&msg->ie_buf_header, ie_custom->buf.data, ie_custom->buf.len);
        else
            has_ie_custom_wp = true;
    }
    msg->ie_iov_header.iov_base = msg->ie_buf_header.data;
    msg->ie_iov_header.iov_len = msg->ie_buf_header.len;
    msg->ie_ext.headerIeVectorList = &msg->ie_iov_header;
    msg->ie_ext.headerIovLength = 1;

    if (!ws_wp_ie_is_empty(wp_ies) || has_ie_custom_wp) {
        ie_offset = ieee802154_ie_push_payload(&msg->ie_buf_payload, IEEE802154_IE_ID_WP);
        if (wp_ies->us)
            ws_wp_nested_us_write(&msg->ie_buf_payload, &info->fhss_config);
        if (wp_ies->bs)
            ws_wp_nested_bs_write(&msg->ie_buf_payload, &info->fhss_config);
        if (wp_ies->pan)
            ws_wp_nested_pan_write(&msg->ie_buf_payload, pan_size,
                                   info->pan_information.routing_cost, info->pan_information.version);
        if (wp_ies->netname)
            ws_wp_nested_netname_write(&msg->ie_buf_payload, info->network_name);
        if (wp_ies->panver)
            ws_wp_nested_panver_write(&msg->ie_buf_payload, info->pan_information.pan_version);
        if (wp_ies->gtkhash)
            ws_wp_nested_gtkhash_write(&msg->ie_buf_payload, ws_pae_controller_gtk_hash_ptr_get(base->interface_ptr));
        if (wp_ies->pom)
            ws_wp_nested_pom_write(&msg->ie_buf_payload, info->phy_config.phy_op_modes, true);
        if (wp_ies->lcp)
            // Only unicast schedule using tag 0 is supported
            ws_wp_nested_lcp_write(&msg->ie_buf_payload, 0, &info->fhss_config);
        if (wp_ies->lfnver)
            ws_wp_nested_lfnver_write(&msg->ie_buf_payload, info->pan_information.lfn_version);
        if (wp_ies->lgtkhash)
            ws_wp_nested_lgtkhash_write(&msg->ie_buf_payload, ws_pae_controller_lgtk_hash_ptr_get(base->interface_ptr),
                                        ws_pae_controller_lgtk_active_index_get(base->interface_ptr));
        if (wp_ies->lbats)
            ws_wp_nested_lbats_write(&msg->ie_buf_payload, base->ie_params.lbats_ie);
        if (wp_ies->jm)
            ws_wp_nested_jm_write(&msg->ie_buf_payload, &info->pan_information.jm);
        SLIST_FOREACH(ie_custom, &info->ie_custom_list, link)
            if (ie_custom->frame_type_mask & BIT(msg->message_type) &&
                ie_custom->ie_type != WS_IE_CUSTOM_TYPE_HEADER)
                iobuf_push_data(&msg->ie_buf_payload, ie_custom->buf.data, ie_custom->buf.len);
        ieee802154_ie_fill_len_payload(&msg->ie_buf_payload, ie_offset);
    }
    msg->ie_iov_payload[0].iov_len = msg->ie_buf_payload.len;
    msg->ie_iov_payload[0].iov_base = msg->ie_buf_payload.data;
    msg->ie_ext.payloadIeVectorList = &msg->ie_iov_payload[0];
    msg->ie_ext.payloadIovLength = 1;
}

static uint16_t ws_mpx_header_size_get(llc_data_base_t *base, uint16_t user_id)
{
    //TODO add IEEE802154_IE_ID_WP support
    uint16_t header_size = 0;
    if (user_id == MPX_ID_6LOWPAN) {
        header_size += 7 + 8 + 5 + 2; //UTT+BTT+ MPX + Padding

        //Dynamic length
        header_size += 2 + 2 /* WP-IE header */ +
                       ws_wp_nested_hopping_schedule_length(&base->interface_ptr->ws_info.fhss_config, true) +
                       ws_wp_nested_hopping_schedule_length(&base->interface_ptr->ws_info.fhss_config, false);
    } else if (MPX_ID_KMP) {
        header_size += 7 + 5 + 2;
        //Dynamic length
        header_size += 2 + 2 /* WP-IE header */ +
                       ws_wp_nested_hopping_schedule_length(&base->interface_ptr->ws_info.fhss_config, true);
    }
    return header_size;
}

static bool ws_eapol_handshake_first_msg(uint8_t *pdu, uint16_t length, struct net_if *cur)
{
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
    struct mpx_ie mpx_header = {
        .transfer_type = MPX_FT_FULL_FRAME,
        .transaction_id = message->mpx_id,
        .multiplex_id = user_id,
    };
    uint16_t ie_len;
    int ie_offset;

    ie_offset = ieee802154_ie_push_payload(&message->ie_buf_payload, IEEE802154_IE_ID_MPX);
    mpx_ie_write(&message->ie_buf_payload, &mpx_header);
    ie_len = message->ie_buf_payload.len - ie_offset - 2 + message->ie_iov_payload[1].iov_len;
    ieee802154_ie_set_len(&message->ie_buf_payload, ie_offset, ie_len, IEEE802154_IE_PAYLOAD_LEN_MASK);
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
}

static uint8_t ws_llc_find_phy_mode_id(const uint8_t phy_mode_id_list[],
                                       uint8_t phy_mode_id_count,
                                       uint8_t phy_mode_id)
{
    for (int i = 0; i < phy_mode_id_count; i++)
        if (phy_mode_id_list[i] == phy_mode_id)
            return phy_mode_id;
    return 0;
}

uint8_t ws_llc_mdr_phy_mode_get(const struct ws_phy_config *phy_config,
                                const struct ws_neigh *ws_neigh)
{
    uint8_t ms_phy_mode_id = 0;

    switch (ws_neigh->ms_mode) {
    case WS_MODE_SWITCH_PHY:
    case WS_MODE_SWITCH_MAC:
        ms_phy_mode_id = ws_neigh->ms_phy_mode_id;
        break;
    case WS_MODE_SWITCH_DEFAULT:
        if (phy_config->ms_mode == WS_MODE_SWITCH_PHY || phy_config->ms_mode == WS_MODE_SWITCH_MAC)
            ms_phy_mode_id = phy_config->phy_mode_id_ms_tx;
        break;
    }
    return ws_llc_find_phy_mode_id(ws_neigh->pom_ie.phy_op_mode_id,
                                   ws_neigh->pom_ie.phy_op_mode_number,
                                   ms_phy_mode_id);
}

static void ws_llc_fill_rates(const struct ws_info *ws_info,
                              const struct ws_neigh *ws_neigh,
                              struct rcp_rate_info rate_list[4])
{
    const struct phy_params *phy_params;
    uint8_t phy_mode_id;
    int8_t tx_power_dbm;

    memset(rate_list, 0, 4 * sizeof(struct rcp_rate_info));

    phy_mode_id = ws_llc_mdr_phy_mode_get(&ws_info->phy_config, ws_neigh);
    if (!phy_mode_id)
        phy_mode_id = ws_info->phy_config.phy_mode_id_ms_base;

    phy_params = ws_regdb_phy_params(phy_mode_id, 0);
    if (!ws_neigh || ws_info->fhss_config.regional_regulation != HIF_REG_WPC)
        tx_power_dbm = ws_info->tx_power_dbm;
    else if (phy_params && phy_params->modulation == MODULATION_OFDM)
        tx_power_dbm = ws_neigh->apc_txpow_dbm_ofdm;
    else
        tx_power_dbm = ws_neigh->apc_txpow_dbm;

    rate_list[0].phy_mode_id = phy_mode_id;
    rate_list[0].tx_attempts = 20;
    rate_list[0].tx_power_dbm = tx_power_dbm;
}

static void ws_llc_lowpan_mpx_data_request(llc_data_base_t *base, mpx_user_t *user_cb, const struct mcps_data_req *data)
{
    struct ws_info *ws_info = &base->interface_ptr->ws_info;
    struct ws_neigh *ws_neigh = data->DstAddrMode == IEEE802154_ADDR_MODE_64_BIT ?
                                ws_neigh_get(&ws_info->neighbor_storage, data->DstAddr) :
                                NULL;
    uint8_t node_role = ws_neigh ? ws_neigh->node_role : WS_NR_ROLE_UNKNOWN;
    struct wh_ie_list wh_ies = {
        .utt = true,
        .bt  = true,
        .lbt = node_role == WS_NR_ROLE_LFN || data->lfn_multicast,
    };
    struct wp_ie_list wp_ies = {
        .us  = true,
        .bs  = !data->TxAckReq,
        .pom = ws_info->phy_config.phy_op_modes[0],
        // Include JM-IE in broadcast ULAD frames if PA transmissions are suppressed.
        .jm  = ws_info->pan_information.jm.mask &&
               data->DstAddrMode == IEEE802154_ADDR_MODE_NONE &&
               ws_info->mngt.trickle_pa.c >= ws_info->mngt.trickle_params.k,
    };
    uint24_t adjusted_offset_ms = 0;
    uint24_t adjusted_listening_interval = 0;

    //Allocate Message
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        mcps_data_cnf_t data_conf;
        memset(&data_conf, 0, sizeof(mcps_data_cnf_t));
        data_conf.hif.handle = data->msduHandle;
        data_conf.hif.status = HIF_STATUS_NOMEM;
        user_cb->data_confirm(&base->mpx_data_base.mpx_api, &data_conf);
        return;
    }

    //Add To active list
    llc_message_id_allocate(message, base, true);
    base->llc_message_list_size++;
    red_aq_calc(&base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);

    mcps_data_req_t data_req;
    message->mpx_user_handle = data->msduHandle;
    message->ack_requested = data->TxAckReq;
    message->message_type = WS_FT_DATA;
    message->security = data->Key;
    if (data->DstAddrMode == IEEE802154_ADDR_MODE_64_BIT) {
        message->dst_address_type = data->DstAddrMode;
        memcpy(message->dst_address, data->DstAddr, 8);
        if (ws_neigh) {
            if (ws_neigh->edfe_mode == WS_EDFE_DEFAULT)
                wh_ies.fc = ws_info->edfe_mode == WS_EDFE_ENABLED;
            else
                wh_ies.fc = ws_neigh->edfe_mode == WS_EDFE_ENABLED;
        }
    } else {
        memset(message->dst_address, 0xff, sizeof(message->dst_address));
    }

    data_req = *data;
    data_req.msdu = NULL;
    data_req.msduLength = 0;
    data_req.msduHandle = message->msg_handle;

    /**
     * Wi-SUN FAN 1.1v08 - 6.3.4.3.1.2 Extended Directed Frame Exchange
     * All EDFE frames are ULAD frames populated as described in section
     * 6.3.2.1.6. The AR field MUST be set to 0.
     */
    if (wh_ies.fc) {
        data_req.TxAckReq = false;
        message->ack_requested = false;
    }

    if (ws_neigh) {
        ws_llc_fill_rates(ws_info, ws_neigh, message->rate_list);
        // Do not send default params to the RCP to save some bytes
        if (data_req.rate_list[0].phy_mode_id != ws_info->phy_config.phy_mode_id_ms_base ||
            data_req.rate_list[0].tx_power_dbm != ws_info->tx_power_dbm)
            memcpy(data_req.rate_list, message->rate_list, sizeof(data_req.rate_list));
        else
            memset(data_req.rate_list, 0, sizeof(data_req.rate_list));
        data_req.ms_mode = ws_neigh->ms_mode == WS_MODE_SWITCH_DEFAULT ? ws_info->phy_config.ms_mode : ws_neigh->ms_mode;
    }
    data_req.frame_type = WS_FT_DATA;

    /**
     * Wi-SUN FAN 1.1v08 - 6.3.2.1.6 Upper Layer Application Data Frame
     * For unicast ULAD frames:
     *   2. PAN ID Compression field MUST be set to 1.
     * For broadcast ULAD frames:
     *   2. PAN ID Compression field MUST be set to 0.
     *   3. Destination Addressing Mode field MUST be set to 0.
     */
    if (!ws_neigh) {
        data_req.PanIdSuppressed = false;
        data_req.DstAddrMode = IEEE802154_ADDR_MODE_NONE;
    } else {
        data_req.PanIdSuppressed = true;
    }

    if (node_role == WS_NR_ROLE_LFN || data->lfn_multicast)
        data_req.fhss_type = data_req.DstAddrMode ? HIF_FHSS_TYPE_LFN_UC : HIF_FHSS_TYPE_LFN_BC;
    else
        data_req.fhss_type = data_req.DstAddrMode ? HIF_FHSS_TYPE_FFN_UC : HIF_FHSS_TYPE_FFN_BC;

    ws_llc_prepare_ie(base, message, &wh_ies, &wp_ies);

    // Adding another parameter to the MAC's API just for LTO was not a good idea.
    // The chosen solution is to write the computed LTO information in the LTO-IE.
    // The MAC then reads these information and calculates the actual offset to
    // be applied based on the target's current broadcast schedule offset.
    if (node_role == WS_NR_ROLE_LFN && !data->lfn_multicast) {
        adjusted_listening_interval = ws_neigh_calc_lfn_adjusted_interval(base->interface_ptr->ws_info.fhss_config.lfn_bc_interval,
                                                                                   ws_neigh->fhss_data.lfn.uc_listen_interval_ms,
                                                                                   ws_neigh->lto_info.uc_interval_min_ms,
                                                                                   ws_neigh->lto_info.uc_interval_max_ms);
        adjusted_offset_ms = ws_neigh_calc_lfn_offset(adjusted_listening_interval,
                                                   base->interface_ptr->ws_info.fhss_config.lfn_bc_interval);
        if ((adjusted_listening_interval != ws_neigh->fhss_data.lfn.uc_listen_interval_ms ||
            !ws_neigh->lto_info.offset_adjusted) && adjusted_listening_interval != 0 && adjusted_offset_ms != 0) {
            // FIXME: insert LTO-IE in ws_llc_prepare_ie()
            ws_wh_lto_write(&message->ie_buf_header, adjusted_offset_ms, adjusted_listening_interval);
            ws_neigh->lto_info.offset_adjusted = true;
            message->ie_iov_header.iov_base = message->ie_buf_header.data;
            message->ie_iov_header.iov_len = message->ie_buf_header.len;
        }
    }

    message->ie_iov_payload[1].iov_base = data->msdu;
    message->ie_iov_payload[1].iov_len = data->msduLength;
    ws_llc_lowpan_mpx_header_write(message, MPX_ID_6LOWPAN);
    message->ie_iov_payload[0].iov_len = message->ie_buf_payload.len;
    message->ie_iov_payload[0].iov_base = message->ie_buf_payload.data;
    message->ie_ext.payloadIeVectorList = message->ie_iov_payload;
    message->ie_ext.payloadIovLength = 2;

    message->tx_time = time_now_s(CLOCK_MONOTONIC);

    ws_trace_llc_mac_req(&data_req, message);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &message->ie_ext);
}

static void ws_llc_eapol_data_req_init(mcps_data_req_t *data_req, llc_message_t *message)
{
    memset(data_req, 0, sizeof(mcps_data_req_t));
    data_req->TxAckReq = message->ack_requested;
    data_req->DstPANId = message->pan_id;
    data_req->SrcAddrMode = message->src_address_type;
    if (!data_req->TxAckReq) {
        data_req->PanIdSuppressed = false;
        data_req->DstAddrMode = IEEE802154_ADDR_MODE_NONE;
    } else {
        data_req->PanIdSuppressed = true;
        data_req->DstAddrMode = message->dst_address_type;
        memcpy(data_req->DstAddr, message->dst_address, 8);
    }


    data_req->msdu = NULL;
    data_req->msduLength = 0;
    data_req->msduHandle = message->msg_handle;
    data_req->frame_type = message->message_type;
    ws_llc_lowpan_mpx_header_write(message, MPX_ID_KMP);
}

static void ws_llc_mpx_eapol_send(llc_data_base_t *base, llc_message_t *message)
{
    mcps_data_req_t data_req;

    //Allocate message ID
    llc_message_id_allocate(message, base, true);
    base->llc_message_list_size++;
    red_aq_calc(&base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);
    ws_llc_eapol_data_req_init(&data_req, message);
    base->temp_entries.active_eapol_session = true;
    BUG_ON(data_req.DstAddrMode != IEEE802154_ADDR_MODE_64_BIT); // EAPOL frames are unicast
    if (ws_llc_get_node_role(base->interface_ptr, message->dst_address) == WS_NR_ROLE_LFN)
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_UC;
    else
        data_req.fhss_type = HIF_FHSS_TYPE_FFN_UC;

    message->tx_time = time_now_s(CLOCK_MONOTONIC);

    ws_trace_llc_mac_req(&data_req, message);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &message->ie_ext);
}


static void ws_llc_mpx_eapol_request(llc_data_base_t *base, mpx_user_t *user_cb, const struct mcps_data_req *data)
{
    bool eapol_handshake_first_msg = ws_eapol_handshake_first_msg(data->msdu, data->msduLength, base->interface_ptr);
    struct wh_ie_list wh_ies = {
        .utt = true,
        .bt  = true,
        .ea  = eapol_handshake_first_msg,
    };
    struct wp_ie_list wp_ies = {
        .us = true,
        .bs = eapol_handshake_first_msg,
    };

    //Allocate Message
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        mcps_data_cnf_t data_conf;
        memset(&data_conf, 0, sizeof(mcps_data_cnf_t));
        data_conf.hif.handle = data->msduHandle;
        data_conf.hif.status = HIF_STATUS_NOMEM;
        user_cb->data_confirm(&base->mpx_data_base.mpx_api, &data_conf);
        return;
    }
    message->mpx_user_handle = data->msduHandle;
    message->ack_requested = data->TxAckReq;

    message->src_address_type = data->SrcAddrMode;
    memcpy(message->dst_address, data->DstAddr, 8);
    message->dst_address_type = data->DstAddrMode;
    message->pan_id = data->DstPANId;
    message->message_type = WS_FT_EAPOL;
    message->security = data->Key;

    ws_llc_prepare_ie(base, message, &wh_ies, &wp_ies);
    message->ie_iov_payload[1].iov_base = data->msdu;
    message->ie_iov_payload[1].iov_len = data->msduLength;
    message->ie_ext.payloadIovLength = 2;

    if (base->temp_entries.active_eapol_session) {
        //Move to pending list
        ns_list_add_to_end(&base->temp_entries.llc_eap_pending_list, message);
        base->temp_entries.llc_eap_pending_list_size++;
        red_aq_calc(&base->interface_ptr->llc_eapol_random_early_detection, base->temp_entries.llc_eap_pending_list_size);
    } else {
        ws_llc_mpx_eapol_send(base, message);
    }
}


static void ws_llc_mpx_data_request(const mpx_api_t *api, const struct mcps_data_req *data, uint16_t user_id)
{
    struct llc_data_base *base = &g_llc_base;
    mpx_user_t *user_cb = ws_llc_mpx_user_discover(&base->mpx_data_base, user_id);

    if (!user_cb || !user_cb->data_confirm || !user_cb->data_ind) {
        return;
    }

    if (user_id == MPX_ID_KMP) {
        ws_llc_mpx_eapol_request(base, user_cb, data);
    } else if (user_id == MPX_ID_6LOWPAN) {
        ws_llc_lowpan_mpx_data_request(base, user_cb, data);
    }
}

static int8_t ws_llc_mpx_data_cb_register(const mpx_api_t *api, mpx_data_confirm *confirm_cb, mpx_data_indication *indication_cb, uint16_t user_id)
{
    struct llc_data_base *base = &g_llc_base;
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
    struct llc_data_base *base = &g_llc_base;

    return ws_mpx_header_size_get(base, user_id);
}

static void ws_llc_mpx_init(mpx_class_t *mpx_class)
{
    //Init Mbed Class and API
    mpx_class->mpx_user_table[0].user_id = MPX_ID_6LOWPAN;
    mpx_class->mpx_user_table[1].user_id = MPX_ID_KMP;
    mpx_class->mpx_api.mpx_headroom_size_get = &ws_llc_mpx_header_size_get;
    mpx_class->mpx_api.mpx_user_registration = &ws_llc_mpx_data_cb_register;
    mpx_class->mpx_api.mpx_data_request = &ws_llc_mpx_data_request;
}

static void ws_llc_clean(llc_data_base_t *base)
{
    //Clean Message queue's
    ns_list_foreach_safe(llc_message_t, message, &base->llc_message_list) {
        if (message->message_type == WS_FT_EAPOL) {
            ws_llc_mac_eapol_clear(base);
        }
        rcp_req_data_tx_abort(base->interface_ptr->rcp, message->msg_handle);
        llc_message_free(message, base);
    }

    ns_list_foreach_safe(llc_message_t, message, &base->temp_entries.llc_eap_pending_list) {
        ns_list_remove(&base->temp_entries.llc_eap_pending_list, message);
        free(message);
    }
    base->temp_entries.llc_eap_pending_list_size = 0;
    base->temp_entries.active_eapol_session = false;
    memset(&base->ie_params, 0, sizeof(llc_ie_params_t));

    //Disable High Priority mode
    base->high_priority_mode = false;
}

#define MS_FALLBACK_MIN_SAMPLE 50
#define MS_FALLBACK_MAX_SAMPLE 1000
// Mode Switch rate management function
static void ws_llc_rate_handle_tx_conf(llc_data_base_t *base, const mcps_data_cnf_t *data, struct ws_neigh *neighbor)
{
    struct ws_phy_config *schedule = &base->interface_ptr->ws_info.phy_config;
    uint8_t i;

    if (data->success_phy_mode_id == schedule->phy_mode_id_ms_base)
        neighbor->ms_tx_count++;

    if (data->hif.tx_retries) {
        // Look for mode switch retries
        for (i = 0; i < ARRAY_SIZE(data->retry_per_rate); i++) {
            if (data->retry_per_rate[i].phy_mode_id == schedule->phy_mode_id_ms_base) {
                neighbor->ms_retries_count += data->retry_per_rate[i].retries;
            }
        }
    }

    // Mode switch fallback management
    if (neighbor->ms_tx_count + neighbor->ms_retries_count > MS_FALLBACK_MIN_SAMPLE) {
        if (neighbor->ms_retries_count > 4 * neighbor->ms_tx_count) {
            // Fallback: disable mode switch
            schedule->ms_mode = WS_MODE_SWITCH_DISABLED;

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

int8_t ws_llc_create(struct net_if *interface,
                     ws_llc_mngt_ind_cb *mngt_ind, ws_llc_mngt_cnf_cb *mngt_cnf)
{
    struct llc_data_base *base = &g_llc_base;

    ns_list_init(&base->temp_entries.llc_eap_pending_list);
    ns_list_init(&base->llc_message_list);
    base->interface_ptr = interface;
    base->mngt_ind = mngt_ind;
    base->mngt_cnf = mngt_cnf;
    //Init MPX class
    ws_llc_mpx_init(&base->mpx_data_base);
    return 0;
}

int8_t ws_llc_delete(struct net_if *interface)
{
    struct llc_data_base *base = &g_llc_base;

    ws_llc_clean(base);
    return 0;
}



void ws_llc_reset(struct net_if *interface)
{
    struct llc_data_base *base = &g_llc_base;

    ws_llc_clean(base);
}

mpx_api_t *ws_llc_mpx_api_get(struct net_if *interface)
{
    struct llc_data_base *base = &g_llc_base;

    return &base->mpx_data_base.mpx_api;
}

int8_t ws_llc_asynch_request(struct ws_info *ws_info, struct ws_llc_mngt_req *request)
{
    struct llc_data_base *base = &g_llc_base;

    if (base->high_priority_mode) {
        //Drop asynch messages at High Priority mode
        return -1;
    }

    if ((request->frame_type == WS_FT_PA && ws_info->mngt.pan_advert_running) ||
        (request->frame_type == WS_FT_PC && ws_info->mngt.pan_config_running)) {
        TRACE(TR_TX_ABORT, "tx-abort %-9s: async tx already in progress",
              tr_ws_frame(request->frame_type));
        return -1;
    }
    if (request->frame_type == WS_FT_PA)
        ws_info->mngt.pan_advert_running = true;
    if (request->frame_type == WS_FT_PC)
        ws_info->mngt.pan_config_running = true;

    //Allocate LLC message pointer
    llc_message_t *message = llc_message_allocate(base);
    if (!message) {
        if (base->mngt_cnf) {
            base->mngt_cnf(ws_info, request->frame_type);
        }
        return 0;
    }

    //Add To active list
    llc_message_id_allocate(message, base, false);
    base->llc_message_list_size++;
    red_aq_calc(&base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, message);
    message->message_type = request->frame_type;
    message->security = request->security;
    memset(message->dst_address, 0xff, sizeof(message->dst_address));

    mcps_data_req_t data_req;
    memset(&data_req, 0, sizeof(mcps_data_req_t));
    data_req.SeqNumSuppressed = true;
    data_req.SrcAddrMode = IEEE802154_ADDR_MODE_64_BIT;
    data_req.Key = request->security;
    data_req.msduHandle = message->msg_handle;
    data_req.frame_type = request->frame_type;
    if (request->frame_type == WS_FT_PAS)
        data_req.PanIdSuppressed = true;
    data_req.fhss_type = HIF_FHSS_TYPE_ASYNC;

    ws_llc_prepare_ie(base, message, &request->wh_ies, &request->wp_ies);

    message->tx_time = time_now_s(CLOCK_MONOTONIC);

    ws_trace_llc_mac_req(&data_req, message);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &message->ie_ext);

    return 0;
}

// TODO: Factorize this with MPX and EAPOL
// The Wi-SUN spec uses the term "directed frames" for LPA and LPC, but it
// seems to just mean unicast.
int ws_llc_mngt_lfn_request(const struct ws_llc_mngt_req *req, const uint8_t dst[8])
{
    struct llc_data_base *base = &g_llc_base;
    mcps_data_req_t data_req = {
        .SeqNumSuppressed = true,
        .PanIdSuppressed  = true,
        .SrcAddrMode = IEEE802154_ADDR_MODE_64_BIT,
        .DstAddrMode = dst ? IEEE802154_ADDR_MODE_64_BIT : IEEE802154_ADDR_MODE_NONE,
        .frame_type = req->frame_type,
        .Key = req->security,
    };
    llc_message_t *msg;

    msg = llc_message_allocate(base);
    if (!msg) {
        WARN("%s: tx abort", __func__);
        // FIXME: No confirmation callback
        return 0;
    }

    // Add To active list
    llc_message_id_allocate(msg, base, false);
    base->llc_message_list_size++;
    red_aq_calc(&base->interface_ptr->llc_random_early_detection, base->llc_message_list_size);
    ns_list_add_to_end(&base->llc_message_list, msg);
    msg->message_type = req->frame_type;
    msg->security     = req->security;

    if (dst) {
        memcpy(msg->dst_address, dst, sizeof(msg->dst_address));
        memcpy(data_req.DstAddr, dst, sizeof(data_req.DstAddr));
    } else {
        // FIXME: This timer should be restarted at confirmation instead
        if (req->wh_ies.lbt)
            ws_timer_start(WS_TIMER_LTS);
        // Broadcast LPC are the only LFN frames that include a source PAN ID
        if (req->frame_type == WS_FT_LPC)
            data_req.PanIdSuppressed = false;
        memset(msg->dst_address, 0xff, sizeof(msg->dst_address));
    }
    if (!dst)
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_BC;
    else if (req->frame_type == WS_FT_LPA)
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_PA;
    else
        data_req.fhss_type = HIF_FHSS_TYPE_LFN_UC;
    data_req.msduHandle = msg->msg_handle;

    ws_llc_prepare_ie(base, msg, &req->wh_ies, &req->wp_ies);

    msg->tx_time = time_now_s(CLOCK_MONOTONIC);

    ws_trace_llc_mac_req(&data_req, msg);
    wsbr_data_req_ext(base->interface_ptr, &data_req, &msg->ie_ext);
    return 0;
}

int8_t ws_llc_set_mode_switch(struct net_if *interface, uint8_t mode, uint8_t phy_mode_id,
                              uint8_t *neighbor_mac_address)
{
    struct ws_neigh *ws_neigh;
    uint8_t peer_phy_mode_id = 0;
    uint8_t i;

    // Can't set default to default
    if (mode == WS_MODE_SWITCH_DEFAULT && !neighbor_mac_address)
        return -EINVAL;
    if (phy_mode_id > 0 && version_older_than(interface->rcp->version_api, 2, 0, 1))
        return -ENOTSUP;
    if (phy_mode_id > 0 && mode == WS_MODE_SWITCH_MAC && version_older_than(interface->rcp->version_api, 2, 1, 0))
        return -ENOTSUP;

    if (mode == WS_MODE_SWITCH_PHY || mode == WS_MODE_SWITCH_MAC) {
        for (i = 0; interface->ws_info.phy_config.phy_op_modes[i]; i++)
            if (phy_mode_id == interface->ws_info.phy_config.phy_op_modes[i])
                break;
        if (!interface->ws_info.phy_config.phy_op_modes[i])
            return -EINVAL;
    }

    if (!neighbor_mac_address) {
        interface->ws_info.phy_config.phy_mode_id_ms_tx = phy_mode_id;
        interface->ws_info.phy_config.ms_mode = mode;
    } else {
        ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, neighbor_mac_address);
        if (!ws_neigh)
            return -EINVAL;

        if (mode == WS_MODE_SWITCH_PHY || mode == WS_MODE_SWITCH_MAC) {
            peer_phy_mode_id = ws_llc_find_phy_mode_id(ws_neigh->pom_ie.phy_op_mode_id,
                                                       ws_neigh->pom_ie.phy_op_mode_number,
                                                       phy_mode_id);
            if (peer_phy_mode_id != phy_mode_id)
                return -EINVAL;
        }

        ws_neigh->ms_phy_mode_id = peer_phy_mode_id;
        ws_neigh->ms_mode = mode;
        ws_neigh->ms_tx_count = 0;
        ws_neigh->ms_retries_count = 0;
    }

    return 0;
}

int ws_llc_set_edfe(struct net_if *interface, enum ws_edfe_mode mode, uint8_t *neighbor_mac_address)
{
    struct ws_neigh *ws_neigh;

    if (!neighbor_mac_address) {
        interface->ws_info.edfe_mode = mode;
    } else {
        ws_neigh = ws_neigh_get(&interface->ws_info.neighbor_storage, neighbor_mac_address);
        if (!ws_neigh)
            return -1;
        ws_neigh->edfe_mode = mode;
    }
    return 0;
}
