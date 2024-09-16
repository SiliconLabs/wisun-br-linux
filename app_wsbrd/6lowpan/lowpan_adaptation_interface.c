/*
 * Copyright (c) 2016-2021, Pelion and affiliates.
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "common/endian.h"
#include "common/rcp_api.h"
#include "common/rand.h"
#include "common/dhcp_server.h"
#include "common/log_legacy.h"
#include "common/ns_list.h"
#include "common/version.h"
#include "common/memutils.h"
#include "common/specs/ieee802154.h"
#include "common/specs/ws.h"
#include "common/specs/ip.h"

#include "common/random_early_detection.h"
#include "common/events_scheduler.h"

#include "app/wsbrd.h"
#include "app/wsbr_mac.h"
#include "net/timers.h"
#include "net/netaddr_types.h"
#include "net/ns_buffer.h"
#include "net/ns_address_internal.h"
#include "net/ns_error_types.h"
#include "net/protocol.h"
#include "6lowpan/iphc_decode/cipv6.h"
#include "6lowpan/mac/mac_helper.h"
#include "6lowpan/mac/mpx_api.h"
#include "6lowpan/iphc_decode/iphc_decompress.h"
#include "ws/ws_bootstrap.h"
#include "ws/ws_llc.h"

#include "6lowpan/lowpan_adaptation_interface.h"

#define TRACE_GROUP "6lAd"

#define ADAPTION_DIRECT_TX_QUEUE_SIZE_THRESHOLD_TRACE 20
#define LFN_BUFFER_TIMEOUT_PARAM 4

typedef struct fragmenter_tx_entry {
    uint16_t tag;   /*!< Fragmentation datagram TAG ID */
    uint16_t size;  /*!< Datagram Total Size (uncompressed) */
    uint16_t orig_size; /*!< Datagram Original Size (compressed) */
    uint16_t frag_max;  /*!< Maximum fragment size (MAC payload) */
    uint16_t offset; /*!< Data offset from datagram start */
    int16_t pattern; /*!< Size of compressed LoWPAN headers */
    uint16_t unfrag_ptr; /*!< Offset within buf of headers that precede the FRAG header */
    uint16_t frag_len;
    uint8_t unfrag_len; /*!< Length of headers that precede the FRAG header */
    bool fragmented_data: 1;
    bool first_fragment: 1;
    buffer_t *buf;
    uint8_t *fragmenter_buf;
    ns_list_link_t      link; /*!< List link entry */
} fragmenter_tx_entry_t;


typedef NS_LIST_HEAD(fragmenter_tx_entry_t, link) fragmenter_tx_list_t;

typedef struct fragmenter_interface {
    int8_t interface_id;
    uint16_t local_frag_tag;
    uint8_t msduHandle;
    uint8_t *fragment_indirect_tx_buffer; //Used for write fragmentation header
    fragmenter_tx_entry_t active_broadcast_tx_buf; //Current active direct broadcast tx process
    fragmenter_tx_entry_t active_lfn_broadcast_tx_buf; //Current active direct lfn broadcast tx process
    fragmenter_tx_list_t activeUnicastList; //Unicast packets waiting data confirmation from MAC
    buffer_list_t directTxQueue; //Waiting free tx process
    uint16_t directTxQueue_size;
    uint16_t directTxQueue_level;
    uint16_t activeTxList_size;
    bool fragmenter_active; /*!< Fragmenter state */
    mpx_api_t *mpx_api;
    uint16_t mpx_user_id;
    ns_list_link_t      link; /*!< List link entry */
} fragmenter_interface_t;

#define LOWPAN_ACTIVE_UNICAST_ONGOING_MAX 10
#define LOWPAN_HIGH_PRIORITY_STATE_LENGTH 50 //5 seconds 100us ticks

#define LOWPAN_TX_BUFFER_AGE_LIMIT_LOW_PRIORITY     30 // Remove low priority packets older than limit (seconds)
#define LOWPAN_TX_BUFFER_AGE_LIMIT_HIGH_PRIORITY    60 // Remove high priority packets older than limit (seconds)
#define LOWPAN_TX_BUFFER_AGE_LIMIT_EF_PRIORITY      120 // Remove expedited forwarding packets older than limit (seconds)

static NS_LIST_DEFINE(fragmenter_interface_list, fragmenter_interface_t, link);

/* Adaptation interface local functions */
static fragmenter_interface_t *lowpan_adaptation_interface_discover(int8_t interfaceId);

/* Interface direct message pending queue functions */
static void lowpan_adaptation_tx_queue_write(struct net_if *cur, fragmenter_interface_t *interface_ptr, buffer_t *buf);
static buffer_t *lowpan_adaptation_tx_queue_read(struct net_if *cur, fragmenter_interface_t *interface_ptr);

/* Data direction and message length validation */
static bool lowpan_adaptation_request_longer_than_mtu(struct net_if *cur, buffer_t *buf, fragmenter_interface_t *interface_ptr);

/* Common data tx request process functions */
static void lowpan_active_buffer_state_reset(fragmenter_tx_entry_t *tx_buffer);
static uint8_t lowpan_data_request_unique_handle_get(fragmenter_interface_t *interface_ptr);
static fragmenter_tx_entry_t *lowpan_indirect_entry_allocate(uint16_t fragment_buffer_size);
static fragmenter_tx_entry_t *lowpan_adaptation_tx_process_init(fragmenter_interface_t *interface_ptr,
                                                                bool is_unicast, bool lfn_multicast);
static void lowpan_adaptation_data_request_primitiv_set(const buffer_t *buf, mcps_data_req_t *dataReq, struct net_if *cur);
static void lowpan_data_request_to_mac(struct net_if *cur, buffer_t *buf, fragmenter_tx_entry_t *tx_ptr, fragmenter_interface_t *interface_ptr);

/* Tx confirmation local functions */
static bool lowpan_active_tx_handle_verify(uint8_t handle, buffer_t *buf);
static fragmenter_tx_entry_t *lowpan_listed_tx_handle_verify(uint8_t handle, fragmenter_tx_list_t *indirect_tx_queue);
static void lowpan_adaptation_data_process_clean(fragmenter_interface_t *interface_ptr, fragmenter_tx_entry_t *tx_ptr);
static bool lowpan_adaptation_tx_process_ready(fragmenter_tx_entry_t *tx_ptr);

/* Fragmentation local functions */
static int8_t lowpan_message_fragmentation_init(buffer_t *buf, fragmenter_tx_entry_t *frag_entry, struct net_if *cur, fragmenter_interface_t *interface_ptr);
static bool lowpan_message_fragmentation_message_write(const fragmenter_tx_entry_t *frag_entry, mcps_data_req_t *dataReq);

static bool lowpan_buffer_tx_allowed(fragmenter_interface_t *interface_ptr, buffer_t *buf);

static void lowpan_adaptation_interface_data_ind(struct net_if *cur, const mcps_data_ind_t *data_ind);
static int8_t lowpan_adaptation_interface_tx_confirm(struct net_if *cur, const mcps_data_cnf_t *confirm);

//Discover
static fragmenter_interface_t *lowpan_adaptation_interface_discover(int8_t interfaceId)
{

    ns_list_foreach(fragmenter_interface_t, interface_ptr, &fragmenter_interface_list) {
        if (interfaceId == interface_ptr->interface_id) {
            return interface_ptr;
        }
    }

    return NULL;
}

static struct net_if *lowpan_adaptation_network_interface_discover(const mpx_api_t *api)
{

    ns_list_foreach(fragmenter_interface_t, interface_ptr, &fragmenter_interface_list) {
        if (api == interface_ptr->mpx_api) {
            return protocol_stack_interface_info_get_by_id(interface_ptr->interface_id);
        }
    }

    return NULL;
}


static void lowpan_adaptation_tx_queue_level_update(struct net_if *cur, fragmenter_interface_t *interface_ptr)
{
    red_aq_calc(&cur->random_early_detection, interface_ptr->directTxQueue_size);

    if (interface_ptr->directTxQueue_size == interface_ptr->directTxQueue_level + ADAPTION_DIRECT_TX_QUEUE_SIZE_THRESHOLD_TRACE ||
            interface_ptr->directTxQueue_size == interface_ptr->directTxQueue_level - ADAPTION_DIRECT_TX_QUEUE_SIZE_THRESHOLD_TRACE) {
        interface_ptr->directTxQueue_level = interface_ptr->directTxQueue_size;
        tr_info("Adaptation layer TX queue size %u Active MAC tx request %u", interface_ptr->directTxQueue_level, interface_ptr->activeTxList_size);
    }
}


static void lowpan_adaptation_tx_queue_write(struct net_if *cur, fragmenter_interface_t *interface_ptr, buffer_t *buf)
{
    TRACE(TR_QUEUE, "queue: frame enqueued dst:%s", tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
    ns_list_add_to_end(&interface_ptr->directTxQueue, buf);
    interface_ptr->directTxQueue_size++;
    lowpan_adaptation_tx_queue_level_update(cur, interface_ptr);
}

static void lowpan_adaptation_tx_queue_write_to_front(struct net_if *cur, fragmenter_interface_t *interface_ptr, buffer_t *buf)
{
    TRACE(TR_QUEUE, "queue: frame enqueued front dst:%s", tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
    ns_list_add_to_start(&interface_ptr->directTxQueue, buf);
    interface_ptr->directTxQueue_size++;
    lowpan_adaptation_tx_queue_level_update(cur, interface_ptr);
}

static buffer_t *lowpan_adaptation_tx_queue_read(struct net_if *cur, fragmenter_interface_t *interface_ptr)
{
    TRACE(TR_QUEUE, "queue: looking for frame to tx");
    // Currently this function is called only when data confirm is received for previously sent packet.
    if (!interface_ptr->directTxQueue_size) {
        return NULL;
    }
    ns_list_foreach_safe(buffer_t, buf, &interface_ptr->directTxQueue) {
        if (lowpan_buffer_tx_allowed(interface_ptr, buf)) {
            ns_list_remove(&interface_ptr->directTxQueue, buf);
            interface_ptr->directTxQueue_size--;
            lowpan_adaptation_tx_queue_level_update(cur, interface_ptr);
            TRACE(TR_QUEUE, "queue: frame dequeued dst:%s", tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
            return buf;
        }
    }
    return NULL;
}

//fragmentation needed

static bool lowpan_adaptation_request_longer_than_mtu(struct net_if *cur, buffer_t *buf, fragmenter_interface_t *interface_ptr)
{
    uint16_t overhead = mac_helper_frame_overhead(cur, buf);

    if (interface_ptr->mpx_api) {
        overhead += interface_ptr->mpx_api->mpx_headroom_size_get(interface_ptr->mpx_api, interface_ptr->mpx_user_id);
    }

    return buffer_data_length(buf) > cur->mac_parameters.mtu - overhead;
}

static void lowpan_active_buffer_state_reset(fragmenter_tx_entry_t *tx_buffer)
{
    if (tx_buffer->buf) {
        buffer_free(tx_buffer->buf);
        tx_buffer->buf = NULL;
    }
    tx_buffer->fragmented_data = false;
    tx_buffer->first_fragment = true;
}

static bool lowpan_active_tx_handle_verify(uint8_t handle, buffer_t *buf)
{

    if (buf && buf->seq == handle) {
        return true;
    }


    return false;
}



static fragmenter_tx_entry_t *lowpan_listed_tx_handle_verify(uint8_t handle, fragmenter_tx_list_t *indirect_tx_queue)
{
    ns_list_foreach(fragmenter_tx_entry_t, entry, indirect_tx_queue) {
        if (entry->buf->seq == handle) {
            return entry;
        }
    }
    return NULL;
}



static uint8_t lowpan_data_request_unique_handle_get(fragmenter_interface_t *interface_ptr)
{
    bool valid_info = false;
    uint8_t handle;
    while (!valid_info) {
        handle = interface_ptr->msduHandle++;
        if (!lowpan_listed_tx_handle_verify(handle, &interface_ptr->activeUnicastList) &&
            !lowpan_active_tx_handle_verify(handle, interface_ptr->active_broadcast_tx_buf.buf) &&
            !lowpan_active_tx_handle_verify(handle, interface_ptr->active_lfn_broadcast_tx_buf.buf)) {
            valid_info = true;
        }
    }
    return handle;

}

static void lowpan_list_entry_free(fragmenter_tx_list_t *list, fragmenter_tx_entry_t *entry)
{
    ns_list_remove(list, entry);
    if (entry->buf) {
        buffer_free(entry->buf);
    }
    free(entry->fragmenter_buf);
    free(entry);
}

static void lowpan_list_free(fragmenter_tx_list_t *list, bool fragment_buf_free)
{
    while (!ns_list_is_empty(list)) {
        fragmenter_tx_entry_t *entry = ns_list_get_first(list);
        if (!fragment_buf_free) {
            //We can't free this pointer becuase it must be until interface is deleted
            entry->fragmenter_buf = NULL;
        }
        lowpan_list_entry_free(list, entry);
    }
}

void lowpan_adaptation_interface_init(int8_t interface_id)
{
    fragmenter_interface_t *interface_ptr = zalloc(sizeof(fragmenter_interface_t));

    lowpan_adaptation_interface_free(interface_id);

    interface_ptr->interface_id = interface_id;
    interface_ptr->msduHandle = rand_get_8bit();
    interface_ptr->local_frag_tag = rand_get_16bit();

    ns_list_init(&interface_ptr->directTxQueue);
    ns_list_init(&interface_ptr->activeUnicastList);

    ns_list_add_to_end(&fragmenter_interface_list, interface_ptr);
}

int8_t lowpan_adaptation_interface_free(int8_t interface_id)
{
    //Discover
    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(interface_id);
    if (!interface_ptr) {
        return -1;
    }

    ns_list_remove(&fragmenter_interface_list, interface_ptr);
    //free active tx process
    lowpan_list_free(&interface_ptr->activeUnicastList, false);
    interface_ptr->activeTxList_size = 0;
    lowpan_active_buffer_state_reset(&interface_ptr->active_broadcast_tx_buf);
    lowpan_active_buffer_state_reset(&interface_ptr->active_lfn_broadcast_tx_buf);

    buffer_free_list(&interface_ptr->directTxQueue);
    interface_ptr->directTxQueue_size = 0;
    interface_ptr->directTxQueue_level = 0;
    //Free Dynamic allocated entries
    free(interface_ptr->fragment_indirect_tx_buffer);
    free(interface_ptr);

    return 0;
}


int8_t lowpan_adaptation_interface_reset(int8_t interface_id)
{
    //Discover
    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(interface_id);
    if (!interface_ptr) {
        return -1;
    }

    //free active tx process
    lowpan_list_free(&interface_ptr->activeUnicastList, false);
    interface_ptr->activeTxList_size  = 0;
    lowpan_active_buffer_state_reset(&interface_ptr->active_broadcast_tx_buf);
    lowpan_active_buffer_state_reset(&interface_ptr->active_lfn_broadcast_tx_buf);
    //Clean fragmented message flag
    interface_ptr->fragmenter_active = false;

    buffer_free_list(&interface_ptr->directTxQueue);
    interface_ptr->directTxQueue_size = 0;
    interface_ptr->directTxQueue_level = 0;

    return 0;
}

static void lowpan_adaptation_mpx_data_confirm(const mpx_api_t *api, const struct mcps_data_cnf *data)
{
    struct net_if *interface = lowpan_adaptation_network_interface_discover(api);

    lowpan_adaptation_interface_tx_confirm(interface, data);
}

static void lowpan_adaptation_mpx_data_indication(const mpx_api_t *api, const struct mcps_data_ind *data)
{
    struct net_if *interface = lowpan_adaptation_network_interface_discover(api);
    lowpan_adaptation_interface_data_ind(interface, data);
}




int8_t lowpan_adaptation_interface_mpx_register(int8_t interface_id, struct mpx_api *mpx_api, uint16_t mpx_user_id)
{
    //Discover
    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(interface_id);
    if (!interface_ptr) {
        return -1;
    }
    if (!mpx_api && interface_ptr->mpx_api) {
        //Disable Data Callbacks from MPX Class
        interface_ptr->mpx_api->mpx_user_registration(interface_ptr->mpx_api, NULL, NULL, interface_ptr->mpx_user_id);
    }

    interface_ptr->mpx_api = mpx_api;
    interface_ptr->mpx_user_id = mpx_user_id;

    if (interface_ptr->mpx_api) {
        //Register MPX callbacks: confirmation and indication
        interface_ptr->mpx_api->mpx_user_registration(interface_ptr->mpx_api, lowpan_adaptation_mpx_data_confirm, lowpan_adaptation_mpx_data_indication, interface_ptr->mpx_user_id);
    }
    return 0;
}

static fragmenter_tx_entry_t *lowpan_indirect_entry_allocate(uint16_t fragment_buffer_size)
{
    fragmenter_tx_entry_t *indirec_entry = malloc(sizeof(fragmenter_tx_entry_t));
    if (!indirec_entry) {
        return NULL;
    }

    if (fragment_buffer_size) {
        indirec_entry->fragmenter_buf = malloc(fragment_buffer_size);
        if (!indirec_entry->fragmenter_buf) {
            free(indirec_entry);
            return NULL;
        }
    } else {
        indirec_entry->fragmenter_buf = NULL;
    }


    indirec_entry->buf = NULL;
    indirec_entry->fragmented_data = false;
    indirec_entry->first_fragment = true;

    return indirec_entry;
}

static int8_t lowpan_message_fragmentation_init(buffer_t *buf, fragmenter_tx_entry_t *frag_entry, struct net_if *cur, fragmenter_interface_t *interface_ptr)
{
    uint8_t *ptr;
    uint16_t uncompressed_size;

    /* Look for pre-fragmentation headers - strip off and store away */
    frag_entry->unfrag_ptr = buf->buf_ptr;
    frag_entry->unfrag_len = 0;
    ptr = buffer_data_pointer(buf);

    if (ptr[0] == LOWPAN_DISPATCH_BC0) {
        ptr += 2;
        buf->buf_ptr += 2;
    }

    frag_entry->unfrag_len = buf->buf_ptr - frag_entry->unfrag_ptr;

    frag_entry->pattern = iphc_header_scan(buf, &uncompressed_size);
    frag_entry->size = buffer_data_length(buf);
    frag_entry->orig_size = frag_entry->size;
    frag_entry->size += (uncompressed_size - frag_entry->pattern);

    uint16_t overhead = mac_helper_frame_overhead(cur, buf);
    if (interface_ptr->mpx_api) {
        overhead += interface_ptr->mpx_api->mpx_headroom_size_get(interface_ptr->mpx_api, interface_ptr->mpx_user_id);
    }

    frag_entry->frag_max = cur->mac_parameters.mtu - overhead;


    /* RFC 4944 says MTU and hence maximum size here is 1280, but that's
     * arbitrary, and some have argued that 6LoWPAN should have a larger
     * MTU, to avoid the need for IP fragmentation. So we don't enforce
     * that, leaving MTU decisions to upper layer config, and only look
     * for the "real" MTU from the FRAG header format, which would allow up
     * to 0x7FF (2047).
     */
    if (frag_entry->size > LOWPAN_HARD_MTU_LIMIT) {
        tr_error("Packet too big");
        return -1;
    }

    frag_entry->offset = uncompressed_size / 8;
    frag_entry->frag_len = frag_entry->pattern;
    if (frag_entry->unfrag_len + 4 + frag_entry->frag_len > frag_entry->frag_max) {
        tr_error("Too long 6LoWPAN header for fragment");
        return -1;
    }

    /* Now, frag_len is compressed payload bytes (just IPHC headers), and
     * frag_ptr->offset is uncompressed payload 8-octet units (just uncompressed
     * IPHC headers). Add post-IPHC payload to bring total compressed size up
     * to maximum fragment size.
     */
    while (frag_entry->unfrag_len + 4 + frag_entry->frag_len + 8 <= frag_entry->frag_max) {
        frag_entry->offset++;
        frag_entry->frag_len += 8;
    }
    frag_entry->fragmented_data = true;

    return 0;

}

/**
 * Return true when there is more fragmented packet for this message
 */
static bool lowpan_message_fragmentation_message_write(const fragmenter_tx_entry_t *frag_entry, mcps_data_req_t *dataReq)
{
    uint8_t *ptr = dataReq->msdu;
    if (frag_entry->unfrag_len) {
        memcpy(ptr, frag_entry->buf->buf  + frag_entry->unfrag_ptr, frag_entry->unfrag_len);
        ptr += frag_entry->unfrag_len;
    }
    if (frag_entry->first_fragment) {
        ptr = write_be16(ptr, ((uint16_t) LOWPAN_FRAG1 << 8) | frag_entry->size);
        ptr = write_be16(ptr, frag_entry->tag);
    } else {
        ptr = write_be16(ptr, ((uint16_t) LOWPAN_FRAGN << 8) | frag_entry->size);
        ptr = write_be16(ptr, frag_entry->tag);
        *ptr++ = frag_entry->offset;
    }
    memcpy(ptr, buffer_data_pointer(frag_entry->buf), frag_entry->frag_len);
    ptr += frag_entry->frag_len;
    dataReq->msduLength = ptr - dataReq->msdu;
    return frag_entry->offset * 8 + frag_entry->frag_len < frag_entry->size;
}

static fragmenter_tx_entry_t *lowpan_adaptation_tx_process_init(fragmenter_interface_t *interface_ptr,
                                                                bool is_unicast, bool lfn_multicast)
{
    // For broadcast, the active TX queue is only 1 entry. For unicast, using a list.
    fragmenter_tx_entry_t *tx_entry;

    if (is_unicast) {
        tx_entry = lowpan_indirect_entry_allocate(0);
        if (!tx_entry) {
            return NULL;
        }
        ns_list_add_to_end(&interface_ptr->activeUnicastList, tx_entry);
        interface_ptr->activeTxList_size++;
    } else if (lfn_multicast) {
        tx_entry = &interface_ptr->active_lfn_broadcast_tx_buf;
    } else {
        tx_entry = &interface_ptr->active_broadcast_tx_buf;
    }
    tx_entry->fragmenter_buf = interface_ptr->fragment_indirect_tx_buffer;

    if (!tx_entry) {
        return NULL;
    }

    lowpan_active_buffer_state_reset(tx_entry);

    return tx_entry;
}

buffer_t *lowpan_adaptation_data_process_tx_preprocess(struct net_if *cur, buffer_t *buf)
{
    struct ws_neigh *ws_neigh;

    //Validate is link known and set indirect, datareq and security key id mode
    if (buf->dst_sa.addr_type == ADDR_NONE) {
        goto tx_error_handler;
    }

    if (addr_check_broadcast(buf->dst_sa.address, buf->dst_sa.addr_type) == eOK) {
        buf->dst_sa.addr_type = ADDR_802_15_4_SHORT;
        buf->dst_sa.address[2] = 0xff;
        buf->dst_sa.address[3] = 0xff;
        buf->link_specific.ieee802_15_4.requestAck = false;
    } else {
        ws_neigh = ws_neigh_get(&cur->ws_info.neighbor_storage, buf->dst_sa.address + PAN_ID_LEN);

        //Validate neighbour
        if (!ws_neigh) {
            TRACE(TR_TX_ABORT, "tx-abort: neighbor %s not found", tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
            goto tx_error_handler;
        }
        if (!ws_neigh->trusted_device) {
            TRACE(TR_TX_ABORT, "tx-abort: neighbor %s not trusted", tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
            goto tx_error_handler;
        }
        buf->link_specific.ieee802_15_4.requestAck = true;
    }

    return buf;

tx_error_handler:
    buffer_free(buf);
    return NULL;

}

static void lowpan_adaptation_data_request_primitiv_set(const buffer_t *buf, mcps_data_req_t *dataReq, struct net_if *cur)
{
    struct ws_neigh *ws_neigh;

    memset(dataReq, 0, sizeof(mcps_data_req_t));
    //Check do we need fragmentation

    dataReq->TxAckReq = buf->link_specific.ieee802_15_4.requestAck;
    dataReq->SrcAddrMode = buf->src_sa.addr_type;
    dataReq->DstAddrMode = buf->dst_sa.addr_type;
    memcpy(dataReq->DstAddr, &buf->dst_sa.address[2], 8);
    dataReq->DstPANId = cur->ws_info.pan_information.pan_id;

    //Allocate message msdu handle
    dataReq->msduHandle = buf->seq;

    //Set Messages
    dataReq->Key.SecurityLevel = IEEE802154_SEC_LEVEL_ENC_MIC64;
    if (dataReq->Key.SecurityLevel) {
        ws_neigh = ws_neigh_get(&cur->ws_info.neighbor_storage, dataReq->DstAddr);

        if ((ws_neigh && ws_neigh->node_role == WS_NR_ROLE_LFN) || buf->options.lfn_multicast)
            dataReq->Key.KeyIndex = cur->ws_info.lfn_gtk_index;
        else
            dataReq->Key.KeyIndex = cur->ws_info.ffn_gtk_index;
    }
}

static void lowpan_data_request_to_mac(struct net_if *cur, buffer_t *buf, fragmenter_tx_entry_t *tx_ptr, fragmenter_interface_t *interface_ptr)
{
    mcps_data_req_t dataReq;

    BUG_ON(!interface_ptr->mpx_api);
    lowpan_adaptation_data_request_primitiv_set(buf, &dataReq, cur);
    if (tx_ptr->fragmented_data) {
        dataReq.msdu = tx_ptr->fragmenter_buf;
        lowpan_message_fragmentation_message_write(tx_ptr, &dataReq);
    } else {
        dataReq.msduLength = buffer_data_length(buf);
        dataReq.msdu = buffer_data_pointer(buf);
    }

    dataReq.lfn_multicast = buf->options.lfn_multicast;
    interface_ptr->mpx_api->mpx_data_request(interface_ptr->mpx_api, &dataReq, interface_ptr->mpx_user_id);
}

static bool lowpan_adaptation_is_destination_tx_active(fragmenter_tx_list_t *list, buffer_t *buf)
{
    ns_list_foreach(fragmenter_tx_entry_t, entry, list) {
        if (entry->buf) {
            if (!memcmp(&entry->buf->dst_sa.address[2], &buf->dst_sa.address[2], 8)) {
                return true;
            }
        }
    }
    return false;
}

static bool lowpan_buffer_tx_allowed(fragmenter_interface_t *interface_ptr, buffer_t *buf)
{
    bool is_unicast = buf->link_specific.ieee802_15_4.requestAck;

    // Do not accept any other TX when fragmented TX active. Prevents other frames to be sent in between two fragments.
    if (interface_ptr->fragmenter_active) {
        TRACE(TR_QUEUE, "queue: tx not allowed: fragmented tx in progress");
        return false;
    }
    // Do not accept more than one active broadcast TX
    if (!is_unicast) {
        if (buf->options.lfn_multicast && interface_ptr->active_lfn_broadcast_tx_buf.buf) {
            TRACE(TR_QUEUE, "queue: tx not allowed: lfn broadcast frame with handle %u already in MAC",
                  interface_ptr->active_lfn_broadcast_tx_buf.buf->seq);
            return false;
        }
        if (!buf->options.lfn_multicast && interface_ptr->active_broadcast_tx_buf.buf) {
            TRACE(TR_QUEUE, "queue: tx not allowed: broadcast frame with handle %u already in MAC",
                  interface_ptr->active_broadcast_tx_buf.buf->seq);
            return false;
        }
    }

    if (is_unicast && interface_ptr->activeTxList_size >= LOWPAN_ACTIVE_UNICAST_ONGOING_MAX) {
        TRACE(TR_QUEUE, "queue: tx not allowed: too many active tx");
        //New TX is not possible there is already too manyactive connecting
        return false;
    }


    // Do not accept more than one active unicast TX per destination
    if (is_unicast && lowpan_adaptation_is_destination_tx_active(&interface_ptr->activeUnicastList, buf)) {
        TRACE(TR_QUEUE, "queue: tx not allowed: unicast frame already in MAC for this destination dst:%s",
              tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
        return false;
    }
    return true;
}

static bool lowpan_adaptation_interface_check_buffer_timeout(struct net_if *cur, buffer_t *buf)
{
    // Convert from 100ms slots to seconds
    uint32_t buffer_age_s = (g_monotonic_time_100ms - buf->adaptation_timestamp) / 10;
    int lfn_bc_interval_s = cur->ws_info.fhss_config.lfn_bc_interval / 1000;
    struct ws_neigh *ws_neigh;
    int lfn_uc_l_interval_s;

    if (buf->options.lfn_multicast)
        return buffer_age_s > LFN_BUFFER_TIMEOUT_PARAM * lfn_bc_interval_s;
    if (buf->link_specific.ieee802_15_4.requestAck) {
        ws_neigh = ws_neigh_get(&cur->ws_info.neighbor_storage, buf->dst_sa.address + PAN_ID_LEN);

        if (!ws_neigh)
            return true;
        if (ws_neigh->node_role == WS_NR_ROLE_LFN) {
            lfn_uc_l_interval_s = ws_neigh->fhss_data.lfn.uc_listen_interval_ms / 1000;
            return buffer_age_s > LFN_BUFFER_TIMEOUT_PARAM * lfn_uc_l_interval_s;
        }
    }
    return buffer_age_s > LOWPAN_TX_BUFFER_AGE_LIMIT_LOW_PRIORITY;
}

int lowpan_adaptation_queue_size(int8_t interface_id)
{
    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(interface_id);

    return interface_ptr->directTxQueue_size;
}

int8_t lowpan_adaptation_interface_tx(struct net_if *cur, buffer_t *buf)
{
    if (!buf) {
        return -1;
    }

    if (!cur) {
        goto tx_error_handler;
    }

    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(cur->id);
    if (!interface_ptr) {
        goto tx_error_handler;
    }

    if (!buf->adaptation_timestamp) {
        // Set TX start timestamp
        buf->adaptation_timestamp = g_monotonic_time_100ms;
        if (!buf->adaptation_timestamp) {
            buf->adaptation_timestamp--;
        }
    } else if (lowpan_adaptation_interface_check_buffer_timeout(cur, buf)) {
        TRACE(TR_TX_ABORT, "tx-abort: buffer timed out dst:%s", tr_eui64(buf->dst_sa.address + PAN_ID_LEN));
        goto tx_error_handler;
    }

    //Check packet size
    bool fragmented_needed = lowpan_adaptation_request_longer_than_mtu(cur, buf, interface_ptr);
    if (fragmented_needed) {
        // If fragmentation TX buffer not allocated, do it now.
        if (!interface_ptr->fragment_indirect_tx_buffer)
            interface_ptr->fragment_indirect_tx_buffer = xalloc(cur->mac_parameters.mtu);
    }
    bool is_unicast = buf->link_specific.ieee802_15_4.requestAck;

    if (!lowpan_buffer_tx_allowed(interface_ptr, buf)) {

        if (red_congestion_check(&cur->random_early_detection)) {
            WARN("congestion detected: dropping oldest packet");
            // If we need to drop packet we drop oldest normal Priority packet.
            buffer_t *dropped = ns_list_get_first(&interface_ptr->directTxQueue);
            if (dropped) {
                TRACE(TR_TX_ABORT, "tx-abort: congestion detected dst:%s",
                      tr_eui64(dropped->dst_sa.address + PAN_ID_LEN));
                ns_list_remove(&interface_ptr->directTxQueue, dropped);
                interface_ptr->directTxQueue_size--;
                buffer_free(dropped);
            }
        }
        lowpan_adaptation_tx_queue_write(cur, interface_ptr, buf);
        return 0;
    }

    //Allocate Handle
    buf->seq = lowpan_data_request_unique_handle_get(interface_ptr);

    fragmenter_tx_entry_t *tx_ptr = lowpan_adaptation_tx_process_init(interface_ptr, is_unicast,
                                                                      buf->options.lfn_multicast);
    if (!tx_ptr) {
        goto tx_error_handler;
    }

    tx_ptr->buf = buf;

    if (fragmented_needed) {
        //Fragmentation init
        if (lowpan_message_fragmentation_init(buf, tx_ptr, cur, interface_ptr)) {
            tr_error("Fragment init fail");
            tx_ptr->buf = NULL;
            goto tx_error_handler;
        }

        tx_ptr->tag = interface_ptr->local_frag_tag++;
        interface_ptr->fragmenter_active = true;
    }

    lowpan_data_request_to_mac(cur, buf, tx_ptr, interface_ptr);
    return 0;

tx_error_handler:
    buffer_free(buf);
    return -1;
}

static bool lowpan_adaptation_tx_process_ready(fragmenter_tx_entry_t *tx_ptr)
{
    if (!tx_ptr->fragmented_data)
        return true;

    //Update data pointer by last packet length
    buffer_data_strip_header(tx_ptr->buf, tx_ptr->frag_len);
    //Update offset
    if (!tx_ptr->first_fragment) {
        tx_ptr->offset += tx_ptr->frag_len / 8;
    } else {
        tx_ptr->first_fragment = false;
    }

    /* Check Is still Data what have to send */
    tx_ptr->frag_len = buffer_data_length(tx_ptr->buf);


    //Release current data
    if (tx_ptr->frag_len == 0)
        return true;

    //Continue Process

    if (tx_ptr->unfrag_len + 5 + tx_ptr->frag_len > tx_ptr->frag_max) {
        tx_ptr->frag_len = tx_ptr->frag_max - 5 - tx_ptr->unfrag_len;
        tx_ptr->frag_len &= ~7;
    }

    return false;
}

static void lowpan_adaptation_data_process_clean(fragmenter_interface_t *interface_ptr, fragmenter_tx_entry_t *tx_ptr)
{
    buffer_t *buf = tx_ptr->buf;

    tx_ptr->buf = NULL;
    if (buf->link_specific.ieee802_15_4.requestAck) {
        ns_list_remove(&interface_ptr->activeUnicastList, tx_ptr);
        free(tx_ptr);
        interface_ptr->activeTxList_size--;
    }
    buffer_free(buf);
}

static int8_t lowpan_adaptation_interface_tx_confirm(struct net_if *cur, const mcps_data_cnf_t *confirm)
{
    uint8_t mlme_status = mlme_status_from_hif(confirm->hif.status);

    if (!cur || !confirm) {
        return -1;
    }

    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(cur->id);
    if (!interface_ptr) {
        return -1;
    }

    //Check first
    fragmenter_tx_entry_t *tx_ptr;
    if (lowpan_active_tx_handle_verify(confirm->hif.handle, interface_ptr->active_broadcast_tx_buf.buf))
        tx_ptr = &interface_ptr->active_broadcast_tx_buf;
    else if (lowpan_active_tx_handle_verify(confirm->hif.handle, interface_ptr->active_lfn_broadcast_tx_buf.buf))
        tx_ptr = &interface_ptr->active_lfn_broadcast_tx_buf;
    else
        tx_ptr = lowpan_listed_tx_handle_verify(confirm->hif.handle, &interface_ptr->activeUnicastList);

    if (!tx_ptr) {
        tr_error("No data request for this confirmation %u", confirm->hif.handle);
        return -1;
    }
    buffer_t *buf = tx_ptr->buf;

    if (mlme_status == MLME_SUCCESS) {
        //Check is there more packets
        if (lowpan_adaptation_tx_process_ready(tx_ptr)) {
            if (tx_ptr->fragmented_data)
                interface_ptr->fragmenter_active = false;
            lowpan_adaptation_data_process_clean(interface_ptr, tx_ptr);
        } else {
            lowpan_data_request_to_mac(cur, buf, tx_ptr, interface_ptr);
        }
    } else {
        if (buf->link_specific.ieee802_15_4.requestAck && mlme_status == MLME_TRANSACTION_EXPIRED) {
            lowpan_adaptation_tx_queue_write_to_front(cur, interface_ptr, buf);
            ns_list_remove(&interface_ptr->activeUnicastList, tx_ptr);
            free(tx_ptr);
            interface_ptr->activeTxList_size--;
        } else {
            if (tx_ptr->fragmented_data) {
                tx_ptr->buf->buf_ptr = tx_ptr->buf->buf_end;
                tx_ptr->buf->buf_ptr -= tx_ptr->orig_size;
                interface_ptr->fragmenter_active = false;
            }
            lowpan_adaptation_data_process_clean(interface_ptr, tx_ptr);
        }
    }
    buffer_t *buf_from_queue = lowpan_adaptation_tx_queue_read(cur, interface_ptr);
    while (buf_from_queue) {
        lowpan_adaptation_interface_tx(cur, buf_from_queue);
        buf_from_queue = lowpan_adaptation_tx_queue_read(cur, interface_ptr);
    }
    return 0;
}

static bool mac_data_is_broadcast_addr(const sockaddr_t *addr)
{
    return (addr->addr_type == ADDR_802_15_4_SHORT) &&
           (addr->address[2] == 0xFF && addr->address[3] == 0xFF);
}

static void lowpan_adaptation_interface_data_ind(struct net_if *cur, const mcps_data_ind_t *data_ind)
{
    buffer_t *buf = buffer_get(data_ind->msduLength);
    if (!buf || !cur) {
        return;
    }
    uint8_t *ptr;
    buffer_data_add(buf, data_ind->msdu_ptr, data_ind->msduLength);
    //tr_debug("MAC Paylod size %u %s",data_ind->msduLength, tr_eui64(data_ind->msdu_ptr));
    buf->src_sa.addr_type = (addrtype_e)data_ind->SrcAddrMode;
    ptr = write_be16(buf->src_sa.address, data_ind->SrcPANId);
    memcpy(ptr, data_ind->SrcAddr, 8);
    ptr = write_be16(buf->dst_sa.address, data_ind->DstPANId);
    // HACK: nanostack uses 0xffff as a broadcast address instead of supporting
    // no address like Wi-SUN. Short address support should be dropped
    // altogether.
    if (data_ind->DstAddrMode != IEEE802154_ADDR_MODE_NONE) {
        memcpy(ptr, data_ind->DstAddr, 8);
        buf->dst_sa.addr_type = data_ind->DstAddrMode;
    } else {
        memset(ptr, 0xff, 8);
        buf->dst_sa.addr_type = ADDR_802_15_4_SHORT;
    }
    //Set Link specific stuff to seperately
    buf->link_specific.ieee802_15_4.srcPanId = data_ind->SrcPANId;
    buf->link_specific.ieee802_15_4.dstPanId = data_ind->DstPANId;
    buf->link_specific.ieee802_15_4.requestAck = data_ind->TxAckReq;

    if (mac_data_is_broadcast_addr(&buf->dst_sa)) {
        buf->options.ll_broadcast_rx = true;
    }
    buf->interface = cur;
    if (data_ind->Key.SecurityLevel) {
        buf->link_specific.ieee802_15_4.fc_security = true;
    } else {
        buf->link_specific.ieee802_15_4.fc_security = false;
        buf->options.ll_security_bypass_rx = true;
    }

    buf->info = (buffer_info_t)(B_TO_IPV6_TXRX | B_FROM_MAC | B_DIR_UP);
    protocol_push(buf);
}

static bool lowpan_tx_buffer_address_compare(sockaddr_t *dst_sa, const uint8_t *address_ptr, addrtype_e adr_type)
{

    if (dst_sa->addr_type != adr_type) {
        return false;
    }

    uint8_t compare_length;
    switch (adr_type) {
        case ADDR_802_15_4_SHORT:
            compare_length = 2;
            break;
        case ADDR_802_15_4_LONG:
            compare_length = 8;
            break;
        default:
            return false;
    }


    if (memcmp(&dst_sa->address[2], address_ptr, compare_length)) {
        return false;
    }
    return true;
}

int8_t lowpan_adaptation_free_messages_from_queues_by_address(struct net_if *cur, const uint8_t *address_ptr, addrtype_e adr_type)
{
    fragmenter_interface_t *interface_ptr = lowpan_adaptation_interface_discover(cur->id);

    if (!interface_ptr) {
        return -1;
    }

    //Check next direct queue
    ns_list_foreach_safe(fragmenter_tx_entry_t, entry, &interface_ptr->activeUnicastList) {
        if (lowpan_tx_buffer_address_compare(&entry->buf->dst_sa, address_ptr, adr_type)) {
            //Purge from mac
            TRACE(TR_TX_ABORT, "tx-abort: associated neighbor deleted handle:%u dst:%s", entry->buf->seq,
                  tr_eui64(entry->buf->dst_sa.address + PAN_ID_LEN));
            lowpan_adaptation_data_process_clean(interface_ptr, entry);
        }
    }

    //Check next directTxQueue there may be pending packets also
    ns_list_foreach_safe(buffer_t, entry, &interface_ptr->directTxQueue) {
        if (lowpan_tx_buffer_address_compare(&entry->dst_sa, address_ptr, adr_type)) {
            TRACE(TR_TX_ABORT, "tx-abort: associated neighbor deleted dst:%s",
                  tr_eui64(entry->dst_sa.address + PAN_ID_LEN));
            ns_list_remove(&interface_ptr->directTxQueue, entry);
            interface_ptr->directTxQueue_size--;
            //Update Average QUEUE
            lowpan_adaptation_tx_queue_level_update(cur, interface_ptr);
            buffer_free(entry);
        }
    }

    return 0;
}
