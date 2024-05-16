/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#ifndef RCP_API_LEGACY_H
#define RCP_API_LEGACY_H
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "common/log.h"
#include "common/rcp_api.h"

struct ws_fhss_config;
struct ws_neigh;
struct iobuf_write;
struct iobuf_read;
struct wsbr_ctxt;
struct bus;
struct net_if;
struct rcp;

struct mlme_security {
    unsigned SecurityLevel: 3;      /**< Security level */
    uint8_t KeyIndex;               /**< Key index */
    uint32_t frame_counter;
};

// Used by rcp_legacy_tx_req_legacy()
// See IEEE standard 802.15.4-2006 (table 41) for more details
typedef struct mcps_data_req {
    unsigned SrcAddrMode: 2;        /**< Source address mode */
    unsigned DstAddrMode: 2;        /**< Destination address mode */
    uint16_t DstPANId;              /**< Destination PAN ID */
    uint8_t DstAddr[8];             /**< Destination address */
    uint16_t msduLength;            /**< Service data unit length */
    uint8_t *msdu;                  /**< Service data unit */
    uint8_t msduHandle;             /**< Handle associated with MSDU */
    bool TxAckReq: 1;               /**< Specifies whether ACK is needed or not */
    bool SeqNumSuppressed: 1;       /**< True suppress sequence number from frame. This will be only checked when 2015 extension is enabled */
    bool PanIdSuppressed: 1;        /**< True suppress PAN-id is done when possible from frame. This will be only checked when 2015 extension is enabled */
    bool lfn_multicast: 1;          /**< Multicast packet for LFN */
    struct mlme_security Key;       /**< Security key */
    struct rcp_rate_info rate_list[4];
    uint8_t ms_mode;
    uint8_t fhss_type;              /**< FHSS policy to send that frame */
    uint8_t frame_type;
} mcps_data_req_t;

// Used by rcp_legacy_tx_req_legacy()
// Structure for IEEE 802.15.4-2015 MCPS data extension to Request
// FIXME: Mostly the same than mcps_data_rx_ie_list
typedef struct mcps_data_req_ie_list {
    struct iovec *headerIeVectorList;    /**< Header IE element list */
    struct iovec *payloadIeVectorList;   /**< Payload IE element list */
    uint16_t headerIovLength;            /**< Header IE element list size, set 0 when no elements */
    uint16_t payloadIovLength;           /**< Payload IE element list size, set 0 when no elements */
} mcps_data_req_ie_list_t;

// See IEEE standard 802.15.4-2006 for more details
enum mcps_data_cnf_status {
    MLME_SUCCESS                    = 0x00, /**< The requested operation was completed successfully*/
    MLME_BUSY_CHAN                  = 0xe1, /**< CSMA-CA fail*/
    MLME_TX_ON                      = 0x09, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_COUNTER_ERROR              = 0xdb, /**< Originated messages security counter is not valid */
    MLME_INVALID_HANDLE             = 0xe7, /**< Status for Purge request when Mac not detect proper queued message*/
    MLME_INVALID_PARAMETER          = 0xe8, /**< A parameter in the primitive is either not supported or is out of the valid range */
    MLME_TX_NO_ACK                  = 0xe9, /**< No ack was received after macMaxFrameRetries */
    MLME_TRANSACTION_EXPIRED        = 0xf0, /**< The transaction has expired and its information was discarded */
    MLME_TRANSACTION_OVERFLOW       = 0xf1, /**< MAC have no capacity to store the transaction */
};

// Used by on_tx_cnf()
// See IEEE standard 802.15.4-2006 (table 42) for more details
typedef struct mcps_data_cnf {
    struct rcp_tx_cnf hif;
    struct mlme_security sec; // Auxiliary security header of the ACK frame (if any)
    struct {
        uint8_t phy_mode_id;
        uint8_t retries;
    } retry_per_rate[4];         /**< Number of retries sorted by rate */
    uint8_t success_phy_mode_id; /**< PhyModeId used to transmit the frame correctly. Only valide if status is MAC_TX_DONE */
} mcps_data_cnf_t;

// Used by on_rx_ind()
// See IEEE standard 802.15.4-2006 (table 43) for more details
typedef struct mcps_data_ind {
    struct rcp_rx_ind hif;
    unsigned SrcAddrMode: 2;    /**< 0x00 = no address 0x01 = reserved 0x02 = 16-bit short address 0x03 = 64-bit extended address */
    uint16_t SrcPANId;          /**< Source PAN ID */
    uint8_t SrcAddr[8];         /**< Source address */
    unsigned DstAddrMode: 2;    /**< Destination address mode */
    bool DSN_suppressed: 1;     /**< Indicate when DSN not include valid sequency id */
    bool TxAckReq: 1;           /**< Is ACK needed */
    bool PanIdSuppressed: 1;    /**< Suppress PAN-ID if possible. 2015 extension only */
    uint16_t DstPANId;          /**< Destination PAN ID */
    uint8_t DstAddr[8];         /**< Destination address */
    uint8_t DSN;                /**< Data sequence number */
    struct mlme_security Key;   /**< Security key */
    uint16_t msduLength;        /**< Data unit length */
    const uint8_t *msdu_ptr;    /**< Data unit */
} mcps_data_ind_t;

// Used by on_rx_ind() and on_tx_cnf()
// FIXME: Mostly the same than mcps_data_req_ie_list
struct mcps_data_rx_ie_list {
    const uint8_t *headerIeList;        /**< Header information IE's list without terminator*/
    const uint8_t *payloadIeList;       /**< Payload information IE's list without terminator*/
    uint16_t headerIeListLength;        /**< Header information IE's list length in bytes */
    uint16_t payloadIeListLength;       /**< Payload information IE's list length in bytes */
};

static inline uint8_t mlme_status_from_hif(enum hif_data_status status)
{
    switch (status) {
    case HIF_STATUS_SUCCESS:  return MLME_SUCCESS;
    case HIF_STATUS_NOMEM:    return MLME_TRANSACTION_OVERFLOW;
    case HIF_STATUS_CCA:      return MLME_BUSY_CHAN;
    case HIF_STATUS_NOACK:    return MLME_TX_NO_ACK;
    case HIF_STATUS_TIMEDOUT: return MLME_TRANSACTION_EXPIRED;
    default:
        WARN("unknown status 0x%02x", status);
        return MLME_INVALID_PARAMETER; // arbitrary
    }
}

#endif
