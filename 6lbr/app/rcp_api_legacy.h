/*
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

#include "app/rcp_api.h"

struct fhss_ws_neighbor_timing_info;
struct fhss_ws_configuration;
struct ws_neigh;
struct iobuf_write;
struct iobuf_read;
struct wsbr_ctxt;
struct os_ctxt;
struct net_if;
struct rcp;

typedef struct phy_rf_channel_configuration {
    uint32_t channel_0_center_frequency;
    uint32_t channel_spacing;
    uint32_t datarate;
    uint16_t number_of_channels;
    uint8_t  modulation;
    uint8_t  modulation_index;
    bool     fec;
    uint8_t  ofdm_option;
    uint8_t  ofdm_mcs;
    int      rcp_config_index;
    bool     use_phy_op_modes;
} phy_rf_channel_configuration_t;

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
    bool PendingBit: 1;             /**< Specifies whether more fragments are to be sent or not */
    bool SeqNumSuppressed: 1;       /**< True suppress sequence number from frame. This will be only checked when 2015 extension is enabled */
    bool PanIdSuppressed: 1;        /**< True suppress PAN-id is done when possible from frame. This will be only checked when 2015 extension is enabled */
    bool ExtendedFrameExchange: 1;  /**< True for Extended Frame change. This will be only checked when 2015 extension and enhanced frame is enabled */
    bool lfn_multicast: 1;          /**< Multicast packet for LFN */
    struct mlme_security Key;       /**< Security key */
    uint8_t phy_id;
    uint8_t fhss_type;              /**< FHSS policy to send that frame */
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
    MLME_BUSY_RX                    = 0x01, /**< The radio is asked to change its state while receiving */
    MLME_BUSY_TX                    = 0x02, /**< The radio is asked to change its state while transmitting. */
    MLME_FORCE_TRX_OFF              = 0x03, /**< The radio is to be switched off immediately */
    MLME_IDLE                       = 0x04, /**< The CCA attempt has detected an idle channel */
    MLME_RX_ON                      = 0x06, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_TRX_OFF                    = 0x08, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_TX_ON                      = 0x09, /**< The radio is in or is to be configured into the receiver enabled state. */
    MLME_COUNTER_ERROR              = 0xdb, /**< Originated messages security counter is not valid */
    MLME_IMPROPER_KEY_TYPE          = 0xdc, /**< Received Messages key used is agains't key usage policy */
    MLME_IMPROPER_SECURITY_LEVEL    = 0xdd, /**< Received Messages security level does not meet minimum security level */
    MLME_UNSUPPORTED_LEGACY         = 0xde, /**< The received frame was purportedly secured using security based on IEEE Std 802.15.4-2003, and such security is not supported by this standard. */
    MLME_UNSUPPORTED_SECURITY       = 0xdf, /**< The received frame security is not supported */
    MLME_SECURITY_FAIL              = 0xe4, /**< Cryptographic processing of the received secured frame failed. */
    MLME_FRAME_TOO_LONG             = 0xe5, /**< Either a frame resulting from processing has a length that is greater than aMaxPHYPacketSize */
    MLME_INVALID_HANDLE             = 0xe7, /**< Status for Purge request when Mac not detect proper queued message*/
    MLME_INVALID_PARAMETER          = 0xe8, /**< A parameter in the primitive is either not supported or is out of the valid range */
    MLME_TX_NO_ACK                  = 0xe9, /**< No ack was received after macMaxFrameRetries */
    MLME_NO_BEACON                  = 0xea, /**< A scan operation failed to find any network beacons */
    MLME_NO_DATA                    = 0xeb, /**< No response data were available following a request */
    MLME_NO_SHORT_ADDRESS           = 0xec, /**< Operation fail because 16-bit address is not allocated */
    MLME_PAN_ID_CONFLICT            = 0xee, /**< A PAN identifier conflict has been detected and communicated to the PAN coordinator. */
    MLME_TRANSACTION_EXPIRED        = 0xf0, /**< The transaction has expired and its information was discarded */
    MLME_TRANSACTION_OVERFLOW       = 0xf1, /**< MAC have no capacity to store the transaction */
    MLME_UNAVAILABLE_KEY            = 0xf3, /**< Received message use unknown key, or the originating device is unknown or is blacklisted with that particular key */
    MLME_UNSUPPORTED_ATTRIBUTE      = 0xf4, /**< A SET/GET request was issued with the unsupported identifier */
    MLME_INVALID_ADDRESS            = 0xf5, /**< A request to send data was unsuccessful because neither the source address parameters nor the destination address parameters were present.*/
    MLME_INVALID_INDEX              = 0xf9, /**< An attempt to write to a MAC PIB attribute that is in a table failed because the specified table index was out of range. */
    MLME_LIMIT_REACHED              = 0xfa, /**< A scan operation terminated prematurely because the number of PAN descriptors stored reached an implementation- specified maximum */
    MLME_READ_ONLY                  = 0xfb, /**< A SET request was issued with the identifier of an attribute that is read only.*/
    MLME_SCAN_IN_PROGRESS           = 0xfc, /**< Request scan request fail when scan is already active */
    // NOT-standard
    MLME_DATA_POLL_NOTIFICATION     = 0xff, /**< Thread requirement feature COMM status status for indicate for successfully data poll event to refresh neighbour data */
};

// Used by on_tx_cnf()
// See IEEE standard 802.15.4-2006 (table 42) for more details
typedef struct mcps_data_cnf {
    uint8_t msduHandle;     /**< Handle associated with MSDU */
    uint8_t status;         /**< Status of the last MSDU transmission, see enum mcps_data_cnf_status */
    uint64_t timestamp;     /**< Time, in symbols, at which the data were transmitted */
    //Non-standard extension
    uint8_t cca_retries;    /**< Number of CCA retries used during sending */
    uint8_t tx_retries;     /**< Number of retries done during sending, 0 means no retries */
    uint32_t frame_counter; // Frame counter used for successful TX of a secured frame
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
    unsigned SrcAddrMode: 2;    /**< 0x00 = no address 0x01 = reserved 0x02 = 16-bit short address 0x03 = 64-bit extended address */
    uint16_t SrcPANId;          /**< Source PAN ID */
    uint8_t SrcAddr[8];         /**< Source address */
    unsigned DstAddrMode: 2;    /**< Destination address mode */
    bool DSN_suppressed: 1;     /**< Indicate when DSN not include valid sequency id */
    bool TxAckReq: 1;           /**< Is ACK needed */
    bool PendingBit: 1;         /**< Are there more fragments to be sent */
    bool PanIdSuppressed: 1;    /**< Suppress PAN-ID if possible. 2015 extension only */
    uint16_t DstPANId;          /**< Destination PAN ID */
    uint8_t DstAddr[8];         /**< Destination address */
    uint8_t mpduLinkQuality;    /**< LQI value measured during reception of the MPDU */
    int signal_dbm;             /**< This extension for normal IEEE 802.15.4 Data indication */
    uint64_t timestamp;         /**< The time, in symbols, at which the data were received */
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

#endif
